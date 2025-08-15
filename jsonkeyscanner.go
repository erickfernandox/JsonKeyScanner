package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
   Crawler Vulnerability Testing Tool — refactor (4 modos, sem mode 0)

   - Lê seeds via stdin (uma por linha). Aceita host sem esquema (assume http://).
   - Faz crawl (mesmo host opcional), com profundidade -d e limite por host (-max-pages).
   - Navega por URLs "prováveis" de app (isLikelyAppURL): diretórios, com query, ou com sufixos permitidos.
   - Fuzzing só é enviado para endpoints com sufixos permitidos OU que tenham query string.
   - Extrai nomes de parâmetros via **um** dos 4 modos (-mode):
       1=JSON keys, 2=Input name, 3=Query keys, 4=Assignments
   - Roda testes: XSS, XSS Script, CRLF (raw header "set-cookie: efx"), Redirect/SSRF, Link Manipulation, SSTI.
   - Sem -lp: usa os parâmetros extraídos pelo crawler; -params amostra N por endpoint (0 = todos).
   - Canais fechados com segurança (crawlWG) — sem panic de send on closed channel.
*/

// =====================================
// Flags e globais
// =====================================

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error { *h = append(*h, val); return nil }

var (
	// execução
	concurrency int
	headers     customheaders
	proxy       string
	htmlOnly    bool
	onlyPOC     bool

	// crawl
	depth      int
	maxPages   int
	sameHost   bool
	userAgent  string
	timeoutSec int

	// injeção
	paramCount int // 0 = todos
	mode       int // 1=JSON, 2=Input, 3=Query, 4=Assign
)

func init() {
	flag.IntVar(&concurrency, "t", 50, "Threads (mínimo 15)")
	flag.Var(&headers, "H", "Header extra (repetível)")
	flag.StringVar(&proxy, "proxy", "", "Proxy HTTP (também aceita -x)")
	flag.StringVar(&proxy, "x", "", "Proxy HTTP (atalho de -proxy)")
	flag.BoolVar(&htmlOnly, "html", false, "Só reportar XSS/Link se Content-Type for text/html")
	flag.BoolVar(&onlyPOC, "s", false, "Somente PoC (esconde Not Vulnerable)")

	flag.IntVar(&depth, "d", 1, "Profundidade de crawl (0 = só seeds)")
	flag.IntVar(&maxPages, "max-pages", 300, "Máximo de páginas por host")
	flag.BoolVar(&sameHost, "same-host", true, "Restringir ao mesmo host")
	flag.StringVar(&userAgent, "ua", "efx-crawler/3.0", "User-Agent")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout (segundos)")

	flag.IntVar(&paramCount, "params", 0, "Quantidade de parâmetros por endpoint (amostra; 0=todos)")
	flag.IntVar(&mode, "mode", 1, "Modo de extração de parâmetros: 1=JSON, 2=Input, 3=Query, 4=Assign")
}

func usage() {
	fmt.Fprintln(os.Stderr, `Uso:
  echo "https://alvo" | go run jsonkeyscanner.go -d 1 -t 80 -params 20 -mode 2 -H "Cookie: a=b" -proxy http://127.0.0.1:8080

Flags:
  -d           Profundidade do crawl (0=apenas seeds)
  -max-pages   Máximo de páginas por host (default 300)
  -same-host   Limitar ao mesmo host (default true)
  -t           Threads (mín 15, default 50)
  -params      Amostra aleatória de N parâmetros por endpoint (0=todos)
  -proxy/-x    Proxy HTTP (suporta CONNECT para HTTPS no CRLF raw)
  -H           Header extra (repetível)
  -html        Só reportar XSS/Link se Content-Type for text/html
  -s           Só linhas PoC (oculta "Not Vulnerable")
  -ua          User-Agent
  -timeout     Timeout em segundos
  -mode        Extração: 1=JSON | 2=Input | 3=Query | 4=Assign
`)
}

// =====================================
// HTTP utils
// =====================================

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}).DialContext,
	}
	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{Transport: tr, Timeout: time.Duration(timeoutSec) * time.Second}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	if userAgent != "" { req.Header.Set("User-Agent", userAgent) }
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func isHTML(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func readAllLimit(rc io.ReadCloser, max int64) ([]byte, error) { return io.ReadAll(io.LimitReader(rc, max)) }
func contains(b []byte, s string) bool                         { return strings.Contains(string(b), s) }

// =====================================
// Extração de parâmetros
// =====================================

var (
	reJSONKeys  = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	reInputName = regexp.MustCompile(`\bname="([a-zA-Z0-9_-]+)"`)
	reQueryKeys = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	reAssign    = regexp.MustCompile(`\b([a-zA-Z0-9_-]+)\s*=`)
)

var (
	reHref = regexp.MustCompile(`\bhref\s*=\s*['"]([^'"]+)['"]`)
	reSrc  = regexp.MustCompile(`\bsrc\s*=\s*['"]([^'"]+)['"]`)
	reAct  = regexp.MustCompile(`\baction\s*=\s*['"]([^'"]+)['"]`)
)

func uniqAppend(set map[string]struct{}, items ...string) {
	for _, it := range items {
		if it == "" { continue }
		set[it] = struct{}{}
	}
}

// caracteres proibidos em nomes de parâmetros
func hasBadParamRune(s string) bool {
	for _, r := range s {
		switch r {
		case '<', '>', '/', '\\', '"', '\'', '`', ' ':
			return true
		}
	}
	return false
}

func extractParamNamesFromBody(body string, mode int) []string {
	m := map[string]struct{}{}
	var regs []*regexp.Regexp
	switch mode {
	case 1:
		regs = []*regexp.Regexp{reJSONKeys}
	case 2:
		regs = []*regexp.Regexp{reInputName}
	case 3:
		regs = []*regexp.Regexp{reQueryKeys}
	case 4:
		regs = []*regexp.Regexp{reAssign}
	default:
		regs = []*regexp.Regexp{reJSONKeys} // fallback
	}
	for _, reg := range regs {
		all := reg.FindAllStringSubmatch(body, -1)
		for _, a := range all {
			if len(a) > 1 {
				name := strings.TrimSpace(a[1])
				if name == "" || len(name) > 40 || hasBadParamRune(name) { continue }
				m[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(m))
	for k := range m { out = append(out, k) }
	sort.Strings(out)
	return out
}

func extractLinksAndForms(base *url.URL, body string) (links []string, formActions []string) {
	abs := func(raw string) string {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.String() == "" { return "" }
		return base.ResolveReference(u).String()
	}
	for _, re := range []*regexp.Regexp{reHref, reSrc} {
		m := re.FindAllStringSubmatch(body, -1)
		for _, a := range m { if len(a) > 1 { links = append(links, abs(a[1])) } }
	}
	m := reAct.FindAllStringSubmatch(body, -1)
	for _, a := range m { if len(a) > 1 { formActions = append(formActions, abs(a[1])) } }
	return
}

func queryKeysFromURL(u *url.URL) []string {
	keys := map[string]struct{}{}
	for k := range u.Query() { uniqAppend(keys, k) }
	out := make([]string, 0, len(keys))
	for k := range keys { out = append(out, k) }
	sort.Strings(out)
	return out
}

// =====================================
// Filtros de URL
// =====================================

func hasAllowedSuffix(u *url.URL) bool {
	suffixes := []string{".php", ".php3", ".php4", ".aspx", ".jsf", ".asp", ".html", ".jsonp", ".json", ".jsp", ".axd", ".htm", ".esp", ".cgi", ".do", ".jsx", ".xhtml", ".jhtm"}
	p := strings.ToLower(u.Path)
	for _, s := range suffixes { if strings.HasSuffix(p, s) { return true } }
	return false
}

// Navegar (crawl) pode ser mais permissivo para não "matar" a exploração muito cedo.
func isLikelyAppURL(u *url.URL) bool {
	if hasAllowedSuffix(u) { return true }
	p := strings.ToLower(u.Path)
	if p == "" || strings.HasSuffix(p, "/") { return true }
	if u.RawQuery != "" { return true }
	seg := p
	if i := strings.LastIndex(p, "/"); i >= 0 { seg = p[i+1:] }
	if !strings.Contains(seg, ".") { return true }
	return false
}

// =====================================
// Testes de vulnerabilidade
// =====================================

type TestCase struct {
	Name     string
	Payloads []string
	NeedHTML bool
	Detector func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string)
}

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" { msg += " | " + detail }
	if onlyPOC { return fmt.Sprintf("%s | %s", urlStr, kind) }
	return msg
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC { return "" }
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func getRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 { return params }
	if count >= len(params) { return params }
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

func buildQueryRaw(params []string, rawValue string) string {
	var b strings.Builder
	for i, p := range params {
		if i > 0 { b.WriteByte('&') }
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(rawValue)
	}
	return b.String()
}

func addParamsRaw(base string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(base)
	if err != nil { return "", false }
	q := u.Query().Encode()
	raw := buildQueryRaw(params, rawValue)
	if q != "" { u.RawQuery = q + "&" + raw } else { u.RawQuery = raw }
	return u.String(), true
}

func buildFormBodyRaw(params []string, rawValue string) string {
	var b strings.Builder
	for i, p := range params {
		if i > 0 { b.WriteByte('&') }
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(rawValue)
	}
	return b.String()
}

func runAllTestsOnEndpoint(base string, allParams []string, client *http.Client) []string {
	if len(allParams) == 0 { return nil }
	selectedParams := getRandomParams(allParams, paramCount)

	tests := []TestCase{
		{
			Name:     "XSS",
			Payloads: []string{`%27%22teste`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) { return false, "" }
				if contains(body, `'"teste`) { return true, `match: '"teste` }
				return false, ""
			},
		},
		{
			Name:     "XSS Script",
			Payloads: []string{`%3C%2Fscript%3E%3Cteste%3E`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) { return false, "" }
				if contains(body, `</script><teste>`) { return true, "match: </script><teste>" }
				return false, ""
			},
		},
		{
			Name:     "CRLF Injection",
			Payloads: []string{`%0d%0aset-cookie:efx`, `%0d%0a%0d%0aset-cookie:efx`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				rawHead, rawErr := fetchRawResponseHead(method, urlStr, sentBody, headers, proxy)
				if rawErr == nil {
					lines := strings.Split(rawHead, "\r\n")
					for _, ln := range lines {
						l := strings.ToLower(strings.TrimSpace(ln))
						if strings.HasPrefix(l, "set-cookie: efx") { return true, "raw-header: " + ln }
					}
				}
				return false, ""
			},
		},
		{
			Name:     "Redirect/SSRF",
			Payloads: []string{`https://example.com`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if contains(body, "Example Domain") { return true, "match: Example Domain" }
				return false, ""
			},
		},
		{
			Name:     "Link Manipulation",
			Payloads: []string{`https://efxtech.com`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) { return false, "" }
				low := strings.ToLower(string(body))
				if strings.Contains(low, `href="https://efxtech.com`) || strings.Contains(low, `src="https://efxtech.com`) || strings.Contains(low, `action="https://efxtech.com`) {
					return true, `match: href/src/action="https://efxtech.com`
				}
				return false, ""
			},
		},
		{
			Name:     "SSTI",
			Payloads: []string{`{{7*7}}efxtech`, `${{7*7}}efxtech`, `*{7*7}efxtech`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if contains(body, "49efxtech") { return true, "match: 49efxtech" }
				return false, ""
			},
		},
	}

	var results []string
	maxBody := int64(2 << 20) // 2MB

	for _, tc := range tests {
		for _, payload := range tc.Payloads {
			// GET
			getURL, ok := addParamsRaw(base, selectedParams, payload)
			if ok {
				req, err := http.NewRequest("GET", getURL, nil)
				if err == nil {
					applyHeaders(req)
					if resp, err := client.Do(req); err == nil {
						body, _ := readAllLimit(resp.Body, maxBody)
						resp.Body.Close()
						if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
							if vul, detail := tc.Detector("GET", getURL, resp, body, ""); vul {
								results = append(results, formatVuln(tc.Name, "GET", getURL, detail))
							} else if !onlyPOC {
								results = append(results, formatNotVuln(tc.Name, "GET", getURL))
							}
						}
					}
				}
			}

			// POST (x-www-form-urlencoded)
			bodyStr := buildFormBodyRaw(selectedParams, payload)
			req, err := http.NewRequest("POST", base, strings.NewReader(bodyStr))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				applyHeaders(req)
				if resp, err := client.Do(req); err == nil {
					body, _ := readAllLimit(resp.Body, maxBody)
					resp.Body.Close()
					if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
						if vul, detail := tc.Detector("POST", base, resp, body, bodyStr); vul {
							results = append(results, formatVuln(tc.Name, "POST", base, detail+" [body:"+bodyStr+"]"))
						} else if !onlyPOC {
							results = append(results, formatNotVuln(tc.Name, "POST", base+" [body:"+bodyStr+"]"))
						}
					}
				}
			}
		}
	}
	return results
}

// =====================================
// Leitura crua de headers (CRLF)
// =====================================

func fetchRawResponseHead(method, fullURL, body string, addHeaders customheaders, proxyURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil { return "", err }

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" { host += ":443" } else { host += ":80" }
	}

	dialTimeout := time.Duration(timeoutSec) * time.Second

	readHead := func(c net.Conn, reqTarget string, tlsWrap bool) (string, error) {
		if tlsWrap {
			sn := u.Hostname()
			tconn := tls.Client(c, &tls.Config{ServerName: sn, InsecureSkipVerify: true})
			if err := tconn.Handshake(); err != nil { return "", err }
			c = tconn
		}
		if reqTarget == "" { reqTarget = u.RequestURI() }
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"
		var b strings.Builder
		b.WriteString(reqLine)
		b.WriteString("Host: "+u.Host+"\r\n")
		b.WriteString("Connection: close\r\n")
		if userAgent != "" { b.WriteString("User-Agent: "+userAgent+"\r\n") }
		for _, h := range addHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 { b.WriteString(strings.TrimSpace(parts[0])+": "+strings.TrimSpace(parts[1])+"\r\n") }
		}
		if method == "POST" && body != "" {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		b.WriteString("\r\n")
		if method == "POST" && body != "" { b.WriteString(body) }

		c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
		if _, err := c.Write([]byte(b.String())); err != nil { return "", err }

		rd := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil { return "", err }
			head.WriteString(line)
			if strings.HasSuffix(head.String(), "\r\n\r\n") { break }
			if head.Len() > 64*1024 { break }
		}
		return strings.TrimSuffix(head.String(), "\r\n\r\n"), nil
	}

	if proxyURL == "" {
		c, err := net.DialTimeout("tcp", host, dialTimeout)
		if err != nil { return "", err }
		defer c.Close()
		needTLS := (u.Scheme == "https")
		return readHead(c, "", needTLS)
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil { return "", err }
	if pURL.Scheme != "http" { return "", fmt.Errorf("proxy scheme not supported for raw: %s", pURL.Scheme) }
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") { proxyHost += ":80" }
	c, err := net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil { return "", err }
	defer c.Close()

	if u.Scheme == "http" {
		return readHead(c, u.String(), false)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	if _, err := c.Write([]byte(connectReq)); err != nil { return "", err }
	br := bufio.NewReader(c)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil { return "", err }
		respHead.WriteString(line)
		if strings.HasSuffix(respHead.String(), "\r\n\r\n") { break }
		if respHead.Len() > 32*1024 { break }
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") { return "", fmt.Errorf("proxy CONNECT failed") }
	return readHead(c, "", true)
}

// =====================================
// Motor de crawl (safe close)
// =====================================

type crawlTask struct { URL string; Depth int }

type endpointJob struct { BaseURL string; ParamNames []string }

func main() {
	flag.Parse()
	if concurrency < 15 { concurrency = 15 }
	rand.Seed(time.Now().UnixNano())

	client := buildClient()

	// ler seeds
	seedSet := map[string]struct{}{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw != "" { seedSet[raw] = struct{}{} }
	}
	if len(seedSet) == 0 { usage(); return }

	var (
		visitedMu sync.Mutex
		visited   = map[string]struct{}{}
		hostCount = map[string]int{}
	)
	shouldVisit := func(u *url.URL) bool {
		visitedMu.Lock(); defer visitedMu.Unlock()
		if _, ok := visited[u.String()]; ok { return false }
		hostCount[u.Host]++
		if hostCount[u.Host] > maxPages { return false }
		visited[u.String()] = struct{}{}
		return true
	}

	crawlCh := make(chan crawlTask, 1024)
	endpointCh := make(chan endpointJob, 1024)

	var wgCrawl, wgTest sync.WaitGroup
	var crawlWG sync.WaitGroup // conta tarefas enfileiradas

	enqueue := func(ct crawlTask) {
		crawlWG.Add(1)
		crawlCh <- ct
	}

	// Workers de teste
	for i := 0; i < concurrency; i++ {
		wgTest.Add(1)
		go func() {
			defer wgTest.Done()
			for job := range endpointCh {
				res := runAllTestsOnEndpoint(job.BaseURL, job.ParamNames, client)
				for _, line := range res { if line != "" { fmt.Println(line) } }
			}
		}()
	}

	// Workers de crawl
	for i := 0; i < concurrency; i++ {
		wgCrawl.Add(1)
		go func() {
			defer wgCrawl.Done()
			for task := range crawlCh {
				func(task crawlTask) {
					defer crawlWG.Done()

					u, err := url.Parse(task.URL)
					if err != nil { return }
					if u.Scheme != "http" && u.Scheme != "https" { return }
					if sameHost && u.Host == "" { return }
					if !isLikelyAppURL(u) { return }

					req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return }
					applyHeaders(req)
					resp, err := client.Do(req); if err != nil { return }
					bodyBytes, _ := readAllLimit(resp.Body, 4<<20); resp.Body.Close()
					body := string(bodyBytes)

					// parâmetros do corpo + query da URL
					pSet := map[string]struct{}{}
					for _, k := range extractParamNamesFromBody(body, mode) { uniqAppend(pSet, k) }
					for _, k := range queryKeysFromURL(u) { uniqAppend(pSet, k) }

					// Enviar pra fuzzing somente se for sufixo permitido ou tiver query
					if len(pSet) > 0 && (hasAllowedSuffix(u) || u.RawQuery != "") {
						params := make([]string, 0, len(pSet))
						for k := range pSet { params = append(params, k) }
						sort.Strings(params)
						endpointCh <- endpointJob{BaseURL: u.String(), ParamNames: params}
					}

					// Expandir crawl
					if task.Depth < depth {
						links, forms := extractLinksAndForms(u, body)
						enq := func(list []string) {
							for _, raw := range list {
								uu, err := url.Parse(raw); if err != nil { continue }
								if uu.Scheme != "http" && uu.Scheme != "https" { continue }
								if sameHost && uu.Host != u.Host { continue }
								if !isLikelyAppURL(uu) { continue }
								if shouldVisit(uu) { enqueue(crawlTask{URL: uu.String(), Depth: task.Depth + 1}) }
							}
						}
						enq(links); enq(forms)
					}
				}(task)
			}
		}()
	}

	// Semeadura
	normalize := func(raw string) (string, bool) {
		s := strings.TrimSpace(raw)
		if s == "" { return "", false }
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			s = "http://" + s
		}
		u, err := url.Parse(s); if err != nil { return "", false }
		if u.Host == "" { return "", false }
		return u.String(), true
	}

	for raw := range seedSet {
		if s, ok := normalize(raw); ok {
			u, _ := url.Parse(s)
			if !isLikelyAppURL(u) { continue }
			if shouldVisit(u) { enqueue(crawlTask{URL: u.String(), Depth: 0}) }
		}
	}

	// Fecha crawlCh quando todas as tarefas terminarem
	go func() {
		crawlWG.Wait()
		close(crawlCh)
	}()

	// Finalização
	wgCrawl.Wait()
	close(endpointCh)
	wgTest.Wait()
}
.

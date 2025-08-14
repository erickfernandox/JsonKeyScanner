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
   Crawler + Param Extractor + Vuln Tester

   - Lê URLs via stdin (semente do crawl)
   - Faz crawl no mesmo host (profundidade configurável)
   - Extrai parâmetros de:
       * chaves "JSON-like":    ['"]?key['"]?\s*:
       * inputs HTML:           name="key"
       * query na página:       ?key=
       * atribuições JS simples: key =
     (mesmos padrões do seu primeiro código)
   - Para cada endpoint descoberto (a.href, form.action e a própria página),
     roda os testes (XSS, CRLF, Redirect/SSRF, Link Manipulation, SSTI) do seu segundo código,
     injetando nos parâmetros EXTRAÍDOS em vez de usar -lp.

   Observação:
     Se um endpoint tiver >0 params já presentes na query, eles também entram no conjunto.
*/

// ======================================================
// Flags e tipos
// ======================================================

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

var (
	// Execução / rede
	concurrency int
	headers     customheaders
	proxy       string
	htmlOnly    bool
	onlyPOC     bool

	// Crawl
	depth      int
	maxPages   int
	sameHost   bool
	userAgent  string
	timeoutSec int

	// Injeção
	paramCount int // amostra aleatória por endpoint (0 = todos)
)

// Defaults
func init() {
	flag.IntVar(&concurrency, "t", 50, "Número de threads (mínimo 15)")
	flag.Var(&headers, "H", "Header extra (repetível): -H 'Header: valor'")
	flag.StringVar(&proxy, "proxy", "", "Proxy HTTP (também aceita -x)")
	flag.StringVar(&proxy, "x", "", "Proxy HTTP (atalho de -proxy)")
	flag.BoolVar(&htmlOnly, "html", false, "Somente imprimir matches XSS/Link se Content-Type for text/html")
	flag.BoolVar(&onlyPOC, "s", false, "Somente PoC (esconde \"Not Vulnerable\")")

	flag.IntVar(&depth, "d", 1, "Profundidade de crawl (0 = só as seeds)")
	flag.IntVar(&maxPages, "max-pages", 300, "Máximo de páginas para visitar por host")
	flag.BoolVar(&sameHost, "same-host", true, "Restringir crawl ao mesmo host")
	flag.StringVar(&userAgent, "ua", "efx-crawler/1.0", "User-Agent")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout (segundos) de requests")
	flag.IntVar(&paramCount, "params", 0, "Quantidade de parâmetros por endpoint (amostra aleatória; 0=usar todos)")
}

func usage() {
	fmt.Fprintln(os.Stderr, `Uso:
  echo "https://alvo.com" | tool -d 1 -t 60 -params 20 -H "Cookie: a=b"

Principais flags:
  -d           Profundidade de crawl (0=apenas URLs do stdin)
  -max-pages   Máximo de páginas por host (default 300)
  -same-host   Limitar ao mesmo host (default true)
  -t           Threads (mínimo 15, default 50)
  -params      Amostra aleatória de N parâmetros por endpoint (0=usar todos)
  -proxy/-x    Proxy HTTP (suporta CONNECT para HTTPS no raw CRLF)
  -H           Header extra (repetível)
  -html        Só reporta XSS/Link quando Content-Type ~= text/html
  -s           Só PoC (não mostrar "Not Vulnerable")
  -ua          User-Agent
  -timeout     Timeout (s)

Entrada: URLs via stdin (semente do crawler).
`)
}

// ======================================================
// Util de rede / HTTP
// ======================================================

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
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func isHTML(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func readAllLimit(rc io.ReadCloser, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(rc, max))
}

func contains(body []byte, s string) bool { return strings.Contains(string(body), s) }

// ======================================================
// Extração de parâmetros (padrões do seu 1º código)
// ======================================================

var (
	reJSONKeys  = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	reInputName = regexp.MustCompile(`\bname="([a-zA-Z0-9_-]+)"`)
	reQueryKeys = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	reAssign    = regexp.MustCompile(`\b([a-zA-Z0-9_-]+)\s*=`)
)

// Além dos padrões, extraímos keys de URLs (href/src/action).
var (
	reHref  = regexp.MustCompile(`\bhref\s*=\s*['"]([^'"]+)['"]`)
	reSrc   = regexp.MustCompile(`\bsrc\s*=\s*['"]([^'"]+)['"]`)
	reAct   = regexp.MustCompile(`\baction\s*=\s*['"]([^'"]+)['"]`)
	reFormM = regexp.MustCompile(`\b<form\b[^>]*\baction\s*=\s*['"]([^'"]+)['"][^>]*>`)
)

func uniqAppend(set map[string]struct{}, items ...string) {
	for _, it := range items {
		if it == "" {
			continue
		}
		set[it] = struct{}{}
	}
}

func extractParamNamesFromBody(body string) []string {
	m := map[string]struct{}{}
	for _, r := range [][]*regexp.Regexp{{reJSONKeys}, {reInputName}, {reQueryKeys}, {reAssign}} {
		for _, reg := range r {
			all := reg.FindAllStringSubmatch(body, -1)
			for _, a := range all {
				if len(a) > 1 {
					uniqAppend(m, a[1])
				}
			}
		}
	}
	// normalize: remove coisas obviamente inválidas
	out := make([]string, 0, len(m))
	for k := range m {
		kk := strings.TrimSpace(k)
		if kk == "" {
			continue
		}
		// Evitar "http", "var", "function" etc. heurística simples:
		if len(kk) > 40 || strings.ContainsAny(kk, "<>/\\\"'` ") {
			continue
		}
		out = append(out, kk)
	}
	sort.Strings(out)
	return out
}

func extractLinksAndForms(base *url.URL, body string) (links []string, formActions []string) {
	var abs = func(raw string) string {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.String() == "" {
			return ""
		}
		return base.ResolveReference(u).String()
	}
	for _, re := range []*regexp.Regexp{reHref, reSrc} {
		m := re.FindAllStringSubmatch(body, -1)
		for _, a := range m {
			if len(a) > 1 {
				links = append(links, abs(a[1]))
			}
		}
	}
	// actions
	m := reAct.FindAllStringSubmatch(body, -1)
	for _, a := range m {
		if len(a) > 1 {
			formActions = append(formActions, abs(a[1]))
		}
	}
	return
}

func queryKeysFromURL(u *url.URL) []string {
	keys := map[string]struct{}{}
	for k := range u.Query() {
		uniqAppend(keys, k)
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ======================================================
/*  Testes de vulnerabilidade (baseados no seu 2º código)
    Modificação principal: NÃO lemos -lp; usamos os parâmetros extraídos.
*/
type TestCase struct {
	Name     string
	Payloads []string
	NeedHTML bool
	Detector func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string)
}

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
	if onlyPOC {
		return fmt.Sprintf("%s | %s", urlStr, kind)
	}
	return msg
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func getRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 {
		return params
	}
	if count >= len(params) {
		return params
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

func buildQueryRaw(params []string, rawValue string) string {
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(rawValue)
	}
	return b.String()
}

func addParamsRaw(base string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	// preserva a query existente e acrescenta/override dos escolhidos
	q := u.Query()
	// add todos de uma vez como raw (mantendo + do payload quando necessário)
	// estratégia: juntar todos no final substitui RawQuery
	raw := buildQueryRaw(params, rawValue)
	// Se já havia query, append manual
	if qs := q.Encode(); qs != "" {
		u.RawQuery = qs + "&" + raw
	} else {
		u.RawQuery = raw
	}
	return u.String(), true
}

func buildFormBodyRaw(params []string, rawValue string) string {
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(rawValue)
	}
	return b.String()
}

func runAllTestsOnEndpoint(base string, allParams []string, client *http.Client) []string {
	if len(allParams) == 0 {
		return nil
	}
	selectedParams := getRandomParams(allParams, paramCount)

	tests := []TestCase{
		{
			Name:     "XSS",
			Payloads: []string{`%27%22teste`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if contains(body, `'"teste`) {
					return true, `match: '"teste`
				}
				return false, ""
			},
		},
		{
			Name:     "XSS Script",
			Payloads: []string{`%3C%2Fscript%3E%3Cteste%3E`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if contains(body, `</script><teste>`) {
					return true, "match: </script><teste>"
				}
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
						if strings.HasPrefix(l, "set-cookie: efx") {
							return true, "raw-header: " + ln
						}
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
				if contains(body, "Example Domain") {
					return true, "match: Example Domain"
				}
				return false, ""
			},
		},
		{
			Name:     "Link Manipulation",
			Payloads: []string{`https://efxtech.com`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				low := strings.ToLower(string(body))
				if strings.Contains(low, `href="https://efxtech.com`) ||
					strings.Contains(low, `src="https://efxtech.com`) ||
					strings.Contains(low, `action="https://efxtech.com`) {
					return true, `match: href/src/action="https://efxtech.com`
				}
				return false, ""
			},
		},
		{
			Name:     "SSTI",
			Payloads: []string{
				`{{7*7}}efxtech`,
				`${{7*7}}efxtech`,
				`*{7*7}efxtech`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if contains(body, "49efxtech") {
					return true, "match: 49efxtech"
				}
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

			// POST x-www-form-urlencoded
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

// ======================================================
// Raw header read (CRLF)
// ======================================================

func fetchRawResponseHead(method, fullURL, body string, addHeaders customheaders, proxyURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var conn net.Conn
	dialTimeout := time.Duration(timeoutSec) * time.Second

	readHead := func(c net.Conn, reqTarget string, tlsWrap bool) (string, error) {
		if tlsWrap {
			serverName := u.Hostname()
			tconn := tls.Client(c, &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
			})
			if err := tconn.Handshake(); err != nil {
				return "", err
			}
			c = tconn
		}

		if reqTarget == "" {
			reqTarget = u.RequestURI()
		}
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"

		var b strings.Builder
		b.WriteString(reqLine)
		b.WriteString("Host: " + u.Host + "\r\n")
		b.WriteString("Connection: close\r\n")
		if userAgent != "" {
			b.WriteString("User-Agent: " + userAgent + "\r\n")
		}
		for _, h := range addHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				b.WriteString(strings.TrimSpace(parts[0]) + ": " + strings.TrimSpace(parts[1]) + "\r\n")
			}
		}
		if method == "POST" && body != "" {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		b.WriteString("\r\n")
		if method == "POST" && body != "" {
			b.WriteString(body)
		}

		c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
		if _, err := c.Write([]byte(b.String())); err != nil {
			return "", err
		}

		rd := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return "", err
			}
			head.WriteString(line)
			if strings.HasSuffix(head.String(), "\r\n\r\n") {
				break
			}
			if head.Len() > 64*1024 {
				break
			}
		}
		return strings.TrimSuffix(head.String(), "\r\n\r\n"), nil
	}

	// Sem proxy
	if proxyURL == "" {
		conn, err = net.DialTimeout("tcp", host, dialTimeout)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		needTLS := (u.Scheme == "https")
		return readHead(conn, "", needTLS)
	}

	// Com proxy HTTP
	pURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	if pURL.Scheme != "http" {
		return "", fmt.Errorf("proxy schema não suportado no raw: %s", pURL.Scheme)
	}
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":80"
	}
	conn, err = net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if u.Scheme == "http" {
		// request absoluto via proxy
		return readHead(conn, u.String(), false)
	}

	// HTTPS via CONNECT
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		respHead.WriteString(line)
		if strings.HasSuffix(respHead.String(), "\r\n\r\n") {
			break
		}
		if respHead.Len() > 32*1024 {
			break
		}
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") {
		return "", fmt.Errorf("proxy CONNECT falhou")
	}
	// agora túnel TLS
	return readHead(conn, "", true)
}

// ======================================================
// Crawl engine
// ======================================================

type crawlTask struct {
	URL   string
	Depth int
}

type endpointJob struct {
	BaseURL    string
	ParamNames []string
}

func main() {
	flag.Parse()
	if concurrency < 15 {
		concurrency = 15
	}

	client := buildClient()

	// Seeds pelo stdin
	seedSet := map[string]struct{}{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		seedSet[raw] = struct{}{}
	}
	if len(seedSet) == 0 {
		usage()
		return
	}

	// Visited e contagem por host
	var (
		visitedMu sync.Mutex
		visited   = map[string]struct{}{}
		hostCount = map[string]int{}
	)

	shouldVisit := func(u *url.URL) bool {
		visitedMu.Lock()
		defer visitedMu.Unlock()
		if _, ok := visited[u.String()]; ok {
			return false
		}
		hostCount[u.Host]++
		if hostCount[u.Host] > maxPages {
			return false
		}
		visited[u.String()] = struct{}{}
		return true
	}

	// filas
	crawlCh := make(chan crawlTask, 1024)
	endpointCh := make(chan endpointJob, 1024)

	var wgCrawl, wgTest sync.WaitGroup

	// Workers de teste (rodam os TestCases em endpoints coletados)
	for i := 0; i < concurrency; i++ {
		wgTest.Add(1)
		go func() {
			defer wgTest.Done()
			for job := range endpointCh {
				res := runAllTestsOnEndpoint(job.BaseURL, job.ParamNames, client)
				for _, line := range res {
					if line != "" {
						fmt.Println(line)
					}
				}
			}
		}()
	}

	// Workers de crawl
	for i := 0; i < concurrency; i++ {
		wgCrawl.Add(1)
		go func() {
			defer wgCrawl.Done()
			for task := range crawlCh {
				u, err := url.Parse(task.URL)
				if err != nil {
					continue
				}

				// GET page
				req, err := http.NewRequest("GET", u.String(), nil)
				if err != nil {
					continue
				}
				applyHeaders(req)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyBytes, _ := readAllLimit(resp.Body, 4<<20) // 4MB
				resp.Body.Close()
				body := string(bodyBytes)

				// Extração de parâmetros desta página (corpo + query da própria URL)
				paramSet := map[string]struct{}{}
				for _, k := range extractParamNamesFromBody(body) {
					uniqAppend(paramSet, k)
				}
				for _, k := range queryKeysFromURL(u) {
					uniqAppend(paramSet, k)
				}

				// Coletar endpoints: a.href / script src / form action + a própria página
				links, formActions := extractLinksAndForms(u, body)

				// Normalizar e filtrar por same-host (se habilitado)
				filter := func(list []string) []string {
					out := []string{}
					for _, raw := range list {
						uu, err := url.Parse(raw)
						if err != nil {
							continue
						}
						if sameHost && uu.Host != u.Host {
							continue
						}
						if uu.Scheme != "http" && uu.Scheme != "https" {
							continue
						}
						out = append(out, uu.String())
					}
					return out
				}
				links = filter(links)
				formActions = filter(formActions)

				// Enfileirar endpoints para teste (se tiver parâmetros úteis)
				if len(paramSet) > 0 {
					params := make([]string, 0, len(paramSet))
					for k := range paramSet {
						params = append(params, k)
					}
					sort.Strings(params)
					// 1) Testar a própria página como endpoint base
					endpointCh <- endpointJob{BaseURL: u.String(), ParamNames: params}
					// 2) Testar cada link encontrado (base = link)
					for _, l := range links {
						endpointCh <- endpointJob{BaseURL: l, ParamNames: params}
					}
					// 3) Testar ações de forms
					for _, a := range formActions {
						endpointCh <- endpointJob{BaseURL: a, ParamNames: params}
					}
				}

				// Expandir crawl (BFS) se ainda houver profundidade
				if task.Depth < depth {
					nextD := task.Depth + 1
					enq := func(list []string) {
						for _, raw := range list {
							uu, err := url.Parse(raw)
							if err != nil {
								continue
							}
							if sameHost && uu.Host != u.Host {
								continue
							}
							if uu.Scheme != "http" && uu.Scheme != "https" {
								continue
							}
							if shouldVisit(uu) {
								crawlCh <- crawlTask{URL: uu.String(), Depth: nextD}
							}
						}
					}
					enq(links)
					enq(formActions)
				}
			}
		}()
	}

	// Semeadura
	for raw := range seedSet {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if shouldVisit(u) {
			crawlCh <- crawlTask{URL: u.String(), Depth: 0}
		}
	}

	close(crawlCh)
	wgCrawl.Wait()
	close(endpointCh)
	wgTest.Wait()
}

// ======================================================
// Helpers diversos
// ======================================================

func init() {
	rand.Seed(time.Now().UnixNano())
}

var stripANSIRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ======================================================
// FIM
// ======================================================

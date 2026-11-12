// nano-pulse — a lightweight, open-source control panel for a Nano node.
//
// It keeps the node's RPC private: the browser only ever talks to this server,
// which aggregates a read-only summary and streams it over Server-Sent Events.
// Single static binary, no external Go dependencies.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

//go:embed web
var webFS embed.FS

// ----- configuration (env) -----

type config struct {
	listen      string
	rpcURL      string
	repAcct     string
	poll        time.Duration
	rpcClient   *http.Client
	tlsDomain   string   // NP_TLS_DOMAIN: enable Let's Encrypt for this hostname (works with *.sslip.io / duckdns)
	tlsEmail    string   // NP_TLS_EMAIL: optional ACME contact
	selfSigned  bool     // NP_TLS_SELFSIGNED=true: HTTPS with a self-signed cert (no domain needed)
	tlsAddr     string   // NP_TLS_LISTEN: HTTPS listen address (default :443)
	tlsCache    string   // NP_TLS_CACHE: dir to persist certs (mount a volume!)
	tlsHosts    []string // NP_TLS_HOSTS: SANs for the self-signed cert (IPs or names)
	authUser    string   // NP_AUTH_USER: enable HTTP basic auth
	authPass    string   // NP_AUTH_PASS
	label       string   // NODE_LABEL: overrides the name shown under the title
	title       string   // NP_TITLE: dashboard title
	defaultLang string   // NP_DEFAULT_LANG: en|es|fr|de|it
	widgetTog   bool     // NP_WIDGET_SWITCHES (default true): show the gear widget toggles
	publicMode  bool     // NP_PUBLIC_MODE: start the dashboard read-only
}

// fileCfg holds values read from the config file; environment variables
// always take precedence over it.
var fileCfg = map[string]string{}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	if v, ok := fileCfg[k]; ok && v != "" {
		return v
	}
	return def
}

// loadConfigFile reads the first existing config file (NP_CONFIG, then
// ./nano-pulse.conf, then /data/nano-pulse.conf) as simple KEY=VALUE lines.
func loadConfigFile() {
	var paths []string
	if p := strings.TrimSpace(os.Getenv("NP_CONFIG")); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, "nano-pulse.conf", "/data/nano-pulse.conf")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			i := strings.IndexByte(line, '=')
			if i <= 0 {
				continue
			}
			k := strings.TrimSpace(line[:i])
			v := strings.Trim(strings.TrimSpace(line[i+1:]), "\"'")
			fileCfg[k] = v
		}
		log.Printf("loaded config file %s", p)
		return
	}
}

func loadConfig() config {
	loadConfigFile()
	poll := 5 * time.Second
	if v := env("NP_POLL_INTERVAL", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			poll = d
		}
	}
	rpcURL := env("NODE_RPC_URL", "")
	if rpcURL == "" {
		rpcURL = "http://" + env("NODE_HOST", "127.0.0.1") + ":" + env("NODE_RPC_PORT", "7076")
	}
	hosts := []string{"127.0.0.1", "localhost"}
	if v := env("NP_TLS_HOSTS", ""); v != "" {
		hosts = nil
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return config{
		listen:      env("NP_LISTEN", ":8080"),
		rpcURL:      rpcURL,
		repAcct:     env("REP_ACCOUNT", ""),
		poll:        poll,
		rpcClient:   &http.Client{Timeout: 8 * time.Second},
		tlsDomain:   env("NP_TLS_DOMAIN", ""),
		tlsEmail:    env("NP_TLS_EMAIL", ""),
		selfSigned:  strings.EqualFold(env("NP_TLS_SELFSIGNED", ""), "true"),
		tlsAddr:     env("NP_TLS_LISTEN", ":443"),
		tlsCache:    env("NP_TLS_CACHE", "/data/certs"),
		tlsHosts:    hosts,
		authUser:    env("NP_AUTH_USER", ""),
		authPass:    env("NP_AUTH_PASS", ""),
		label:       env("NODE_LABEL", ""),
		title:       env("NP_TITLE", ""),
		defaultLang: env("NP_DEFAULT_LANG", ""),
		widgetTog:   !strings.EqualFold(env("NP_WIDGET_SWITCHES", "true"), "false"),
		publicMode:  strings.EqualFold(env("NP_PUBLIC_MODE", ""), "true"),
	}
}

// selfSignedCert loads a cached self-signed cert from dir, or creates one
// (valid 10 years, with the given IP/DNS SANs) and persists it there.
func selfSignedCert(dir string, hosts []string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "self-cert.pem"), filepath.Join(dir, "self-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "nano-pulse", Organization: []string{"nano-pulse"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kpem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	_ = os.WriteFile(certPath, cpem, 0o600)
	_ = os.WriteFile(keyPath, kpem, 0o600)
	return tls.X509KeyPair(cpem, kpem)
}

// ----- RPC -----

func (c config) rpc(ctx context.Context, action string, params map[string]any, out any) error {
	body := map[string]any{"action": action}
	for k, v := range params {
		body[k] = v
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.rpcClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// ----- summary -----

type Summary struct {
	Updated     string  `json:"updated"`
	BlockCount  int64   `json:"block_count"`
	Cemented    int64   `json:"cemented"`
	Unchecked   int64   `json:"unchecked"`
	Peers       int64   `json:"peers"`
	Version     string  `json:"version"`
	Label       string  `json:"label,omitempty"`
	RepAccount  string  `json:"rep_account,omitempty"`
	Uptime      int64   `json:"uptime_seconds"`
	OnlineStake string  `json:"online_stake"`
	WeightRaw   string  `json:"weight_raw,omitempty"`
	WeightPct   float64 `json:"weight_pct"`
	SentPR      int64   `json:"sent_pr"`
	Synced      bool    `json:"synced"`
	NodeUp      bool    `json:"node_up"`
}

func atoi(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

// weightPct = weight / online * 100, computed on big integers.
func weightPct(weightRaw, onlineRaw string) float64 {
	w, ok1 := new(big.Int).SetString(strings.TrimSpace(weightRaw), 10)
	o, ok2 := new(big.Int).SetString(strings.TrimSpace(onlineRaw), 10)
	if !ok1 || !ok2 || o.Sign() == 0 {
		return 0
	}
	wf := new(big.Float).SetInt(w)
	of := new(big.Float).SetInt(o)
	pct, _ := new(big.Float).Quo(wf, of).Float64()
	return pct * 100
}

func (c config) summarize(ctx context.Context) Summary {
	s := Summary{Updated: time.Now().UTC().Format(time.RFC3339), Label: c.label, RepAccount: c.repAcct}

	var bc struct{ Count, Unchecked, Cemented string }
	if err := c.rpc(ctx, "block_count", nil, &bc); err == nil && bc.Count != "" {
		s.NodeUp = true
		s.BlockCount, s.Cemented, s.Unchecked = atoi(bc.Count), atoi(bc.Cemented), atoi(bc.Unchecked)
		s.Synced = s.BlockCount-s.Cemented <= 50
	}

	var cq struct {
		OnlineStakeTotal string `json:"online_stake_total"`
	}
	if err := c.rpc(ctx, "confirmation_quorum", nil, &cq); err == nil {
		s.OnlineStake = cq.OnlineStakeTotal
	}

	var pr struct{ Peers map[string]json.RawMessage }
	if err := c.rpc(ctx, "peers", nil, &pr); err == nil {
		s.Peers = int64(len(pr.Peers))
	}

	var ver struct {
		NodeVendor string `json:"node_vendor"`
	}
	if err := c.rpc(ctx, "version", nil, &ver); err == nil {
		s.Version = ver.NodeVendor
	}

	var up struct{ Seconds string }
	if err := c.rpc(ctx, "uptime", nil, &up); err == nil {
		s.Uptime = atoi(up.Seconds)
	}

	if c.repAcct != "" && s.OnlineStake != "" {
		var aw struct{ Weight string }
		if err := c.rpc(ctx, "account_weight", map[string]any{"account": c.repAcct}, &aw); err == nil {
			s.WeightRaw = aw.Weight
			s.WeightPct = weightPct(aw.Weight, s.OnlineStake)
		}
	}

	var st struct {
		Entries []struct {
			Type, Detail, Value string
		} `json:"entries"`
	}
	if err := c.rpc(ctx, "stats", map[string]any{"type": "counters"}, &st); err == nil {
		for _, e := range st.Entries {
			if e.Type == "vote_generator" && e.Detail == "sent_pr" {
				s.SentPR += atoi(e.Value)
			}
		}
	}

	return s
}

// ----- HTTP handlers -----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// UIConfig is the front-end configuration served at /api/config.
type UIConfig struct {
	Title          string `json:"title,omitempty"`
	Label          string `json:"label,omitempty"`
	DefaultLang    string `json:"default_lang,omitempty"`
	WidgetSwitches bool   `json:"widget_switches"`
	PublicMode     bool   `json:"public_mode"`
}

// basicAuth guards everything except /healthz when a user is configured.
func basicAuth(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="nano-pulse"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg := loadConfig()

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		writeJSON(w, cfg.summarize(ctx))
	})

	// Server-Sent Events: pushes a fresh summary every poll interval.
	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		send := func() {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			b, _ := json.Marshal(cfg.summarize(ctx))
			_, _ = w.Write([]byte("event: summary\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}

		send()
		ticker := time.NewTicker(cfg.poll)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				send()
			}
		}
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, UIConfig{
			Title:          cfg.title,
			Label:          cfg.label,
			DefaultLang:    cfg.defaultLang,
			WidgetSwitches: cfg.widgetTog,
			PublicMode:     cfg.publicMode,
		})
	})

	mux.Handle("/", http.FileServer(http.FS(sub)))

	var handler http.Handler = mux
	if cfg.authUser != "" {
		handler = basicAuth(mux, cfg.authUser, cfg.authPass)
		log.Printf("HTTP basic auth enabled (user %q)", cfg.authUser)
	}

	log.Printf("nano-pulse  rpc=%s  rep=%s  poll=%s", cfg.rpcURL, shorten(cfg.repAcct), cfg.poll)

	switch {
	case cfg.tlsDomain != "":
		// Let's Encrypt (needs a public DNS name + ports 80/443 reachable).
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.tlsDomain),
			Cache:      autocert.DirCache(cfg.tlsCache),
			Email:      cfg.tlsEmail,
		}
		// :80 answers ACME HTTP-01 challenges and redirects the rest to HTTPS.
		go func() {
			redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+cfg.tlsDomain+r.RequestURI, http.StatusMovedPermanently)
			})
			log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(redirect)))
		}()
		srv := &http.Server{Addr: cfg.tlsAddr, Handler: handler, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
		log.Printf("serving HTTPS on %s for %s via Let's Encrypt (cache=%s)", cfg.tlsAddr, cfg.tlsDomain, cfg.tlsCache)
		log.Fatal(srv.ListenAndServeTLS("", ""))

	case cfg.selfSigned:
		// Self-signed: HTTPS with no domain. Browsers warn once; fine for a private panel.
		cert, err := selfSignedCert(cfg.tlsCache, cfg.tlsHosts)
		if err != nil {
			log.Fatal(err)
		}
		srv := &http.Server{
			Addr:              cfg.tlsAddr,
			Handler:           handler,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Printf("serving HTTPS on %s with a self-signed cert (SANs=%v, cache=%s)", cfg.tlsAddr, cfg.tlsHosts, cfg.tlsCache)
		log.Fatal(srv.ListenAndServeTLS("", ""))

	default:
		srv := &http.Server{Addr: cfg.listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		log.Printf("serving HTTP on %s", cfg.listen)
		log.Fatal(srv.ListenAndServe())
	}
}

func shorten(a string) string {
	if len(a) <= 20 {
		return a
	}
	return a[:11] + "…" + a[len(a)-6:]
}

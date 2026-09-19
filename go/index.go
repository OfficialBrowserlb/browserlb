package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type SearchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}


type SearchServer struct {
	client          *http.Client
	allowedSchemes  map[string]bool
	backendRenderer string 
}

func NewSearchServer(backendRenderer string) *SearchServer {
	return &SearchServer{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		allowedSchemes:  map[string]bool{"http": true, "https": true},
		backendRenderer: backendRenderer,
	}
}

func parseLongSearchURL(raw string) (query string, parsed *url.URL, err error) {
	parsed, err = url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("invalid url: %w", err)
	}
	if !strings.HasPrefix(parsed.Scheme, "http") {
		return "", nil, errors.New("only http/https schemes are supported")
	}
	q := parsed.Query()
	if v := q.Get("q"); v != "" {
		return v, parsed, nil
	}

	for _, key := range []string{"query", "search", "text"} {
		if v := q.Get(key); v != "" {
			return v, parsed, nil
		}
	}
	return "", parsed, nil
}

func (s *SearchServer) fetch(target string) (body []byte, contentType string, statusCode int, err error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, "", 0, err
	}
	if !s.allowedSchemes[parsed.Scheme] {
		return nil, "", 0, fmt.Errorf("scheme %q not allowed", parsed.Scheme)
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", "BrowserLB/1.0 (+go-core)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 5<<20)
	body, err = io.ReadAll(limited)
	if err != nil {
		return nil, "", 0, err
	}
	return body, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

func (s *SearchServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, `{"error":"missing url param"}`, http.StatusBadRequest)
		return
	}

	query, parsed, err := parseLongSearchURL(target)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	body, contentType, status, err := s.fetch(target)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}

	resp := map[string]any{
		"requestedUrl": target,
		"host":         parsed.Host,
		"query":        query,
		"status":       status,
		"contentType":  contentType,
		"bytes":        len(body),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func upgradeToWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") {
		return nil, errors.New("not a websocket upgrade request")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijacking not supported")
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	accept := computeAcceptKey(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := buf.WriteString(response); err != nil {
		conn.Close()
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, rw: buf}, nil
}

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsConn struct {
	conn io.ReadWriteCloser
	rw   *bufio.ReadWriter
}

func (c *wsConn) readTextFrame() (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.rw, header); err != nil {
		return "", err
	}
	opcode := header[0] & 0x0f
	if opcode == 0x8 { 
		return "", io.EOF
	}
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7f)


	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		io.ReadFull(c.rw, ext)
		payloadLen = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		io.ReadFull(c.rw, ext)
		for _, b := range ext {
			payloadLen = payloadLen<<8 | int(b)
		}
	}

	var maskKey [4]byte
	if masked {
		io.ReadFull(c.rw, maskKey[:])
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return "", err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return string(payload), nil
}

func (c *wsConn) writeTextFrame(msg string) error {
	data := []byte(msg)
	var header []byte
	switch {
	case len(data) <= 125:
		header = []byte{0x81, byte(len(data))}
	case len(data) <= 65535:
		header = []byte{0x81, 126, byte(len(data) >> 8), byte(len(data))}
	default:
		return errors.New("message too large for this minimal implementation")
	}
	if _, err := c.rw.Write(header); err != nil {
		return err
	}
	if _, err := c.rw.Write(data); err != nil {
		return err
	}
	return c.rw.Flush()
}
func (s *SearchServer) handleLiveSearch(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeToWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.conn.Close()

	for {
		query, err := ws.readTextFrame()
		if err != nil {
			return
		}
		results := []SearchResult{
			{Title: "BrowserLB result for " + query, URL: "https://example.com/?q=" + url.QueryEscape(query), Snippet: "Live suggestion from the Go core."},
		}
		payload, _ := json.Marshal(map[string]any{"query": query, "results": results})
		if err := ws.writeTextFrame(string(payload)); err != nil {
			return
		}
	}
}

func main() {
	addr := flag.String("addr", ":8080", "address for the Go search/transport core")
	backend := flag.String("backend", "http://localhost:5000", "Python rendering backend base URL")
	flag.Parse()

	srv := NewSearchServer(*backend)

	mux := http.NewServeMux()
	mux.HandleFunc("/search", srv.handleSearch) 
	mux.HandleFunc("/ws", srv.handleLiveSearch) 
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","service":"browserlb-go"}`))
	})

	log.Printf("BrowserLB Go core listening on %s (backend=%s)", *addr, *backend)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

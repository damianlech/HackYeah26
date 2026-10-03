// Minimal Go equivalent of gateway.py (benchmark harness): pass-through or SSE parse + holdback secret scan.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var rx = regexp.MustCompile(`AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,48}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

const hold = 64

var client = &http.Client{Transport: &http.Transport{MaxIdleConns: 1000, MaxIdleConnsPerHost: 1000}}

type delta struct {
	Content string `json:"content,omitempty"`
}
type choice struct {
	Index        int     `json:"index"`
	Delta        delta   `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}
type event struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Choices []choice        `json:"choices"`
	Usage   json.RawMessage `json:"usage,omitempty"`
}

func emit(w io.Writer, f http.Flusher, base event, text string, finish *string) {
	ev := base
	ev.Usage = nil
	ev.Choices = []choice{{Index: 0, Delta: delta{Content: text}, FinishReason: finish}}
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	t0 := time.Now()
	up, err := client.Post("http://127.0.0.1:9101/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer up.Body.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Server-Timing", fmt.Sprintf("preflight;dur=%.2f", float64(time.Since(t0).Microseconds())/1000))
	fl := w.(http.Flusher)
	if r.Header.Get("x-mode") == "pass" {
		buf := make([]byte, 32*1024)
		for {
			n, err := up.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				fl.Flush()
			}
			if err != nil {
				return
			}
		}
	}
	sc := bufio.NewScanner(up.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var base event
	var usage json.RawMessage
	pending := ""
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}
		var ev event
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if base.ID == "" {
			base = event{ID: ev.ID, Object: ev.Object, Created: ev.Created, Model: ev.Model}
		}
		if len(ev.Usage) > 0 && string(ev.Usage) != "null" {
			usage = ev.Usage
		}
		for _, ch := range ev.Choices {
			if ch.Delta.Content != "" {
				pending += ch.Delta.Content
				if loc := rx.FindStringIndex(pending); loc != nil {
					if loc[0] > 0 {
						emit(w, fl, base, pending[:loc[0]], nil)
					}
					cf := "content_filter"
					emit(w, fl, base, "", &cf)
					fmt.Fprint(w, "data: {\"error\":{\"message\":\"Blocked by policy SEC-001\",\"type\":\"policy_violation\",\"code\":\"content_blocked\"}}\n\n")
					fl.Flush()
					return
				}
				if len(pending) > hold {
					emit(w, fl, base, pending[:len(pending)-hold], nil)
					pending = pending[len(pending)-hold:]
				}
			}
			if ch.FinishReason != nil {
				if pending != "" {
					emit(w, fl, base, pending, nil)
					pending = ""
				}
				emit(w, fl, base, "", ch.FinishReason)
			}
		}
	}
	if usage != nil {
		fmt.Fprintf(w, "data: {\"id\":%q,\"object\":%q,\"created\":%d,\"model\":%q,\"choices\":[],\"usage\":%s}\n\n", base.ID, base.Object, base.Created, base.Model, usage)
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	fl.Flush()
}

func main() {
	http.HandleFunc("/v1/chat/completions", handler)
	http.ListenAndServe(":9102", nil)
}

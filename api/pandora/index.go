package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	pandoraCache  sync.Map
	pandoraCSRFRe = regexp.MustCompile(`csrftoken=([a-f0-9]+)`)
)

const pandoraCacheTTL = 5 * time.Minute
const pandoraUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

type pandoraCacheEntry struct {
	Data   map[string]any
	Expiry time.Time
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Cache-Control", "public, max-age=60, s-maxage=300, stale-while-revalidate=600")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Method Not Allowed"})
		return
	}

	// IP extraction like api/pandora.js:21-24
	forwarded := r.Header.Get("X-Forwarded-For")
	var ip string
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		ip = strings.TrimSpace(parts[0])
	} else {
		// RemoteAddr includes port
		ip = r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		if ip == "" {
			ip = "unknown"
		}
	}

	now := time.Now()
	if v, ok := pandoraCache.Load(ip); ok {
		entry := v.(pandoraCacheEntry)
		if now.Before(entry.Expiry) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := make(map[string]any, len(entry.Data)+2)
			for k, val := range entry.Data {
				resp[k] = val
			}
			resp["source"] = "cache"
			resp["expires_in_seconds"] = int(entry.Expiry.Sub(now).Seconds())
			json.NewEncoder(w).Encode(resp)
			return
		}
		pandoraCache.Delete(ip)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Step 1: GET https://www.pandora.com to extract csrftoken
	reqHome, err := http.NewRequest(http.MethodGet, "https://www.pandora.com", nil)
	if err != nil {
		log.Printf("pandora home req create: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	reqHome.Header.Set("User-Agent", pandoraUserAgent)

	respHome, err := client.Do(reqHome)
	if err != nil {
		log.Printf("pandora home fetch: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	defer respHome.Body.Close()

	// Collect Set-Cookie headers and body for regex, matching api/pandora.js:49 which greps curl -I output
	var cookieHeader string
	for _, c := range respHome.Cookies() {
		cookieHeader += c.String() + ";"
	}
	for _, h := range respHome.Header.Values("Set-Cookie") {
		cookieHeader += h + ";"
	}
	// Also read a limited body in case token is in body (defensive)
	bodyBytes, _ := io.ReadAll(io.LimitReader(respHome.Body, 1<<20))
	cookieHeader += string(bodyBytes)

	match := pandoraCSRFRe.FindStringSubmatch(cookieHeader)
	if len(match) < 2 {
		// Fallback: check raw headers string
		log.Printf("pandora csrf not found, headers: %v", respHome.Header)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Falha ao obter csrftoken da home page."})
		return
	}
	csrfToken := match[1]

	// Step 2: POST https://www.pandora.com/api/v1/auth/anonymousLogin
	reqLogin, err := http.NewRequest(http.MethodPost, "https://www.pandora.com/api/v1/auth/anonymousLogin", strings.NewReader("{}"))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Cookie", "csrftoken="+csrfToken)
	reqLogin.Header.Set("X-CsrfToken", csrfToken)
	reqLogin.Header.Set("User-Agent", pandoraUserAgent)
	reqLogin.Header.Set("Origin", "https://www.pandora.com")
	reqLogin.Header.Set("Referer", "https://www.pandora.com/")

	respLogin, err := client.Do(reqLogin)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	defer respLogin.Body.Close()

	if respLogin.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(respLogin.Body, 4096))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(respLogin.StatusCode)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": fmt.Sprintf("login status %d: %s", respLogin.StatusCode, string(b))})
		return
	}

	var loginData struct {
		AuthToken string `json:"authToken"`
	}
	bodyLogin, _ := io.ReadAll(io.LimitReader(respLogin.Body, 1<<20))
	if err := json.Unmarshal(bodyLogin, &loginData); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Falha ao parsear resposta do login JSON."})
		return
	}
	if loginData.AuthToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Resposta do login não contém authToken."})
		return
	}

	resultData := map[string]any{
		"success":   true,
		"csrfToken": csrfToken,
		"authToken": loginData.AuthToken,
		"method":    "go-net-http",
		"source":    "live",
	}

	pandoraCache.Store(ip, pandoraCacheEntry{
		Data:   resultData,
		Expiry: now.Add(pandoraCacheTTL),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resultData)
}

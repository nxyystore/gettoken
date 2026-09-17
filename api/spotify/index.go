package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Cache-Control", "no-store, max-age=0")

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

	tokenerBase := strings.TrimSpace(os.Getenv("TOKENER_URL"))
	if tokenerBase == "" {
		tokenerBase = strings.TrimSpace(os.Getenv("SPOTIFY_TOKENER_URL"))
	}
	if tokenerBase == "" {
		tokenerBase = "https://spotify.swipe.codes"
	}
	tokenerBase = strings.TrimRight(tokenerBase, "/")

	// Build target URL: support both base URL and full /api/token URL
	targetURL := tokenerBase
	if !strings.HasSuffix(strings.ToLower(targetURL), "/api/token") {
		targetURL = targetURL + "/api/token"
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Invalid TOKENER_URL", "details": err.Error()})
		return
	}
	// Forward query params (e.g. productType) for compatibility, though tokener ignores them
	q := parsed.Query()
	for k, vals := range r.URL.Query() {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}

	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("tokener proxy error: %v target=%s", err, parsed.String())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to contact tokener", "details": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("tokener error: status=%d body=%s target=%s", resp.StatusCode, string(body), parsed.String())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		var tokenerErr any
		if err := json.Unmarshal(body, &tokenerErr); err == nil {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Tokener error", "details": tokenerErr, "status": resp.StatusCode})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Tokener error", "details": string(body), "status": resp.StatusCode})
		}
		return
	}

	// Success: tokener returns Spotify's JSON directly (accessToken etc.)
	ctype := resp.Header.Get("Content-Type")
	if ctype == "" {
		ctype = "application/json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

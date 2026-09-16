package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	mu                  sync.Mutex
	currentTotpSecret   string
	currentTotpVersion  string
	lastSecretFetchTime time.Time
)

const secretFetchInterval = time.Hour
const secretsURL = "https://raw.githubusercontent.com/xyloflake/spot-secrets-go/refs/heads/main/secrets/secretDict.json"
const userAgentMobile = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

	productType := r.URL.Query().Get("productType")
	if productType != "mobile-web-player" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "productType must be mobile-web-player"})
		return
	}

	spDc := os.Getenv("SP_DC")
	if spDc == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "SP_DC env variable not configured on server for mobile token generation"})
		return
	}

	if err := ensureTotpSecrets(); err != nil {
		log.Printf("Failed to ensure TOTP secrets: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to fetch TOTP secrets", "details": err.Error()})
		return
	}

	serverTimeMs, err := getServerTime(spDc)
	if err != nil {
		log.Printf("Failed to get server time: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to get server time", "details": err.Error()})
		return
	}

	serverTimeSec := serverTimeMs / 1000
	localTimeSec := time.Now().Unix()

	totpLocal := generateTOTP(currentTotpSecret, localTimeSec)
	totpServer := generateTOTP(currentTotpSecret, serverTimeSec)

	tokenURL, _ := url.Parse("https://open.spotify.com/api/token")
	q := tokenURL.Query()
	q.Set("reason", "transport")
	q.Set("productType", "mobile-web-player")
	q.Set("totp", totpLocal)
	ver := currentTotpVersion
	if ver == "" {
		ver = "19"
	}
	q.Set("totpVer", ver)
	q.Set("totpServer", totpServer)
	tokenURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", userAgentMobile)
	req.Header.Set("Origin", "https://open.spotify.com/")
	req.Header.Set("Referer", "https://open.spotify.com/")
	req.Header.Set("Cookie", "sp_dc="+spDc)

	client := &http.Client{Timeout: 10 * time.Second}
	spotifyRes, err := client.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	defer spotifyRes.Body.Close()

	bodyBytes, _ := io.ReadAll(spotifyRes.Body)
	if spotifyRes.StatusCode != http.StatusOK {
		log.Printf("Spotify token error: status=%d body=%s totp=%s totpServer=%s ver=%s", spotifyRes.StatusCode, string(bodyBytes), totpLocal, totpServer, ver)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(spotifyRes.StatusCode)
		// Try to preserve Spotify's JSON, fallback to text
		var spotifyErr any
		if err := json.Unmarshal(bodyBytes, &spotifyErr); err == nil {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to get mobile token", "details": spotifyErr, "status": spotifyRes.StatusCode})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to get mobile token", "details": string(bodyBytes), "status": spotifyRes.StatusCode})
		}
		return
	}

	// Decode and re-encode to ensure valid JSON
	var data any
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to parse token response", "details": string(bodyBytes)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func ensureTotpSecrets() error {
	mu.Lock()
	defer mu.Unlock()

	if currentTotpSecret != "" && time.Since(lastSecretFetchTime) < secretFetchInterval {
		return nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(secretsURL)
	if err != nil {
		return fmt.Errorf("fetch secrets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch secrets: status %d", resp.StatusCode)
	}

	var secrets map[string][]int
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return fmt.Errorf("decode secrets: %w", err)
	}

	if len(secrets) == 0 {
		return fmt.Errorf("empty secrets")
	}

	maxVer := -1
	maxVerStr := ""
	for k := range secrets {
		v, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		if v > maxVer {
			maxVer = v
			maxVerStr = k
		}
	}
	if maxVerStr == "" {
		return fmt.Errorf("no valid version")
	}

	secretData := secrets[maxVerStr]
	mapped := make([]byte, len(secretData))
	for i, v := range secretData {
		mapped[i] = byte(v ^ ((i % 33) + 9))
	}

	currentTotpSecret = hex.EncodeToString(mapped)
	currentTotpVersion = maxVerStr
	lastSecretFetchTime = time.Now()
	return nil
}

func getServerTime(spDc string) (int64, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://open.spotify.com/api/server-time", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgentMobile)
	req.Header.Set("Cookie", "sp_dc="+spDc)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("server-time request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("server-time status %d", resp.StatusCode)
	}

	var data struct {
		ServerTime int64 `json:"serverTime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, fmt.Errorf("decode serverTime: %w", err)
	}
	if data.ServerTime == 0 {
		return 0, fmt.Errorf("empty serverTime")
	}
	return data.ServerTime, nil
}

func generateTOTP(secretHex string, timeSec int64) string {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return "000000"
	}
	counter := timeSec / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f
	code := (int(digest[offset]&0x7f)<<24 |
		int(digest[offset+1]&0xff)<<16 |
		int(digest[offset+2]&0xff)<<8 |
		int(digest[offset+3]&0xff)) % 1000000

	return fmt.Sprintf("%06d", code)
}

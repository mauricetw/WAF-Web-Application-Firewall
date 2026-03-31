package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// ==========================================
// 1. WAF 基礎設定常數
// ==========================================
const (
	WAFPort    = ":8080"
	BackendURL = "http://localhost:9000"
	RateLimit  = 5
	WindowSec  = 10
)

// ==========================================
// 2. 防護引擎特徵庫 (Regex)
// ==========================================
var (
	sqlRegex = regexp.MustCompile(`(?i)(UNION.+SELECT|SELECT.+FROM|INSERT.+INTO|UPDATE.+SET|DROP\s+TABLE|--\s*$)`)
	xssRegex = regexp.MustCompile(`(?i)(<script.*?>|javascript:|onerror=|onload=|eval\()`)
	lfiRegex = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd)`)
)

// ==========================================
// 3. Rate Limiting (頻率限制) 狀態紀錄
// ==========================================
type visitor struct {
	count    int
	lastSeen time.Time
}

var (
	visitors = make(map[string]*visitor)
	mu       sync.Mutex
)

func isRateLimited(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	v, exists := visitors[ip]
	if !exists {
		visitors[ip] = &visitor{count: 1, lastSeen: time.Now()}
		return false
	}

	if time.Since(v.lastSeen) > time.Duration(WindowSec)*time.Second {
		v.count = 1
		v.lastSeen = time.Now()
		return false
	}

	v.count++
	return v.count > RateLimit
}

// ==========================================
// 4. 惡意特徵檢查邏輯 (已升級 URL 解碼防禦)
// ==========================================
func isMalicious(req *http.Request) (bool, string) {
	// 1. 取得瀏覽器傳送過來的原始 URI (可能包含 %3C 這種 URL 編碼)
	rawURI := req.URL.String()

	// 2. 進行 URL 解碼 (URL Decode)
	// 這會將 %3C 轉回 <，%20 轉回空白，讓隱藏的攻擊現出原形
	decodedURI, err := url.QueryUnescape(rawURI)
	if err != nil {
		// 如果解碼失敗(遇到不合法的編碼格式)，我們仍保留原始字串進行後續檢查
		decodedURI = rawURI
		log.Printf("[Warning] URL Decode failed for: %s", rawURI)
	}

	// 3. 使用「解碼後」的字串進行 Regex 比對
	if sqlRegex.MatchString(decodedURI) {
		return true, "SQL Injection"
	}
	if xssRegex.MatchString(decodedURI) {
		return true, "XSS"
	}
	if lfiRegex.MatchString(decodedURI) {
		return true, "LFI/RFI"
	}

	return false, ""
}

// ==========================================
// 5. WAF 核心中介軟體 (Middleware)
// ==========================================
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr

		// 基礎日誌記錄 (印出原始 URI 方便追蹤)
		log.Printf("[REQ] IP: %s | Method: %s | URI: %s", clientIP, r.Method, r.URL.String())

		// 防護一：IP Rate Limiting 檢查
		if isRateLimited(clientIP) {
			log.Printf("🚨 [BLOCKED] Rate Limit Exceeded: %s", clientIP)
			http.Error(w, "429 Too Many Requests - WAF Blocked", http.StatusTooManyRequests)
			return
		}

		// 防護二：Regex 惡意 Payload 檢查
		if isAttack, attackType := isMalicious(r); isAttack {
			// 在日誌中印出被攔截的惡意行為
			log.Printf("💀 [BLOCKED] %s Attack detected from %s, Payload: %s", attackType, clientIP, r.URL.String())
			http.Error(w, "403 Forbidden - Malicious Request Blocked", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==========================================
// 6. 主程式進入點
// ==========================================
func main() {
	targetURL, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatalf("無法解析後端 URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-WAF-Protected-By", "Lightweight-SecWAF/2.1")
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/", proxy)

	handler := WAFMiddleware(mux)

	fmt.Println("=====================================================")
	fmt.Printf("🛡️  輕量級 WAF (v2.1 解碼增強版) 已啟動 | 監聽 Port %s\n", WAFPort)
	fmt.Printf("⚙️  目前規則: 防禦 SQLi, XSS, 目錄穿越 | 限流: %d次/%d秒\n", RateLimit, WindowSec)
	fmt.Printf("🔄 流量將轉發至後端: %s\n", BackendURL)
	fmt.Println("=====================================================")

	server := &http.Server{
		Addr:         WAFPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("WAF 伺服器啟動失敗: %v", err)
	}
}

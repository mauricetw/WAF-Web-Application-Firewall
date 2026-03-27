package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// WAF 設定常數
const (
	WAFPort     = ":8080"                  // WAF 監聽的 Port
	BackendURL  = "http://localhost:9000"  // 真正後端伺服器的位址 (請確保此 port 有服務運行)
)

// WAFMiddleware 是一個中介軟體，未來第 2 個月的過濾引擎會寫在這裡
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 取得客戶端真實 IP (如果有經過 Nginx 則需要抓 X-Forwarded-For)
		clientIP := r.RemoteAddr

		// [第 1 個月] 基礎日誌記錄：印出收到的 Request
		log.Printf("[REQ] Time: %s | IP: %s | Method: %s | URI: %s", 
			time.Now().Format(time.RFC3339), clientIP, r.Method, r.URL.Path)

		// ---------------------------------------------------------
		// [第 2 個月預留區塊]
		// 1. 這裡將加入 IP Rate Limiting 檢查
		// 2. 這裡將加入 Regex 惡意 Payload 檢查 (URI, Headers, Body)
		// 如果發現惡意攻擊：
		// log.Printf("[BLOCKED] Attack detected from %s", clientIP)
		// http.Error(w, "403 Forbidden - WAF Blocked", http.StatusForbidden)
		// return // 終止處理，不往下傳遞給後端
		// ---------------------------------------------------------

		// 若檢查無誤，將請求交給下一個處理程序 (也就是 Reverse Proxy)
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 1. 解析後端伺服器的 URL
	targetURL, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatalf("無法解析後端 URL: %v", err)
	}

	// 2. 建立一個標準的 Reverse Proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 可選：自定義 ModifyResponse 來檢查後端回傳的內容 (防範資料外洩)
	proxy.ModifyResponse = func(resp *http.Response) error {
		// log.Printf("[RES] Backend status code: %d", resp.StatusCode)
		// 可以在這裡加入安全性 Headers，例如：
		resp.Header.Set("X-WAF-Protected-By", "Lightweight-SecWAF/1.0")
		return nil
	}

	// 3. 設定路由並套用 WAF 中介軟體
	mux := http.NewServeMux()
	mux.Handle("/", proxy) // 所有流量交給 Proxy

	// 將 mux 包装進我們的 WAFMiddleware
	handler := WAFMiddleware(mux)

	// 4. 啟動 WAF 伺服器
	fmt.Printf("🛡️  輕量級 WAF 已啟動，監聽 Port %s\n", WAFPort)
	fmt.Printf("🔄 流量將轉發至後端伺服器: %s\n", BackendURL)
	
	server := &http.Server{
		Addr:         WAFPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second, // 防止 Slowloris 攻擊的基礎防禦
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("WAF 伺服器啟動失敗: %v", err)
	}
}
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sync"
	"time"

	// 引入 MySQL 驅動，前面的底線 '_' 代表只觸發它的 init() 註冊驅動，不直接呼叫它的函數
	_ "github.com/go-sql-driver/mysql"
)

const (
	WAFPort    = ":8080"
	BackendURL = "http://localhost:9000"
	RateLimit  = 5
	WindowSec  = 10

	// 修正時區問題：加上 &loc=Local 告訴 Go 使用本地時區解析時間
	DBDSN = "root:@tcp(127.0.0.1:3306)/waf_logs?parseTime=true&loc=Local"
)

var (
	sqlRegex = regexp.MustCompile(`(?i)(UNION.+SELECT|SELECT.+FROM|INSERT.+INTO|UPDATE.+SET|DROP\s+TABLE|--\s*$)`)
	xssRegex = regexp.MustCompile(`(?i)(<script.*?>|javascript:|onerror=|onload=|eval\()`)
	lfiRegex = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd)`)

	visitors = make(map[string]*visitor)
	mu       sync.Mutex

	// 全域的資料庫連線物件
	db *sql.DB
)

type visitor struct {
	count    int
	lastSeen time.Time
}

// ==========================================
// 資料庫初始化與寫入功能
// ==========================================

// initDB 初始化資料庫連線
func initDB() {
	var err error
	db, err = sql.Open("mysql", DBDSN)
	if err != nil {
		log.Fatalf("❌ 資料庫連線設定失敗: %v", err)
	}

	// 測試連線是否真的通暢
	if err := db.Ping(); err != nil {
		log.Fatalf("❌ 無法連線到資料庫 (請確認 XAMPP 的 MySQL 是否已啟動): %v", err)
	}

	// 設定連線池參數 (提升效能)
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	fmt.Println("✅ 成功連線至 MariaDB 資料庫 (waf_logs)")
}

// logAttackToDB 將攻擊紀錄寫入資料庫
func logAttackToDB(ip, method, uri, attackType string) {
	query := `INSERT INTO attack_logs (source_ip, http_method, request_uri, attack_type) VALUES (?, ?, ?, ?)`

	// 使用 Exec 執行寫入，避免 SQL Injection (我們自己也要防禦自己！)
	_, err := db.Exec(query, ip, method, uri, attackType)
	if err != nil {
		log.Printf("❌ 寫入資料庫失敗: %v", err)
	}
}

// ==========================================
// 戰情儀表板 (Dashboard) API 處理
// ==========================================

// DashboardData 定義回傳給前端的 JSON 結構
type DashboardData struct {
	Stats   []AttackStat `json:"stats"`
	Recents []LogEntry   `json:"recents"`
}

type AttackStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type LogEntry struct {
	// 修正時區問題：將 string 改為 time.Time，這樣轉為 JSON 時會自動帶上標準時區格式 (RFC3339)
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	AttackType string    `json:"attack_type"`
}

// apiStatsHandler 從資料庫讀取統計資料並回傳 JSON
func apiStatsHandler(w http.ResponseWriter, r *http.Request) {
	var data DashboardData

	// 1. 取得各類型攻擊次數統計
	rows, err := db.Query("SELECT attack_type, COUNT(*) FROM attack_logs GROUP BY attack_type")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var stat AttackStat
			if err := rows.Scan(&stat.Type, &stat.Count); err == nil {
				data.Stats = append(data.Stats, stat)
			}
		}
	}

	// 2. 取得最新 10 筆攻擊紀錄
	recentRows, err := db.Query("SELECT timestamp, source_ip, http_method, request_uri, attack_type FROM attack_logs ORDER BY timestamp DESC LIMIT 10")
	if err == nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var entry LogEntry
			if err := recentRows.Scan(&entry.Timestamp, &entry.SourceIP, &entry.Method, &entry.URI, &entry.AttackType); err == nil {
				data.Recents = append(data.Recents, entry)
			}
		}
	}

	// 設定回傳格式為 JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// ==========================================
// 核心防護邏輯 (與之前相同)
// ==========================================

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

func isMalicious(req *http.Request) (bool, string) {
	rawURI := req.URL.String()
	decodedURI, err := url.QueryUnescape(rawURI)
	if err != nil {
		decodedURI = rawURI
	}

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
// WAF Middleware
// ==========================================

func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// [新增] 白名單機制：如果是存取儀表板或 API，直接放行，不套用 WAF 攔截規則
		if r.URL.Path == "/dashboard" || r.URL.Path == "/api/stats" {
			next.ServeHTTP(w, r)
			return
		}

		// 修正：從 RemoteAddr 中分離出單純的 IP 位址，忽略 Port 號
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// 如果解析失敗（通常不會發生），就退回使用原本的字串
			clientIP = r.RemoteAddr
		}

		// 防護一：限流檢查
		if isRateLimited(clientIP) {
			log.Printf("🚨 [BLOCKED] Rate Limit: %s", clientIP)

			// 使用 goroutine (背景執行) 寫入資料庫，不卡住當前請求
			go logAttackToDB(clientIP, r.Method, r.URL.String(), "Rate Limit DDoS")

			http.Error(w, "429 Too Many Requests - WAF Blocked", http.StatusTooManyRequests)
			return
		}

		// 防護二：Regex 檢查
		if isAttack, attackType := isMalicious(r); isAttack {
			log.Printf("💀 [BLOCKED] %s: %s", attackType, clientIP)

			// 使用 goroutine 背景寫入資料庫
			go logAttackToDB(clientIP, r.Method, r.URL.String(), attackType)

			http.Error(w, "403 Forbidden - Malicious Request Blocked", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==========================================
// 主程式
// ==========================================

func main() {
	// 先啟動資料庫連線
	initDB()
	// 程式結束前關閉連線池
	defer db.Close()

	targetURL, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatalf("無法解析後端 URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-WAF-Protected-By", "Lightweight-SecWAF/3.0-DB")
		return nil
	}

	mux := http.NewServeMux()

	// 新增：註冊 Dashboard 的 API 與 靜態網頁路由
	// 讓這些特定路徑由 WAF 自己處理，而不轉發給後端
	mux.HandleFunc("/api/stats", apiStatsHandler)
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})

	mux.Handle("/", proxy)

	fmt.Println("=====================================================")
	fmt.Printf("🛡️  輕量級 WAF (v3.0 具備資料庫紀錄) 已啟動\n")
	fmt.Printf("📊 戰情儀表板: http://localhost%s/dashboard\n", WAFPort)
	fmt.Printf("🔄 監聽 Port %s，轉發至 %s\n", WAFPort, BackendURL)
	fmt.Println("=====================================================")

	server := &http.Server{
		Addr:         WAFPort,
		Handler:      WAFMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("WAF 伺服器啟動失敗: %v", err)
	}
}

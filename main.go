package main

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

// In-memory storage with expiration
var (
	urlStore = make(map[string]urlEntry)
	mu       sync.RWMutex
)

type urlEntry struct {
	URL       string
	CreatedAt time.Time
}

// Rate limiting
var (
	rateLimiter = make(map[string][]time.Time)
	rateMu      sync.Mutex
)

const (
	maxURLLength    = 2048 // Max input URL length
	maxRequestSize  = 4096 // Max request body size
	rateLimit       = 30   // Requests per minute per IP
	rateLimitWindow = time.Minute
	urlExpiration   = 24 * time.Hour // URLs expire after 24 hours
	maxStoredURLs   = 100000         // Maximum URLs in memory
)

type LengthenRequest struct {
	URL    string `json:"url"`
	Length int    `json:"length"` // How ridiculously long (1-10 scale)
}

type LengthenResponse struct {
	Original string `json:"original"`
	Long     string `json:"long"`
	Length   int    `json:"length"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "60320"
	}

	// Validate port to prevent log injection
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(port) {
		log.Fatal("Invalid PORT value")
	}

	// Start cleanup goroutine
	go cleanupExpiredURLs()

	mux := http.NewServeMux()
	mux.HandleFunc("/", securityHeaders(handleHome))
	mux.HandleFunc("/api/lengthen", securityHeaders(handleLengthen))
	mux.HandleFunc("/r/", securityHeaders(handleRedirect))

	// Use http.Server with timeouts for security
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Make A Longer Link running on http://localhost:%s", port) // #nosec G706 - port validated as numeric
	log.Fatal(server.ListenAndServe())
}

// Security headers middleware
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next(w, r)
	}
}

// Rate limiting check
func isRateLimited(ip string) bool {
	rateMu.Lock()
	defer rateMu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rateLimitWindow)

	// Clean old entries
	var recent []time.Time
	for _, t := range rateLimiter[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}
	rateLimiter[ip] = recent

	if len(recent) >= rateLimit {
		return true
	}

	rateLimiter[ip] = append(rateLimiter[ip], now)
	return false
}

// Get client IP
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For for proxied requests
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

// Validate URL - only allow http/https, no javascript/data/file schemes
func validateURL(inputURL string) (string, error) {
	// Check length
	if len(inputURL) > maxURLLength {
		return "", fmt.Errorf("URL too long (max %d characters)", maxURLLength)
	}

	// Add protocol if missing
	if !strings.HasPrefix(inputURL, "http://") && !strings.HasPrefix(inputURL, "https://") {
		inputURL = "https://" + inputURL
	}

	// Parse and validate
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format")
	}

	// Only allow http and https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("only http and https URLs are allowed")
	}

	// Must have a host
	if parsed.Host == "" {
		return "", fmt.Errorf("URL must have a valid host")
	}

	// Block localhost and private IPs (basic SSRF protection)
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" ||
		strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "172.16.") || strings.HasPrefix(host, "172.17.") ||
		strings.HasPrefix(host, "172.18.") || strings.HasPrefix(host, "172.19.") ||
		strings.HasPrefix(host, "172.2") || strings.HasPrefix(host, "172.30.") ||
		strings.HasPrefix(host, "172.31.") || host == "::1" || host == "[::1]" {
		return "", fmt.Errorf("private/local URLs are not allowed")
	}

	return inputURL, nil
}

// Cleanup expired URLs periodically
func cleanupExpiredURLs() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		mu.Lock()
		now := time.Now()
		for slug, entry := range urlStore {
			if now.Sub(entry.CreatedAt) > urlExpiration {
				delete(urlStore, slug)
			}
		}
		mu.Unlock()
		log.Printf("Cleanup complete. URLs in store: %d", len(urlStore))
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl, err := template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execute error: %v", err)
	}
}

func handleLengthen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting
	clientIP := getClientIP(r)
	if isRateLimited(clientIP) {
		http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req LengthenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON or request too large", http.StatusBadRequest)
		return
	}

	// Validate URL
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Validate and sanitize URL
	validatedURL, err := validateURL(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if we've hit max storage
	mu.RLock()
	storeSize := len(urlStore)
	mu.RUnlock()
	if storeSize >= maxStoredURLs {
		http.Error(w, "Service temporarily at capacity. Please try again later.", http.StatusServiceUnavailable)
		return
	}

	// Default length scale: 5 (medium absurdity)
	if req.Length < 1 || req.Length > 10 {
		req.Length = 5
	}

	// Generate absurdly long random string
	// Length scale: 1 = 500 chars, 10 = 8000 chars (RFC 7230 practical limit)
	charCount := 500 + (req.Length-1)*833
	longSlug := generateGibberish(charCount)

	// Store the mapping with timestamp
	mu.Lock()
	urlStore[longSlug] = urlEntry{
		URL:       validatedURL,
		CreatedAt: time.Now(),
	}
	mu.Unlock()

	// Build the long URL
	host := r.Host
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	longURL := scheme + "://" + host + "/r/" + longSlug

	resp := LengthenResponse{
		Original: validatedURL,
		Long:     longURL,
		Length:   len(longSlug),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/r/")
	if slug == "" {
		http.Error(w, "No slug provided", http.StatusBadRequest)
		return
	}

	mu.RLock()
	entry, exists := urlStore[slug]
	mu.RUnlock()

	if !exists {
		http.Error(w, "Link not found. It's too long, even for us!", http.StatusNotFound)
		return
	}

	// Check if expired
	if time.Since(entry.CreatedAt) > urlExpiration {
		mu.Lock()
		delete(urlStore, slug)
		mu.Unlock()
		http.Error(w, "Link has expired.", http.StatusGone)
		return
	}

	http.Redirect(w, r, entry.URL, http.StatusTemporaryRedirect)
}

func generateGibberish(length int) string {
	// Dial-up modem sounds!
	sounds := []string{
		"beep", "boop", "borp", "blop", "bloop", "blooop", "bloooop", "blooooop",
		"beeep", "beeeep", "beeeeep", "beeeeeep",
		"baaaah", "baaaaah", "baaaaaah",
		"skree", "skreee", "skreeee",
		"whirr", "whirrr", "whirrrr",
		"ding", "dong", "doot", "doooot",
		"neeee", "neeeee", "neeeeee",
		"brrrr", "brrrrr", "brrrrrr",
		"chirp", "chirrrp", "chirrrrp",
		"weeee", "weeeee", "weeeeee",
		"zzzzt", "zzzzzt", "zzzzzzt",
		"pshhhh", "pshhhhh", "pshhhhhh",
		"kachunk", "screech", "crackle",
		"fweee", "fweeee", "fweeeee",
		"bonk", "boink", "bink", "bonnnk",
	}

	var result strings.Builder
	for result.Len() < length {
		// Pick a random sound
		randByte := make([]byte, 1)
		rand.Read(randByte)
		sound := sounds[int(randByte[0])%len(sounds)]

		if result.Len() > 0 {
			result.WriteString("-")
		}
		result.WriteString(sound)
	}

	// Trim to exact length if needed
	str := result.String()
	if len(str) > length {
		str = str[:length]
	}
	return str
}

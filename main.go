package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
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

// Rate limiting (no URL storage needed anymore!)
var (
	rateLimiter = make(map[string][]time.Time)
	rateMu      sync.Mutex
)

const (
	maxURLLength    = 2048 // Max input URL length
	maxRequestSize  = 4096 // Max request body size
	rateLimit       = 30   // Requests per minute per IP
	rateLimitWindow = time.Minute
	urlDelimiter    = "_BEEPBOOP_" // Delimiter between encoded URL and padding
	minCharCount    = 100          // Minimum URL length
	maxCharCount    = 8000         // RFC 7230 practical max
)

type LengthenRequest struct {
	URL       string `json:"url"`
	Length    int    `json:"length"`    // Legacy: 1-10 scale
	CharCount int    `json:"charCount"` // Direct character count (100-8000)
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
	log.Printf("Stateless mode: URLs are deterministic, no database needed!")
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

	// Determine target length
	var targetLength int
	if req.CharCount > 0 {
		// Use direct character count if provided
		targetLength = req.CharCount
		if targetLength < minCharCount {
			targetLength = minCharCount
		}
		if targetLength > maxCharCount {
			targetLength = maxCharCount
		}
	} else {
		// Fall back to legacy 1-10 scale
		if req.Length < 1 || req.Length > 10 {
			req.Length = 5
		}
		// Length scale: 1 = 500 chars, 10 = 8000 chars (RFC 7230 practical limit)
		targetLength = 500 + (req.Length-1)*833
	}

	// Generate deterministic long slug
	longSlug := encodeURLToSlug(validatedURL, targetLength)

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

	// Decode the URL from the slug
	originalURL, err := decodeSlugToURL(slug)
	if err != nil {
		http.Error(w, "Invalid or corrupted link. The dial-up modem gods are displeased!", http.StatusBadRequest)
		return
	}

	// Validate the decoded URL (security check)
	if _, err := validateURL(originalURL); err != nil {
		http.Error(w, "Invalid redirect target", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, originalURL, http.StatusTemporaryRedirect)
}

// encodeURLToSlug creates a deterministic long slug from a URL
// Format: <base64url_encoded_url>_BEEPBOOP_<deterministic_dial_up_sounds>
func encodeURLToSlug(originalURL string, targetLength int) string {
	// URL-safe base64 encode the URL
	encoded := base64.URLEncoding.EncodeToString([]byte(originalURL))

	// Calculate how much padding we need
	baseLength := len(encoded) + len(urlDelimiter)
	paddingNeeded := targetLength - baseLength
	if paddingNeeded < 0 {
		paddingNeeded = 100 // Minimum padding
	}

	// Generate deterministic padding based on URL hash
	padding := generateDeterministicGibberish(originalURL, paddingNeeded)

	return encoded + urlDelimiter + padding
}

// decodeSlugToURL extracts and decodes the original URL from a slug
func decodeSlugToURL(slug string) (string, error) {
	// Find the delimiter
	idx := strings.Index(slug, urlDelimiter)
	if idx == -1 {
		return "", fmt.Errorf("invalid slug format")
	}

	// Extract the base64 encoded part
	encoded := slug[:idx]

	// Decode
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode URL: %w", err)
	}

	return string(decoded), nil
}

// generateDeterministicGibberish creates reproducible dial-up sounds based on URL
func generateDeterministicGibberish(seed string, length int) string {
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

	// Create deterministic seed from URL hash
	hash := sha256.Sum256([]byte(seed))
	var seedInt int64
	for i := 0; i < 8; i++ {
		seedInt = (seedInt << 8) | int64(hash[i])
	}

	// Use seeded random for deterministic output
	rng := rand.New(rand.NewSource(seedInt)) // #nosec G404 - not used for security

	var result strings.Builder
	for result.Len() < length {
		sound := sounds[rng.Intn(len(sounds))]

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

package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ──────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────

const (
	tokenExpiry        = 24 * time.Hour
	authCookieName     = "myrecon_token"
	defaultUsername    = "admin"
	defaultPasswordRaw = "yy233966"
)

var (
	jwtSecret     []byte
	jwtSecretOnce sync.Once

	// Pre-hashed password; computed at init.
	adminUsername     string
	adminPasswordHash string
)

func init() {
	adminUsername = envOrDefaultAuth("AUTH_USERNAME", defaultUsername)
	raw := envOrDefaultAuth("AUTH_PASSWORD", defaultPasswordRaw)
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("[Auth] failed to hash password: %v", err)
	}
	adminPasswordHash = string(hash)
}

func envOrDefaultAuth(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getJWTSecret() []byte {
	jwtSecretOnce.Do(func() {
		if env := strings.TrimSpace(os.Getenv("JWT_SECRET")); env != "" {
			jwtSecret = []byte(env)
		} else {
			jwtSecret = make([]byte, 32)
			if _, err := rand.Read(jwtSecret); err != nil {
				log.Fatalf("[Auth] failed to generate JWT secret: %v", err)
			}
			log.Println("[Auth] generated random JWT secret (set JWT_SECRET env to persist across restarts)")
		}
	})
	return jwtSecret
}

// ──────────────────────────────────────────
// Simple JWT (HMAC-SHA256, no external deps)
// ──────────────────────────────────────────

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func signJWT(username string, duration time.Duration) (string, error) {
	secret := getJWTSecret()
	now := time.Now()

	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	claims := jwtClaims{
		Sub: username,
		Iat: now.Unix(),
		Exp: now.Add(duration).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	signature := base64URLEncode(mac.Sum(nil))

	return signingInput + "." + signature, nil
}

func verifyJWT(tokenStr string) (*jwtClaims, error) {
	secret := getJWTSecret()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(signatureBytes, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding")
	}

	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims JSON")
	}

	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// ──────────────────────────────────────────
// Login handler
// ──────────────────────────────────────────

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	Username  string `json:"username"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)

	if username == "" || password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Verify credentials
	if !strings.EqualFold(username, adminUsername) {
		log.Printf("[Auth] login failed: unknown user %q from %s", username, r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(adminPasswordHash), []byte(password)); err != nil {
		log.Printf("[Auth] login failed: bad password for %q from %s", username, r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate token
	token, err := signJWT(adminUsername, tokenExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	expiresAt := time.Now().Add(tokenExpiry)
	log.Printf("[Auth] login success: user=%s from=%s", adminUsername, r.RemoteAddr)

	writeJSON(w, http.StatusOK, loginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Username:  adminUsername,
	})
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// If we reach here, the auth middleware already verified the token.
	claims := r.Context().Value(ctxKeyClaims)
	if claims == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": true,
			"username":      "unknown",
		})
		return
	}
	c := claims.(*jwtClaims)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"username":      c.Sub,
	})
}

// ──────────────────────────────────────────
// Auth Middleware
// ──────────────────────────────────────────

type contextKey string

const ctxKeyClaims contextKey = "auth_claims"

// publicPaths are paths that do NOT require authentication.
var publicPaths = map[string]bool{
	"/api/auth/login": true,
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public paths
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for non-API paths (frontend static files)
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header or cookie
		tokenStr := extractToken(r)
		if tokenStr == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		claims, err := verifyJWT(tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractToken(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}

	// 2. Query parameter (for screenshot file serving etc.)
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return t
	}

	// 3. Cookie
	if cookie, err := r.Cookie(authCookieName); err == nil {
		return strings.TrimSpace(cookie.Value)
	}

	return ""
}

// generateRandomHex generates a random hex string (unused currently, available for CSRF etc.)
func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

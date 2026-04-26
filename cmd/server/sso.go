package main

// TOTP (RFC 6238) + OAuth2/OIDC SSO support
// TOTP: standard Google Authenticator compatible
// OAuth: Cisco ASA sso-v2 protocol for AnyConnect/OpenConnect

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ========== TOTP ==========

func generateTOTP(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	counter := uint64(math.Floor(float64(t.Unix()) / 30))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF
	return fmt.Sprintf("%06d", code%1000000)
}

func verifyTOTP(secret, code string) bool {
	now := time.Now()
	// Allow ±1 window (30s each)
	for _, delta := range []int{-1, 0, 1} {
		t := now.Add(time.Duration(delta) * 30 * time.Second)
		if generateTOTP(secret, t) == code {
			return true
		}
	}
	return false
}

// ========== OAuth2 / OIDC ==========

type OAuthConfig struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"`      // "google", "github", "generic"
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	AuthURL      string `json:"authUrl"`       // Authorization endpoint
	TokenURL     string `json:"tokenUrl"`      // Token endpoint
	UserInfoURL  string `json:"userInfoUrl"`   // UserInfo endpoint
	RedirectURL  string `json:"redirectUrl"`   // Our callback URL
	Scopes       string `json:"scopes"`        // space-separated
	AllowDomains string `json:"allowDomains"`  // comma-separated allowed email domains
}

// Pending SSO sessions: ssoToken → channel that receives username on completion
var (
	ssoSessions   sync.Map // ssoToken → *SSOSession
	oauthCfg      *OAuthConfig
)

type SSOSession struct {
	Token    string
	State    string // OAuth state parameter
	Created  time.Time
	Done     chan string // sends username when OAuth completes
	Username string     // set after OAuth callback
}

func initOAuth(cfg *OAuthConfig) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	oauthCfg = cfg
	log.Printf("OAuth/OIDC enabled: provider=%s", cfg.Provider)
}

// ssoAuthResponse returns the XML that tells AnyConnect to open a browser
func ssoAuthResponse(loginURL, finalURL, tokenCookie, errorCookie string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>VPN</tunnel-group>
<config-hash>1595829378234</config-hash>
</opaque>
<auth id="main">
<title>SSO Login</title>
<message>Please complete login in your browser</message>
<sso-v2-login>%s</sso-v2-login>
<sso-v2-login-final>%s</sso-v2-login-final>
<sso-v2-token-cookie-name>%s</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>%s</sso-v2-error-cookie-name>
</auth>
</config-auth>`, loginURL, finalURL, tokenCookie, errorCookie)
}

// handleOAuthStart initiates OAuth flow — called when client requests SSO
func handleOAuthStart(w http.ResponseWriter, r *http.Request) string {
	if oauthCfg == nil {
		return ""
	}

	// Create SSO session
	ssoToken := RandomHex(32)
	state := RandomHex(16)
	sess := &SSOSession{
		Token:   ssoToken,
		State:   state,
		Created: time.Now(),
		Done:    make(chan string, 1),
	}
	ssoSessions.Store(ssoToken, sess)
	ssoSessions.Store("state:"+state, sess) // also index by state

	// Build OAuth authorization URL
	scopes := oauthCfg.Scopes
	if scopes == "" {
		scopes = "openid email profile"
	}
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		oauthCfg.AuthURL,
		url.QueryEscape(oauthCfg.ClientID),
		url.QueryEscape(oauthCfg.RedirectURL),
		url.QueryEscape(scopes),
		state,
	)

	// The "final" URL is where the client polls for completion
	baseURL := oauthCfg.RedirectURL
	if idx := strings.LastIndex(baseURL, "/"); idx > 0 {
		baseURL = baseURL[:idx]
	}
	finalURL := baseURL + "/sso/wait?token=" + ssoToken

	return ssoAuthResponse(authURL, finalURL, "sso-token", "sso-error")
}

// handleOAuthCallback processes the OAuth provider's redirect
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", 400)
		return
	}

	// Find session by state
	val, ok := ssoSessions.Load("state:" + state)
	if !ok {
		http.Error(w, "invalid state", 400)
		return
	}
	sess := val.(*SSOSession)

	// Exchange code for token
	tokenResp, err := exchangeCode(code)
	if err != nil {
		log.Printf("OAuth token exchange: %v", err)
		http.Error(w, "token exchange failed", 500)
		return
	}

	// Get user info
	username, err := getUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Printf("OAuth userinfo: %v", err)
		http.Error(w, "userinfo failed", 500)
		return
	}

	// Check allowed domains
	if oauthCfg.AllowDomains != "" {
		allowed := false
		for _, d := range strings.Split(oauthCfg.AllowDomains, ",") {
			if strings.HasSuffix(username, "@"+strings.TrimSpace(d)) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("OAuth: domain not allowed for %s", username)
			http.Error(w, "domain not allowed", 403)
			return
		}
	}

	sess.Username = username
	sess.Done <- username
	AuditLog(username, "oauth_login", r.RemoteAddr, "provider="+oauthCfg.Provider)

	// Show success page (browser closes itself or user closes it)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body><h2>Login successful</h2><p>Welcome %s. You may close this window.</p>
<script>window.close()</script></body></html>`, username)
}

// handleSSOWait is polled by the VPN client waiting for OAuth completion
func handleSSOWait(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	val, ok := ssoSessions.Load(token)
	if !ok {
		http.Error(w, "invalid token", 400)
		return
	}
	sess := val.(*SSOSession)

	// Wait up to 30 seconds for OAuth to complete
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	select {
	case username := <-sess.Done:
		// OAuth completed! Return session cookie
		sessionToken := RandomHex(32)
		sessionsMu.Lock()
		sessions[sessionToken] = &Session{Token: sessionToken, Created: time.Now()}
		sessionsMu.Unlock()
		tokenUserMap.Store(sessionToken, username)

		// Set cookie for the VPN client
		http.SetCookie(w, &http.Cookie{
			Name:  "sso-token",
			Value: sessionToken,
			Path:  "/",
		})
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>%s</session-token>
<auth id="success">
<banner>Welcome %s</banner>
</auth>
</config-auth>`, sessionToken, username)

		// Cleanup
		ssoSessions.Delete(token)
		ssoSessions.Delete("state:" + sess.State)

	case <-ctx.Done():
		w.WriteHeader(408)
		fmt.Fprint(w, "timeout")
	}
}

// OAuth token exchange
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

func exchangeCode(code string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthCfg.RedirectURL},
		"client_id":     {oauthCfg.ClientID},
		"client_secret": {oauthCfg.ClientSecret},
	}

	resp, err := http.PostForm(oauthCfg.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token: %w (body: %s)", err, body[:min(200, len(body))])
	}
	return &tr, nil
}

func getUserInfo(accessToken string) (string, error) {
	req, _ := http.NewRequest("GET", oauthCfg.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var info map[string]interface{}
	json.Unmarshal(body, &info)

	// Try email first, then login/username
	if email, ok := info["email"].(string); ok && email != "" {
		return email, nil
	}
	if login, ok := info["login"].(string); ok && login != "" {
		return login, nil
	}
	if name, ok := info["preferred_username"].(string); ok && name != "" {
		return name, nil
	}
	return "", fmt.Errorf("no username in userinfo: %v", info)
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

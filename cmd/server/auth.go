package main

// Multi-user auth with groups
// Config file: users.json
// Format:
// {
//   "groups": {
//     "default": { "routes": ["10.99.0.0/24"], "dns": "8.8.8.8" },
//     "admin":   { "routes": ["0.0.0.0/0"], "dns": "1.1.1.1" }
//   },
//   "users": {
//     "alice": { "password": "pass1", "group": "admin", "otp_secret": "" },
//     "bob":   { "password": "pass2", "group": "default" }
//   }
// }

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

type UserConfig struct {
	Groups map[string]*GroupConfig `json:"groups"`
	Users  map[string]*UserEntry  `json:"users"`
}

type GroupConfig struct {
	Routes    []string `json:"routes"`    // split-include routes
	DNS       string   `json:"dns"`       // DNS to push
	Banner    string   `json:"banner"`    // login banner
	MaxOnline int      `json:"maxOnline"` // max concurrent sessions (0=unlimited)
}

type UserEntry struct {
	Password  string `json:"password"`
	Group     string `json:"group"`
	OTPSecret string `json:"otp_secret,omitempty"` // TOTP secret (future)
	Disabled  bool   `json:"disabled,omitempty"`
}

var (
	userConfig   *UserConfig
	userConfigMu sync.RWMutex
)

func loadUsers(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var uc UserConfig
	if err := json.Unmarshal(data, &uc); err != nil {
		return err
	}
	userConfigMu.Lock()
	userConfig = &uc
	userConfigMu.Unlock()
	log.Printf("Loaded %d users, %d groups from %s", len(uc.Users), len(uc.Groups), path)
	return nil
}

// AuthResult contains the result of user authentication
type AuthResult struct {
	OK        bool
	Username  string
	Group     *GroupConfig
	NeedOTP   bool   // requires second factor
	OTPSecret string // for verification
}

// authenticateUser checks username/password against config
// Falls back to single-password mode if no users.json loaded
func authenticateUser(username, password string) AuthResult {
	// Try DB first
	if db != nil {
		return dbAuthenticateUser(username, password)
	}

	userConfigMu.RLock()
	uc := userConfig
	userConfigMu.RUnlock()

	if uc == nil {
		// Single-password mode (backwards compatible)
		if password == cfg.Password {
			return AuthResult{OK: true, Username: username, Group: &GroupConfig{
				Routes: []string{cfg.Pool},
				DNS:    cfg.DNS,
			}}
		}
		return AuthResult{OK: false}
	}

	user, ok := uc.Users[username]
	if !ok || user.Disabled {
		return AuthResult{OK: false}
	}
	if user.Password != password {
		return AuthResult{OK: false}
	}

	group := uc.Groups[user.Group]
	if group == nil {
		group = &GroupConfig{Routes: []string{cfg.Pool}, DNS: cfg.DNS}
	}

	return AuthResult{OK: true, Username: username, Group: group, NeedOTP: user.OTPSecret != "", OTPSecret: user.OTPSecret}
}

// getGroupNames returns available group names for the login form
func getGroupNames() []string {
	userConfigMu.RLock()
	uc := userConfig
	userConfigMu.RUnlock()

	if uc == nil {
		return []string{"default"}
	}
	names := make([]string, 0, len(uc.Groups))
	for k := range uc.Groups {
		names = append(names, k)
	}
	return names
}

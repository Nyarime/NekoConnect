package main

// Lightweight SQLite-compatible database using pure Go
// Uses modernc.org/sqlite (no CGO required)
// Stores: users, groups, sessions, audit log, settings

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	// WAL mode for better concurrency
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			password TEXT NOT NULL,
			grp TEXT DEFAULT 'default',
			otp_secret TEXT DEFAULT '',
			disabled INTEGER DEFAULT 0,
			created_at TEXT DEFAULT (datetime('now')),
			last_login TEXT
		);

		CREATE TABLE IF NOT EXISTS groups (
			name TEXT PRIMARY KEY,
			routes TEXT DEFAULT '',
			dns TEXT DEFAULT '8.8.8.8',
			banner TEXT DEFAULT '',
			max_online INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT DEFAULT (datetime('now')),
			username TEXT,
			action TEXT,
			remote_ip TEXT,
			detail TEXT
		);

		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
		CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username);
	`)
	if err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	// Ensure default group exists
	db.Exec("INSERT OR IGNORE INTO groups (name, routes, dns) VALUES ('default', '10.0.0.0/8', '8.8.8.8')")

	log.Printf("Database: %s", path)
	return nil
}

// DB-backed user authentication (alternative to JSON file)
func dbAuthenticateUser(username, password string) AuthResult {
	if db == nil {
		return AuthResult{OK: false}
	}

	var pwd, grp, otpSecret string
	var disabled int
	err := db.QueryRow(
		"SELECT password, grp, otp_secret, disabled FROM users WHERE username = ?",
		username,
	).Scan(&pwd, &grp, &otpSecret, &disabled)

	if err != nil || disabled == 1 {
		return AuthResult{OK: false}
	}

	// TODO: bcrypt comparison for production
	if pwd != password {
		return AuthResult{OK: false}
	}

	// Update last login
	db.Exec("UPDATE users SET last_login = datetime('now') WHERE username = ?", username)

	// Fetch group config
	var routes, dns, banner string
	var maxOnline int
	err = db.QueryRow("SELECT routes, dns, banner, max_online FROM groups WHERE name = ?", grp).
		Scan(&routes, &dns, &banner, &maxOnline)
	if err != nil {
		routes = "10.0.0.0/8"
		dns = "8.8.8.8"
	}

	return AuthResult{
		OK:       true,
		Username: username,
		Group: &GroupConfig{
			Routes: []string{routes},
			DNS:    dns,
			Banner: banner,
			MaxOnline: maxOnline,
		},
		NeedOTP:   otpSecret != "",
		OTPSecret: otpSecret,
	}
}

// DB audit logging
func dbAuditLog(username, action, remoteIP, detail string) {
	if db == nil {
		return
	}
	db.Exec(
		"INSERT INTO audit_log (username, action, remote_ip, detail) VALUES (?, ?, ?, ?)",
		username, action, remoteIP, detail,
	)
}

// DB user management
func dbAddUser(username, password, group string) error {
	_, err := db.Exec(
		"INSERT INTO users (username, password, grp) VALUES (?, ?, ?)",
		username, password, group,
	)
	return err
}

func dbDelUser(username string) error {
	_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

func dbListUsers() ([]map[string]interface{}, error) {
	rows, err := db.Query("SELECT username, grp, disabled, otp_secret != '' as has_otp, created_at, last_login FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var username, grp, createdAt string
		var disabled, hasOTP int
		var lastLogin sql.NullString
		rows.Scan(&username, &grp, &disabled, &hasOTP, &createdAt, &lastLogin)
		users = append(users, map[string]interface{}{
			"username":  username,
			"group":     grp,
			"disabled":  disabled == 1,
			"hasOTP":    hasOTP == 1,
			"createdAt": createdAt,
			"lastLogin": lastLogin.String,
		})
	}
	return users, nil
}

func dbGetAuditLog(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.Query("SELECT ts, username, action, remote_ip, detail FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]interface{}
	for rows.Next() {
		var ts, username, action, remoteIP, detail string
		rows.Scan(&ts, &username, &action, &remoteIP, &detail)
		entries = append(entries, map[string]interface{}{
			"time":     ts,
			"username": username,
			"action":   action,
			"remoteIP": remoteIP,
			"detail":   detail,
		})
	}
	return entries, nil
}

// Cleanup old audit entries (keep last 30 days)
func dbCleanupAudit() {
	if db == nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -30).Format("2006-01-02 15:04:05")
	result, _ := db.Exec("DELETE FROM audit_log WHERE ts < ?", cutoff)
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("Cleaned %d old audit entries", n)
	}
}

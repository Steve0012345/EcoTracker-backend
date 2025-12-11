package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"sort"
	"context"
)

/* =========================
   Config
   ========================= */

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTTTLHours int
}

func loadConfig() Config {
	_ = godotenv.Load()
	port := getenv("PORT", "8080")
	db := getenv("DATABASE_URL", "")
	secret := getenv("JWT_SECRET", "")
	if db == "" || secret == "" {
		log.Fatal("DATABASE_URL and JWT_SECRET are required")
	}
	ttl, _ := strconv.Atoi(getenv("JWT_TTL_HOURS", "24"))
	return Config{Port: port, DatabaseURL: db, JWTSecret: secret, JWTTTLHours: ttl}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

/* =========================
   Models
   ========================= */

type BaseRole string

const (
	RoleStudent BaseRole = "student"
	RoleFaculty BaseRole = "faculty"
	RoleStaff   BaseRole = "staff"
)

type User struct {
	ID           string   `gorm:"type:text;primaryKey"`
	Email        string   `gorm:"uniqueIndex;not null"`
	Username     string   `gorm:"not null"`
	BaseRole     BaseRole `gorm:"type:text;not null"`
	IsAdmin      bool     `gorm:"not null;default:false"`
	PasswordHash string   `gorm:"not null"`

	YearIndex   int        `gorm:"not null;default:1"` // 1..4
	IsAlumni    bool       `gorm:"not null;default:false"`
	GraduatedAt *time.Time
	LastAY      int        `gorm:"not null;default:0"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

type Event struct {
	ID          string    `gorm:"type:text;primaryKey"`
	Title       string    `gorm:"not null"`
	Description string
	StartsAt    time.Time `gorm:"not null"`
	EndsAt      time.Time `gorm:"not null"`
	Location    string
	Points      int       `gorm:"not null"`
	Category    string
	CreatedBy   string    `gorm:"not null"` // user id
	QRSecret    string    `gorm:"not null"` // per-event HMAC key
	CreatedAt   time.Time
}

type PointsLedger struct {
	ID          string    `gorm:"type:text;primaryKey"`
	UserID      string    `gorm:"index;not null"`
	EventID     string    `gorm:"index;not null"`
	DeltaPoints int       `gorm:"not null"`
	Reason      string    `gorm:"not null"` // e.g., EVENT_ATTENDANCE
	OccurredAt  time.Time `gorm:"not null"`
	AdminID *string `gorm:"index"` // which admin performed the action (optional)
	Note    string  `gorm:"type:text"` // free-text reason/comment	
}

type Badge struct {
	ID          string    `gorm:"type:text;primaryKey"`
	Code        string    `gorm:"uniqueIndex;not null"`
	Name        string    `gorm:"not null"`
	Description string    `gorm:"not null"`
	Threshold   int       `gorm:"not null"`
	YearIndex   int       `gorm:"not null"` // 1..4
	IconPath    string    `gorm:"not null"` // e.g., "/assets/badges/y1_50.svg"
	CreatedAt   time.Time
}

type UserBadge struct {
	ID        string    `gorm:"type:text;primaryKey"`
	UserID    string    `gorm:"index;not null"`
	BadgeID   string    `gorm:"index;not null"`
	AwardedAt time.Time `gorm:"not null"`
}

// NEW: stores overflow (beyond cap) without affecting counted points
type BonusLedger struct {
	ID          string    `gorm:"type:text;primaryKey"`
	UserID      string    `gorm:"index;not null"`
	EventID     string    `gorm:"index;not null"`
	BonusPoints int       `gorm:"not null"`         // overflow beyond cap
	Reason      string    `gorm:"not null"`         // e.g., OVERFLOW_EVENT
	OccurredAt  time.Time `gorm:"not null"`
	AdminID *string `gorm:"index"`
	Note    string  `gorm:"type:text"`
}

type EventUpdateLog struct {
  ID        string    `gorm:"type:text;primaryKey"`
  EventID   string    `gorm:"index;not null"`
  AdminID   string    `gorm:"index;not null"`
  Changes   string    `gorm:"type:text;not null"` // JSON diff summary
  CreatedAt time.Time `gorm:"not null"`
}
// ensure AutoMigrate(&EventUpdateLog{}) is called in openDB


/* =========================
   DB
   ========================= */

func openDB(dsn string) *gorm.DB {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &Event{}, &PointsLedger{}, &Badge{}, &UserBadge{}, &BonusLedger{}, &EventUpdateLog{}); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_user_event ON points_ledgers (user_id, event_id);`)
	// prevent duplicate bonus entries for the same event too
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS ux_bonus_user_event ON bonus_ledgers (user_id, event_id);`)
	db.Exec(`CREATE INDEX IF NOT EXISTS ix_bonus_user_time ON bonus_ledgers (user_id, occurred_at);`)

	// Seed default badges with icons (idempotent)
	seedBadges := []Badge{
		// Starter at 0 pts (Year 1)
		{Code: "Y1_0_EXPLORER", Name: "Eco Explorer", Description: "Welcome to Year 1 — start your sustainability journey", Threshold: 0, YearIndex: 1, IconPath: "/assets/badges/y1_explorer.svg"},
		// Milestones by year
		{Code: "Y1_50", Name: "Year 1 — Starter", Description: "Hit 50 points in Year 1", Threshold: 50, YearIndex: 1, IconPath: "/assets/badges/y1_50.svg"},
		{Code: "Y2_100", Name: "Year 2 — Builder", Description: "Hit 100 points in Year 2", Threshold: 100, YearIndex: 2, IconPath: "/assets/badges/y2_100.svg"},
		{Code: "Y3_150", Name: "Year 3 — Driver", Description: "Hit 150 points in Year 3", Threshold: 150, YearIndex: 3, IconPath: "/assets/badges/y3_150.svg"},
		{Code: "Y4_200", Name: "Year 4 — Champion", Description: "Hit 200 points in Year 4", Threshold: 200, YearIndex: 4, IconPath: "/assets/badges/y4_200.svg"},
	}
	for _, b := range seedBadges {
		var count int64
		db.Model(&Badge{}).Where("code = ?", b.Code).Count(&count)
		if count == 0 {
			b.ID = uuid.NewString()
			b.CreatedAt = time.Now()
			db.Create(&b)
		}
	}
	return db
}

/* =========================
   Auth / JWT
   ========================= */

var ErrDomain = errors.New("email must end with cmu.edu")

func validateDomain(email string) error {
	e := strings.ToLower(strings.TrimSpace(email))
	if !strings.HasSuffix(e, "cmu.edu") {
		return ErrDomain
	}
	return nil
}

type Claims struct {
	UID      string `json:"uid"`
	Email    string `json:"email"`
	BaseRole string `json:"base_role"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func makeJWT(uid, email, baseRole string, isAdmin bool, secret string, ttl time.Duration) (string, error) {
	c := &Claims{
		UID: uid, Email: email, BaseRole: baseRole, IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString([]byte(secret))
}

func authRequired(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if h == "" || !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer"})
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")
		token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("claims", claims)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad claims"})
	}
}

func getClaims(c *gin.Context) (jwt.MapClaims, bool) {
	v, ok := c.Get("claims")
	if !ok {
		return nil, false
	}
	switch cl := v.(type) {
	case jwt.MapClaims:
		return cl, true
	case map[string]interface{}:
		return jwt.MapClaims(cl), true
	default:
		return nil, false
	}
}

func adminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		isAdmin, _ := claims["is_admin"].(bool)
		if !isAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin only"})
			return
		}
		c.Next()
	}
}

/* =========================
   Year Caps / Alumni
   ========================= */

var YearCaps = map[int]int{1: 50, 2: 100, 3: 150, 4: 200}
const AlumniCap = 0
const AYStartMonth = time.August
const AYStartDay = 1

func academicYearWindow(now time.Time) (start, end time.Time) {
	y := now.Year()
	start = time.Date(y, AYStartMonth, AYStartDay, 0, 0, 0, 0, now.Location())
	if now.Before(start) {
		start = time.Date(y-1, AYStartMonth, AYStartDay, 0, 0, 0, 0, now.Location())
	}
	end = start.AddDate(1, 0, 0)
	return
}

func academicYearLabel(now time.Time) int {
	y := now.Year()
	start := time.Date(y, AYStartMonth, AYStartDay, 0, 0, 0, 0, now.Location())
	if now.Before(start) {
		return y - 1
	}
	return y
}

func maybeRolloverUserYear(db *gorm.DB, u *User, now time.Time) error {
    ay := academicYearLabel(now)

    // New users (LastAY = 0): set to current year, no rollover
    if u.LastAY == 0 {
        u.LastAY = ay
        return db.Save(u).Error
    }

    if u.LastAY >= ay {
        return nil // already up to date
    }

    if u.IsAlumni {
        u.LastAY = ay
        return db.Save(u).Error
    }

    // Roll to next year if still active
    if u.YearIndex < 4 {
        u.YearIndex++
    } else {
        u.IsAlumni = true
        if u.GraduatedAt == nil {
            t := now
            u.GraduatedAt = &t
        }
    }

    u.LastAY = ay
    return db.Save(u).Error
}


/* =========================
   HMAC / QR helpers
   ========================= */

func randBase64(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(payloadB64, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payloadB64))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

/* =========================
   Handlers: Auth
   ========================= */

type RegisterReq struct {
	Email    string   `json:"email"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	BaseRole BaseRole `json:"base_role"`
	IsAdmin  bool     `json:"is_admin"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}



func registerHandler(db *gorm.DB, cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}
		if err := validateDomain(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Username == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username/password required"})
			return
		}
		if req.BaseRole != RoleStudent && req.BaseRole != RoleFaculty && req.BaseRole != RoleStaff {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base_role"})
			return
		}

		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		u := User{
			ID:           uuid.NewString(),
			Email:        strings.ToLower(strings.TrimSpace(req.Email)),
			Username:     req.Username,
			BaseRole:     req.BaseRole,
			IsAdmin:      false,
			PasswordHash: string(hash),
		}
		if err := db.Create(&u).Error; err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}

		// Award starter badge immediately (Year 1, 0 pts)
		ensureStarterBadge(db, u.ID, 1)

		token, err := makeJWT(u.ID, u.Email, string(u.BaseRole), u.IsAdmin, cfg.JWTSecret, time.Hour*time.Duration(cfg.JWTTTLHours))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"access_token": token})
	}
}

type AdminRegisterReq struct {
	InviteToken string   `json:"invite_token"` // must match env
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	BaseRole    BaseRole `json:"base_role"` // student/faculty/staff
  }
  
  func adminRegisterHandler(db *gorm.DB, cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
	  var req AdminRegisterReq
	  if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":"bad json"}); return
	  }
	  if req.InviteToken == "" || req.InviteToken != os.Getenv("ADMIN_INVITE_TOKEN") {
		c.JSON(http.StatusForbidden, gin.H{"error":"invalid invite token"}); return
	  }
	  if err := validateDomain(req.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	  }
	  if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error":"username/password required"}); return
	  }
	  if req.BaseRole != RoleStudent && req.BaseRole != RoleFaculty && req.BaseRole != RoleStaff {
		c.JSON(http.StatusBadRequest, gin.H{"error":"invalid base_role"}); return
	  }
  
	  // if there are zero admins, allow bootstrap without token check
	  var adminCount int64; db.Model(&User{}).Where("is_admin = ?", true).Count(&adminCount)
  
	  hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	  u := User{
		ID: uuid.NewString(),
		Email: strings.ToLower(strings.TrimSpace(req.Email)),
		Username: req.Username,
		BaseRole: req.BaseRole,
		IsAdmin: true,
		PasswordHash: string(hash),
	  }
	  if err := db.Create(&u).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error":"email already registered"}); return
	  }
  
	  ensureStarterBadge(db, u.ID, 1)
	  token, err := makeJWT(u.ID, u.Email, string(u.BaseRole), u.IsAdmin, cfg.JWTSecret, time.Hour*time.Duration(cfg.JWTTTLHours))
	  if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error":"token error"}); return }
	  c.JSON(http.StatusCreated, gin.H{"access_token": token})
	}
  }
  

func loginHandler(db *gorm.DB, cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}
		if err := validateDomain(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var u User
		if err := db.Where("email = ?", strings.ToLower(strings.TrimSpace(req.Email))).First(&u).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		// Auto-roll to next AY (up to Y4; then alumni)
		_ = maybeRolloverUserYear(db, &u, time.Now())

		// Ensure the starter badge for current year (covers Y1 = 0 pts case)
		ensureStarterBadge(db, u.ID, u.YearIndex)

		token, err := makeJWT(u.ID, u.Email, string(u.BaseRole), u.IsAdmin, cfg.JWTSecret, time.Hour*time.Duration(cfg.JWTTTLHours))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"access_token": token})
	}
}

/* =========================
   Helpers: Totals & Badges
   ========================= */

func sumYearPoints(db *gorm.DB, userID string, start, end time.Time) (int, error) {
	var total int64
	err := db.Model(&PointsLedger{}).
		Where("user_id = ? AND occurred_at >= ? AND occurred_at < ?", userID, start, end).
		Select("COALESCE(SUM(delta_points),0)").
		Scan(&total).Error
	return int(total), err
}

// NEW: sum overflow bonus in an AY
func sumYearBonus(db *gorm.DB, userID string, start, end time.Time) (int, error) {
	var total int64
	err := db.Model(&BonusLedger{}).
		Where("user_id = ? AND occurred_at >= ? AND occurred_at < ?", userID, start, end).
		Select("COALESCE(SUM(bonus_points),0)").
		Scan(&total).Error
	return int(total), err
}

func maybeAwardBadge(db *gorm.DB, userID string, yearIdx, totalThisYear int) (*Badge, bool, error) {
	var b Badge
	if err := db.Where("year_index = ? AND threshold <= ?", yearIdx, totalThisYear).
		Order("threshold desc").First(&b).Error; err != nil {
		return nil, false, nil // no badge at/under threshold
	}
	var ub UserBadge
	if err := db.Where("user_id = ? AND badge_id = ?", userID, b.ID).First(&ub).Error; err == nil {
		return &b, false, nil
	}
	award := UserBadge{
		ID: uuid.NewString(), UserID: userID, BadgeID: b.ID, AwardedAt: time.Now(),
	}
	if err := db.Create(&award).Error; err != nil {
		return nil, false, err
	}
	return &b, true, nil
}

// Ensure starter badge (threshold 0 for current year)
func ensureStarterBadge(db *gorm.DB, userID string, yearIdx int) {
	start, end := academicYearWindow(time.Now())
	total, err := sumYearPoints(db, userID, start, end)
	if err != nil {
		return
	}
	_, _, _ = maybeAwardBadge(db, userID, yearIdx, total)
}

/* =========================
   Handlers: Me / Badges / Ledger / Bonus
   ========================= */

func meHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		userID := fmt.Sprint(claims["uid"])

		var user User
		if err := db.First(&user, "id = ?", userID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}
		start, end := academicYearWindow(time.Now())
		total, _ := sumYearPoints(db, userID, start, end)
		bonusYear, _ := sumYearBonus(db, userID, start, end)

		cap := YearCaps[user.YearIndex]
		if user.IsAlumni {
			cap = AlumniCap
		}

		// Next milestone hint
		nextThreshold := cap
		switch user.YearIndex {
		case 1:
			nextThreshold = 50
		case 2:
			nextThreshold = 100
		case 3:
			nextThreshold = 150
		case 4:
			nextThreshold = 200
		}
		pointsToNext := nextThreshold - total
		if pointsToNext < 0 {
			pointsToNext = 0
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":      claims["uid"],
			"email":        claims["email"],
			"base_role":    claims["base_role"],
			"is_admin":     claims["is_admin"],
			"year_index":   user.YearIndex,
			"is_alumni":    user.IsAlumni,
			"graduated_at": user.GraduatedAt,
			"totals": gin.H{
				"year_points":    total,
				"bonus_year":     bonusYear,   // NEW
				"cap":            cap,
				"next_threshold": nextThreshold,
				"points_to_next": pointsToNext,
			},
		})
	}
}

func listBadgesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var bs []Badge
		if err := db.Order("year_index asc, threshold asc").Find(&bs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusOK, bs)
	}
}

func myBadgesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		userID := fmt.Sprint(claims["uid"])
		var res []struct {
			Code        string    `json:"code"`
			Name        string    `json:"name"`
			Description string    `json:"description"`
			YearIndex   int       `json:"year_index"`
			AwardedAt   time.Time `json:"awarded_at"`
			IconPath    string    `json:"icon_path"`
		}
		err := db.Table("user_badges ub").
			Select("b.code, b.name, b.description, b.year_index, ub.awarded_at, b.icon_path").
			Joins("JOIN badges b ON b.id = ub.badge_id").
			Where("ub.user_id = ?", userID).
			Order("ub.awarded_at asc").
			Scan(&res).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusOK, res)
	}
}

func myLedgerHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		userID := fmt.Sprint(claims["uid"])
		var rows []PointsLedger
		if err := db.Where("user_id = ?", userID).Order("occurred_at desc").Limit(100).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusOK, rows)
	}
}

// NEW: list bonus entries
func myBonusHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		userID := fmt.Sprint(claims["uid"])
		var rows []BonusLedger
		if err := db.Where("user_id = ?", userID).Order("occurred_at desc").Limit(100).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusOK, rows)
	}
}

// ========== Admin: Dashboard stats ==========
func adminStatsHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    now := time.Now()
    // start of "today" in local server tz
    startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

    // counts
    var usersTotal int64
    if err := db.Model(&User{}).Count(&usersTotal).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    var eventsTotal int64
    if err := db.Model(&Event{}).Count(&eventsTotal).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    var eventsUpcoming int64
    if err := db.Model(&Event{}).Where("ends_at > ?", now).Count(&eventsUpcoming).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    // “check-ins today” = number of counted ledger rows written today
    var checkinsToday int64
    if err := db.Model(&PointsLedger{}).Where("occurred_at >= ?", startOfDay).Count(&checkinsToday).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    // points awarded today (counted)
    var pointsToday int64
    if err := db.Model(&PointsLedger{}).
      Where("occurred_at >= ?", startOfDay).
      Select("COALESCE(SUM(delta_points),0)").
      Scan(&pointsToday).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    // overflow/bonus today (optional but handy)
    var bonusToday int64
    if err := db.Model(&BonusLedger{}).
      Where("occurred_at >= ?", startOfDay).
      Select("COALESCE(SUM(bonus_points),0)").
      Scan(&bonusToday).Error; err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return
    }

    c.JSON(http.StatusOK, gin.H{
      "users":                 usersTotal,
      "events_total":          eventsTotal,
      "events_upcoming":       eventsUpcoming,
      "checkins_today":        checkinsToday,
      "points_awarded_today":  pointsToday,
      "bonus_awarded_today":   bonusToday,
    })
  }
}


/* =========================
   Handlers: Events / QR
   ========================= */

type CreateEventReq struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	StartsAtISO string `json:"starts_at"` // RFC3339
	EndsAtISO   string `json:"ends_at"`
	Location    string `json:"location"`
	Points      int    `json:"points"`
	Category    string `json:"category"`
}

type UpdateEventReq struct {
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	StartsAtISO *string `json:"starts_at,omitempty"` // RFC3339
	EndsAtISO   *string `json:"ends_at,omitempty"`
	Location    *string `json:"location,omitempty"`
	Points      *int    `json:"points,omitempty"`
	Category    *string `json:"category,omitempty"`

	// Optional: rotate the per-event QR signing key so old QR codes become invalid
	RotateQR *bool `json:"rotate_qr,omitempty"`
}

type AdminManualAttendReq struct {
	// Identify user by email (cmu.edu) or user_id; email is easiest in the panel
	User           string  `json:"user"` // email or user_id
	Points         *int    `json:"points,omitempty"` // default: event.Points
	ForceBucket    string  `json:"force_bucket,omitempty"` // "", "auto" (default), "counted", "bonus"
	PreventDuplicate bool  `json:"prevent_duplicate,omitempty"` // if true, block if any row exists for (user,event)
	AllowOverCap   bool    `json:"allow_over_cap,omitempty"` // only used when forcing "counted"
	OccurredAtISO  *string `json:"occurred_at,omitempty"` // optional RFC3339; default now
	Note           string  `json:"note,omitempty"` // audit trail (e.g., "scanner failed at door")
}

func findUserByIdentifier(db *gorm.DB, v string) (*User, error) {
	// If it looks like a UUID, try ID first; otherwise treat as email.
	var u User
	if strings.Contains(v, "@") {
		if err := db.Where("email = ?", strings.ToLower(strings.TrimSpace(v))).First(&u).Error; err != nil {
			return nil, err
		}
		return &u, nil
	}
	if err := db.First(&u, "id = ?", v).Error; err == nil {
		return &u, nil
	}
	// fallback: try as email too
	if err := db.Where("email = ?", strings.ToLower(strings.TrimSpace(v))).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}



// core function that actually inserts into PointsLedger / BonusLedger
func applyManualAttend(
	db *gorm.DB,
	adminID string,
	ev *Event,
	u *User,
	req AdminManualAttendReq,
) (awarded int, overflow int, when time.Time, err error) {

	if u.IsAlumni {
		return 0, 0, time.Time{}, fmt.Errorf("alumni_do_not_accrue_points")
	}

	// points to apply
	p := ev.Points
	if req.Points != nil {
		if *req.Points <= 0 {
			return 0, 0, time.Time{}, fmt.Errorf("points must be > 0")
		}
		p = *req.Points
	}

	// occurred_at
	now := time.Now()
	when = now
	if req.OccurredAtISO != nil {
		t, errParse := time.Parse(time.RFC3339, *req.OccurredAtISO)
		if errParse != nil {
			return 0, 0, time.Time{}, fmt.Errorf("invalid occurred_at (RFC3339)")
		}
		when = t
	}

	// duplicates?
	if req.PreventDuplicate {
		var cnt int64
		db.Model(&PointsLedger{}).
			Where("user_id = ? AND event_id = ?", u.ID, ev.ID).
			Count(&cnt)
		if cnt == 0 {
			db.Model(&BonusLedger{}).
				Where("user_id = ? AND event_id = ?", u.ID, ev.ID).
				Count(&cnt)
		}
		if cnt > 0 {
			return 0, 0, when, fmt.Errorf("duplicate detected for user/event")
		}
	}

	// bucket selection
	force := strings.ToLower(strings.TrimSpace(req.ForceBucket))
	if force == "" {
		force = "auto"
	}

	// cap logic
	start, end := academicYearWindow(when)
	current, errSum := sumYearPoints(db, u.ID, start, end)
	if errSum != nil {
		return 0, 0, when, fmt.Errorf("sum error: %w", errSum)
	}

	yrCap, ok := YearCaps[u.YearIndex]
	if !ok {
		yrCap = 0
	}

	writeCounted := func(amount int) error {
		if amount <= 0 {
			return nil
		}
		entry := PointsLedger{
			ID:          uuid.NewString(),
			UserID:      u.ID,
			EventID:     ev.ID,
			DeltaPoints: amount,
			Reason:      "ADMIN_MANUAL_ATTEND",
			OccurredAt:  when,
			AdminID:     &adminID,
			Note:        req.Note,
		}
		return db.Create(&entry).Error
	}
	writeBonus := func(amount int) error {
		if amount <= 0 {
			return nil
		}
		entry := BonusLedger{
			ID:          uuid.NewString(),
			UserID:      u.ID,
			EventID:     ev.ID,
			BonusPoints: amount,
			Reason:      "ADMIN_MANUAL_ATTEND",
			OccurredAt:  when,
			AdminID:     &adminID,
			Note:        req.Note,
		}
		return db.Create(&entry).Error
	}

	awarded, overflow = 0, 0

	switch force {
	case "bonus":
		overflow = p
		if err := writeBonus(overflow); err != nil {
			return 0, 0, when, fmt.Errorf("bonus insert error: %w", err)
		}
	case "counted":
		if req.AllowOverCap {
			awarded = p
			if err := writeCounted(awarded); err != nil {
				return 0, 0, when, fmt.Errorf("insert error: %w", err)
			}
		} else {
			remaining := yrCap - current
			if remaining <= 0 {
				overflow = p
				if err := writeBonus(overflow); err != nil {
					return 0, 0, when, fmt.Errorf("bonus insert error: %w", err)
				}
			} else if p > remaining {
				awarded = remaining
				overflow = p - remaining
				if err := writeCounted(awarded); err != nil {
					return 0, 0, when, fmt.Errorf("insert error: %w", err)
				}
				if err := writeBonus(overflow); err != nil {
					return 0, 0, when, fmt.Errorf("bonus insert error: %w", err)
				}
			} else {
				awarded = p
				if err := writeCounted(awarded); err != nil {
					return 0, 0, when, fmt.Errorf("insert error: %w", err)
				}
			}
		}
	default: // "auto"
		remaining := yrCap - current
		if remaining <= 0 {
			overflow = p
			if err := writeBonus(overflow); err != nil {
				return 0, 0, when, fmt.Errorf("bonus insert error: %w", err)
			}
		} else if p > remaining {
			awarded = remaining
			overflow = p - remaining
			if err := writeCounted(awarded); err != nil {
				return 0, 0, when, fmt.Errorf("insert error: %w", err)
			}
			if err := writeBonus(overflow); err != nil {
				return 0, 0, when, fmt.Errorf("bonus insert error: %w", err)
			}
		} else {
			awarded = p
			if err := writeCounted(awarded); err != nil {
				return 0, 0, when, fmt.Errorf("insert error: %w", err)
			}
		}
	}

	return awarded, overflow, when, nil
}

func adminManualAttendHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// which admin?
		claims, ok := getClaims(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		adminID := fmt.Sprint(claims["uid"])

		eid := c.Param("id")
		var ev Event
		if err := db.First(&ev, "id = ?", eid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		var req AdminManualAttendReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}
		if strings.TrimSpace(req.User) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user is required"})
			return
		}

		u, err := findUserByIdentifier(db, req.User)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}

		awarded, overflow, when, err := applyManualAttend(db, adminID, &ev, u, req)
		if err != nil {
			// map some known strings to nicer HTTP codes
			switch {
			case strings.Contains(err.Error(), "alumni_do_not_accrue_points"):
				c.JSON(http.StatusBadRequest, gin.H{"error": "alumni_do_not_accrue_points"})
			case strings.Contains(err.Error(), "duplicate detected"):
				c.JSON(http.StatusConflict, gin.H{"error": "duplicate detected for user/event"})
			case strings.Contains(err.Error(), "invalid occurred_at"):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid occurred_at (RFC3339)"})
			case strings.Contains(err.Error(), "points must be > 0"):
				c.JSON(http.StatusBadRequest, gin.H{"error": "points must be > 0"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":        u.ID,
			"event_id":       ev.ID,
			"awarded":        awarded,
			"overflow_bonus": overflow,
			"force_bucket":   strings.ToLower(strings.TrimSpace(req.ForceBucket)),
			"allow_over_cap": req.AllowOverCap,
			"note":           req.Note,
			"occurred_at":    when,
		})
	}
}

type BulkAttendReq struct {
	Emails           []string `json:"emails"`                     // list of emails
	CSV              string   `json:"csv"`                        // optional CSV string
	Points           *int     `json:"points,omitempty"`
	ForceBucket      string   `json:"force_bucket,omitempty"`     // "auto" | "counted" | "bonus"
	PreventDuplicate bool     `json:"prevent_duplicate,omitempty"`
	Note             string   `json:"note,omitempty"`
	// you can add AllowOverCap here if you want in the future
}

type BulkAttendRes struct {
	Processed int `json:"processed"`
	Success   int `json:"success"`
	Failed    int `json:"failed"`
}

func extractBulkEmails(req BulkAttendReq) []string {
	var all []string

	// from Emails array
	for _, e := range req.Emails {
		e = strings.TrimSpace(e)
		if e != "" {
			all = append(all, e)
		}
	}

	// from CSV blob if provided
	if strings.TrimSpace(req.CSV) != "" {
		parts := strings.FieldsFunc(req.CSV, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';'
		})
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				all = append(all, p)
			}
		}
	}

	// dedupe
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(all))
	for _, e := range all {
		l := strings.ToLower(e)
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		unique = append(unique, e)
	}
	return unique
}

func adminBulkAttendHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		adminID := fmt.Sprint(claims["uid"])

		eid := c.Param("id")
		var ev Event
		if err := db.First(&ev, "id = ?", eid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		var req BulkAttendReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}

		emails := extractBulkEmails(req)
		if len(emails) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no emails provided"})
			return
		}

		processed, success, failed := 0, 0, 0

		for _, email := range emails {
			processed++

			u, err := findUserByIdentifier(db, email)
			if err != nil {
				// user not found -> count as failed and continue
				failed++
				continue
			}

			manualReq := AdminManualAttendReq{
				User:             email, // mainly for logging / consistency
				Points:           req.Points,
				ForceBucket:      req.ForceBucket,
				PreventDuplicate: req.PreventDuplicate,
				AllowOverCap:     false, // tweak if you want this behaviour
				OccurredAtISO:    nil,   // always "now" for bulk, or add a param if you want
				Note:             req.Note,
			}

			_, _, _, err = applyManualAttend(db, adminID, &ev, u, manualReq)
			if err != nil {
				// duplicates, alumni, cap issues, etc. all show up as failed
				failed++
				continue
			}
			success++
		}

		c.JSON(http.StatusOK, BulkAttendRes{
			Processed: processed,
			Success:   success,
			Failed:    failed,
		})
	}
}


func createEventHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateEventReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}
		if strings.TrimSpace(req.Title) == "" || req.Points <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "title and positive points required"})
			return
		}
		starts, err1 := time.Parse(time.RFC3339, req.StartsAtISO)
		ends, err2 := time.Parse(time.RFC3339, req.EndsAtISO)
		if err1 != nil || err2 != nil || !ends.After(starts) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid starts_at/ends_at"})
			return
		}
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		creator := fmt.Sprint(claims["uid"])

		ev := Event{
			ID:          uuid.NewString(),
			Title:       strings.TrimSpace(req.Title),
			Description: strings.TrimSpace(req.Description),
			StartsAt:    starts,
			EndsAt:      ends,
			Location:    strings.TrimSpace(req.Location),
			Points:      req.Points,
			Category:    strings.TrimSpace(req.Category),
			CreatedBy:   creator,
			QRSecret:    randBase64(32),
			CreatedAt:   time.Now(),
		}
		if err := db.Create(&ev).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": ev.ID})
	}
}

func updateEventHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		var ev Event
		if err := db.First(&ev, "id = ?", id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		var req UpdateEventReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}

		// Apply changes if provided
		if req.Title != nil {
			t := strings.TrimSpace(*req.Title)
			if t == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "title cannot be empty"})
				return
			}
			ev.Title = t
		}
		if req.Description != nil {
			ev.Description = strings.TrimSpace(*req.Description)
		}
		if req.Location != nil {
			ev.Location = strings.TrimSpace(*req.Location)
		}
		if req.Category != nil {
			ev.Category = strings.TrimSpace(*req.Category)
		}
		if req.Points != nil {
			if *req.Points <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "points must be > 0"})
				return
			}
			ev.Points = *req.Points
		}

		// Datetimes (validate ordering if both present / or against the other existing one)
		var startsPtr, endsPtr *time.Time
		if req.StartsAtISO != nil {
			st, err := time.Parse(time.RFC3339, *req.StartsAtISO)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid starts_at (RFC3339)"})
				return
			}
			startsPtr = &st
		}
		if req.EndsAtISO != nil {
			en, err := time.Parse(time.RFC3339, *req.EndsAtISO)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ends_at (RFC3339)"})
				return
			}
			endsPtr = &en
		}
		// Compute the would-be values to validate ordering
		newStarts := ev.StartsAt
		newEnds := ev.EndsAt
		if startsPtr != nil {
			newStarts = *startsPtr
		}
		if endsPtr != nil {
			newEnds = *endsPtr
		}
		if !newEnds.After(newStarts) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ends_at must be after starts_at"})
			return
		}
		// Commit time changes after validation
		if startsPtr != nil {
			ev.StartsAt = *startsPtr
		}
		if endsPtr != nil {
			ev.EndsAt = *endsPtr
		}

		// Optional QR rotation (invalidate previously printed QR codes)
		if req.RotateQR != nil && *req.RotateQR {
			ev.QRSecret = randBase64(32)
		}

		if err := db.Save(&ev).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":        ev.ID,
			"title":     ev.Title,
			"points":    ev.Points,
			"starts_at": ev.StartsAt,
			"ends_at":   ev.EndsAt,
			"rotated_qr": (req.RotateQR != nil && *req.RotateQR),
		})
	}
}


func eventQRHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var ev Event
		if err := db.First(&ev, "id = ?", id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		exp := ev.EndsAt.Add(30 * time.Minute).Unix()

		// payload is now deterministic for this event
		pl := map[string]interface{}{
			"eid": ev.ID,
			"exp": exp,
			// no nonce
		}

		plBytes, _ := json.Marshal(pl)
		plB64 := base64.RawURLEncoding.EncodeToString(plBytes)
		sig := sign(plB64, ev.QRSecret)

		wire := map[string]string{"payload": plB64, "signature": sig}
		wireBytes, _ := json.Marshal(wire)

		if c.Query("format") == "json" {
			c.Data(http.StatusOK, "application/json", wireBytes)
			return
		}

		png, err := qrcode.Encode(string(wireBytes), qrcode.Medium, 256)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "qr encode error"})
			return
		}
		c.Data(http.StatusOK, "image/png", png)
	}
}


func listEventsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var evs []Event
		upcoming := c.Query("upcoming")
		q := db.Order("starts_at asc")
		if upcoming == "1" {
			q = q.Where("ends_at > ?", time.Now())
		}
		if err := q.Find(&evs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		type out struct {
			ID          string    `json:"id"`
			Title       string    `json:"title"`
			Description string    `json:"description"`
			StartsAt    time.Time `json:"starts_at"`
			EndsAt      time.Time `json:"ends_at"`
			Location    string    `json:"location"`
			Points      int       `json:"points"`
			Category    string    `json:"category"`
		}
		res := make([]out, 0, len(evs))
		for _, e := range evs {
			res = append(res, out{
				ID: e.ID, Title: e.Title, Description: e.Description,
				StartsAt: e.StartsAt, EndsAt: e.EndsAt, Location: e.Location,
				Points: e.Points, Category: e.Category,
			})
		}
		c.JSON(http.StatusOK, res)
	}
}

/* =========================
   Handlers: Scan / Attend
   ========================= */

type ScanAttendReq struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type qrPayload struct {
	EID   string `json:"eid"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

func scanAttendHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
			return
		}
		userID := fmt.Sprint(claims["uid"])

		var user User
		if err := db.First(&user, "id = ?", userID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		// Alumni: no accrual
		if user.IsAlumni {
			c.JSON(http.StatusOK, gin.H{
				"duplicate": false, "awarded": 0, "capped": true,
				"reason": "alumni_do_not_accrue_points",
				"year_index": user.YearIndex, "alumni": true,
				"cap": AlumniCap, "total_year": 0,
			})
			return
		}

		var req ScanAttendReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
			return
		}
		if req.Payload == "" || req.Signature == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "payload/signature required"})
			return
		}

		plBytes, err := base64.RawURLEncoding.DecodeString(req.Payload)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload b64"})
			return
		}
		var pl qrPayload
		if err := json.Unmarshal(plBytes, &pl); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload json"})
			return
		}
		if pl.EID == "" || pl.Exp == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing eid/exp"})
			return
		}
		if time.Now().Unix() > pl.Exp {
			c.JSON(http.StatusBadRequest, gin.H{"error": "qr expired"})
			return
		}

		var ev Event
		if err := db.First(&ev, "id = ?", pl.EID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		expected := sign(req.Payload, ev.QRSecret)
		if !hmac.Equal([]byte(expected), []byte(req.Signature)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad signature"})
			return
		}

		// Duplicate detection: block if either counted OR bonus already exists for this (user,event)
		var dupCount int64
		db.Model(&PointsLedger{}).Where("user_id = ? AND event_id = ?", userID, ev.ID).Count(&dupCount)
		if dupCount == 0 {
			db.Model(&BonusLedger{}).Where("user_id = ? AND event_id = ?", userID, ev.ID).Count(&dupCount)
		}
		if dupCount > 0 {
			c.JSON(http.StatusOK, gin.H{
				"duplicate": true, "awarded": 0, "overflow_bonus": 0, "event_points": ev.Points,
			})
			return
		}

		start, end := academicYearWindow(time.Now())
		current, err := sumYearPoints(db, userID, start, end)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "sum error"})
			return
		}
		cap := YearCaps[user.YearIndex]
		remaining := cap - current

		award := ev.Points
		capped := false
		overflow := 0

		if remaining <= 0 {
			// at cap: all event points go to bonus bucket
			award = 0
			capped = true
			overflow = ev.Points
		} else if ev.Points > remaining {
			// partial award + overflow
			award = remaining
			capped = true
			overflow = ev.Points - remaining
		}

		// write counted points if > 0
		if award > 0 {
			entry := PointsLedger{
				ID:          uuid.NewString(),
				UserID:      userID,
				EventID:     ev.ID,
				DeltaPoints: award,
				Reason:      "EVENT_ATTENDANCE",
				OccurredAt:  time.Now(),
			}
			if err := db.Create(&entry).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "insert error"})
				return
			}
		}

		// write overflow bonus if > 0
		if overflow > 0 {
			bonus := BonusLedger{
				ID:          uuid.NewString(),
				UserID:      userID,
				EventID:     ev.ID,
				BonusPoints: overflow,
				Reason:      "OVERFLOW_EVENT",
				OccurredAt:  time.Now(),
			}
			if err := db.Create(&bonus).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "bonus insert error"})
				return
			}
		}

		total := current + award

		var badgeName any = nil
		if award > 0 { // only try badge if we actually added counted points
			if b, awarded, err := maybeAwardBadge(db, userID, user.YearIndex, total); err == nil && awarded {
				badgeName = b.Name
				// Optional: auto-step to next year if you want
				if total >= cap && user.YearIndex < 4 {
					db.Model(&User{}).Where("id = ?", userID).Update("year_index", user.YearIndex+1)
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"duplicate":      false,
			"awarded":        award,          // counted toward cap
			"overflow_bonus": overflow,       // recorded separately
			"capped":         capped,
			"total_year":     total,
			"cap":            cap,
			"event_points":   ev.Points,
			"year_index":     user.YearIndex,
			"badge_awarded":  badgeName,
		})
	}
}

// ========== Admin: Event attendance list ==========
func eventAttendanceListHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		eid := c.Param("id")

		// optional pagination
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}

		// verify event exists
		var ev Event
		if err := db.First(&ev, "id = ?", eid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		// main rows: who attended + awarded points (counted)
		type Row struct {
			UserID     string    `json:"user_id"`
			Email      string    `json:"email"`
			Username   string    `json:"username"`
			BaseRole   string    `json:"base_role"`
			Awarded    int       `json:"awarded"`
			OccurredAt time.Time `json:"occurred_at"`
		}
		var rows []Row
		if err := db.Table("points_ledgers pl").
			Select("pl.user_id, u.email, u.username, u.base_role, pl.delta_points AS awarded, pl.occurred_at").
			Joins("JOIN users u ON u.id = pl.user_id").
			Where("pl.event_id = ?", eid).
			Order("pl.occurred_at asc").
			Limit(limit).Offset(offset).
			Scan(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}

		// attach overflow bonus (if any) per user for this event
		type BonusRow struct {
			UserID string
			Bonus  int
		}
		var bonus []BonusRow
		if err := db.Table("bonus_ledgers").
			Select("user_id, COALESCE(SUM(bonus_points),0) as bonus").
			Where("event_id = ?", eid).
			Group("user_id").
			Scan(&bonus).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		bonusMap := map[string]int{}
		for _, b := range bonus {
			bonusMap[b.UserID] = b.Bonus
		}

		type Out struct {
			UserID       string    `json:"user_id"`
			Email        string    `json:"email"`
			Username     string    `json:"username"`
			BaseRole     string    `json:"base_role"`
			Awarded      int       `json:"awarded"`
			OverflowBonus int      `json:"overflow_bonus"`
			OccurredAt   time.Time `json:"occurred_at"`
		}
		out := make([]Out, 0, len(rows))
		for _, r := range rows {
			out = append(out, Out{
				UserID:        r.UserID,
				Email:         r.Email,
				Username:      r.Username,
				BaseRole:      r.BaseRole,
				Awarded:       r.Awarded,
				OverflowBonus: bonusMap[r.UserID],
				OccurredAt:    r.OccurredAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"event_id":  eid,
			"count":     len(out),
			"attendees": out,
		})
	}
}

// ========== Admin: Event stats ==========
func eventAttendanceStatsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		eid := c.Param("id")

		// verify event exists
		var ev Event
		if err := db.First(&ev, "id = ?", eid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}

		// totals from counted ledger
		var attendeeCount int64
		if err := db.Model(&PointsLedger{}).
			Where("event_id = ?", eid).
			Count(&attendeeCount).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}

		var sumAwarded int64
		if err := db.Model(&PointsLedger{}).
			Where("event_id = ?", eid).
			Select("COALESCE(SUM(delta_points),0)").
			Scan(&sumAwarded).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}

		// bonus totals
		var sumBonus int64
		if err := db.Table("bonus_ledgers").
			Where("event_id = ?", eid).
			Select("COALESCE(SUM(bonus_points),0)").
			Scan(&sumBonus).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}

		// optional: breakdown by base role
		type RoleRow struct {
			BaseRole string
			Cnt      int64
		}
		var breakdown []RoleRow
		if err := db.Table("points_ledgers pl").
			Select("u.base_role, COUNT(*) as cnt").
			Joins("JOIN users u ON u.id = pl.user_id").
			Where("pl.event_id = ?", eid).
			Group("u.base_role").
			Scan(&breakdown).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		roleMap := map[string]int64{}
		for _, r := range breakdown {
			roleMap[r.BaseRole] = r.Cnt
		}

		c.JSON(http.StatusOK, gin.H{
			"event_id":           eid,
			"attendee_count":     attendeeCount,
			"sum_awarded_points": sumAwarded,
			"sum_bonus_overflow": sumBonus,
			"by_role":            roleMap, // e.g. {"student": 42, "faculty": 3, "staff": 6}
		})
	}
}

type AdminAdjustPointsReq struct {
	Delta         int     `json:"delta"` // can be negative
	Bucket        string  `json:"bucket"` // "counted" | "bonus"
	Reason        string  `json:"reason"` // e.g., "GOODWILL", "REVERSAL"
	Note          string  `json:"note,omitempty"`
	OccurredAtISO *string `json:"occurred_at,omitempty"`
	AllowOverCap  bool    `json:"allow_over_cap,omitempty"` // only for counted positive deltas
}

func adminAdjustPointsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := getClaims(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error":"no claims"}); return
		}
		adminID := fmt.Sprint(claims["uid"])

		uid := c.Param("id")
		var u User
		if err := db.First(&u, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error":"user not found"}); return
		}
		if u.IsAlumni && u.YearIndex >= 4 && strings.ToLower(strings.TrimSpace(c.Query("bucket"))) == "counted" && u.IsAlumni {
			// alumni rule: you *can* still put into bonus; counted is typically 0-cap
			// we'll allow but your policy may want to block counted for alumni entirely:
			// c.JSON(http.StatusBadRequest, gin.H{"error":"alumni_do_not_accrue_counted"}); return
		}

		var req AdminAdjustPointsReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":"bad json"}); return
		}
		bucket := strings.ToLower(strings.TrimSpace(req.Bucket))
		if bucket != "counted" && bucket != "bonus" {
			c.JSON(http.StatusBadRequest, gin.H{"error":"bucket must be 'counted' or 'bonus'"}); return
		}
		if req.Delta == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error":"delta cannot be 0"}); return
		}
		when := time.Now()
		if req.OccurredAtISO != nil {
			t, err := time.Parse(time.RFC3339, *req.OccurredAtISO)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error":"invalid occurred_at (RFC3339)"}); return
			}
			when = t
		}
		start, end := academicYearWindow(when)
		current, _ := sumYearPoints(db, u.ID, start, end)
		cap := YearCaps[u.YearIndex]

		// helpers
		writeCounted := func(amount int) error {
			if amount == 0 { return nil }
			entry := PointsLedger{
				ID:          uuid.NewString(),
				UserID:      u.ID,
				EventID:     "", // not tied to an event
				DeltaPoints: amount,
				Reason:      fmt.Sprintf("ADMIN_ADJUST_%s", strings.ToUpper(req.Reason)),
				OccurredAt:  when,
				AdminID:     &adminID,
				Note:        req.Note,
			}
			return db.Create(&entry).Error
		}
		writeBonus := func(amount int) error {
			if amount == 0 { return nil }
			entry := BonusLedger{
				ID:          uuid.NewString(),
				UserID:      u.ID,
				EventID:     "",
				BonusPoints: amount,
				Reason:      fmt.Sprintf("ADMIN_ADJUST_%s", strings.ToUpper(req.Reason)),
				OccurredAt:  when,
				AdminID:     &adminID,
				Note:        req.Note,
			}
			return db.Create(&entry).Error
		}

		// logic
		if bucket == "bonus" {
			if err := writeBonus(req.Delta); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"bonus insert error"}); return
			}
			c.JSON(http.StatusOK, gin.H{"user_id": u.ID, "bucket":"bonus", "delta": req.Delta, "note": req.Note}); return
		}

		// bucket == "counted"
		if req.Delta < 0 {
			// negative deltas: just write to counted (we allow going below 0; your policy can clamp if needed)
			if err := writeCounted(req.Delta); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"insert error"}); return
			}
			c.JSON(http.StatusOK, gin.H{"user_id": u.ID, "bucket":"counted", "delta": req.Delta, "note": req.Note}); return
		}

		// positive delta to counted: respect cap unless allow_over_cap
		if req.AllowOverCap {
			if err := writeCounted(req.Delta); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"insert error"}); return
			}
			c.JSON(http.StatusOK, gin.H{"user_id": u.ID, "bucket":"counted", "delta": req.Delta, "note": req.Note, "allow_over_cap": true}); return
		}

		remaining := cap - current
		awarded, overflow := 0, 0
		if remaining <= 0 {
			overflow = req.Delta
			if err := writeBonus(overflow); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"bonus insert error"}); return
			}
		} else if req.Delta > remaining {
			awarded = remaining
			overflow = req.Delta - remaining
			if err := writeCounted(awarded); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"insert error"}); return
			}
			if err := writeBonus(overflow); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"bonus insert error"}); return
			}
		} else {
			awarded = req.Delta
			if err := writeCounted(awarded); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error":"insert error"}); return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":        u.ID,
			"bucket":         "counted",
			"awarded":        awarded,
			"overflow_bonus": overflow,
			"note":           req.Note,
		})
	}
}

type EventAttendee struct {
  UserID    string    `json:"user_id"`
  Email     string    `json:"email"`
  Username  string    `json:"username"`
  Bucket    string    `json:"bucket"`   
  Points    int       `json:"points"`
  Occurred  time.Time `json:"occurred_at"`
  AdminNote string    `json:"note"`
}

func adminEventAttendeesHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    id := c.Param("id")
    // ensure event exists
    var ev Event
    if err := db.First(&ev, "id = ?", id).Error; err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error":"event not found"}); return
    }

    var counted []EventAttendee
    db.Table("points_ledgers pl").
      Select("pl.user_id, u.email, u.username, 'counted' as bucket, pl.delta_points as points, pl.occurred_at, pl.note").
      Joins("JOIN users u ON u.id = pl.user_id").
      Where("pl.event_id = ?", id).
      Order("pl.occurred_at asc").
      Scan(&counted)

    var bonus []EventAttendee
    db.Table("bonus_ledgers bl").
      Select("bl.user_id, u.email, u.username, 'bonus' as bucket, bl.bonus_points as points, bl.occurred_at, bl.note").
      Joins("JOIN users u ON u.id = bl.user_id").
      Where("bl.event_id = ?", id).
      Order("bl.occurred_at asc").
      Scan(&bonus)

    out := append(counted, bonus...)
    c.JSON(http.StatusOK, out)
  }
}

func adminEventAttendeesCSVHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    // simpler: just re-run the same queries and write CSV
    id := c.Param("id")

    type row struct{ Email, Username, Bucket string; Points int; When string; Note string }
    var rows []row

    var r1 []struct{ Email, Username, Note string; Points int; T time.Time }
    db.Raw(`
      SELECT u.email, u.username, pl.note, pl.delta_points as points, pl.occurred_at as t
      FROM points_ledgers pl JOIN users u ON u.id = pl.user_id
      WHERE pl.event_id = ? ORDER BY pl.occurred_at ASC`, id).Scan(&r1)
    for _, x := range r1 {
      rows = append(rows, row{x.Email, x.Username, "counted", x.Points, x.T.Format(time.RFC3339), x.Note})
    }
    var r2 []struct{ Email, Username, Note string; Points int; T time.Time }
    db.Raw(`
      SELECT u.email, u.username, bl.note, bl.bonus_points as points, bl.occurred_at as t
      FROM bonus_ledgers bl JOIN users u ON u.id = bl.user_id
      WHERE bl.event_id = ? ORDER BY bl.occurred_at ASC`, id).Scan(&r2)
    for _, x := range r2 {
      rows = append(rows, row{x.Email, x.Username, "bonus", x.Points, x.T.Format(time.RFC3339), x.Note})
    }

    c.Header("Content-Disposition", "attachment; filename=attendees_"+id+".csv")
    c.Header("Content-Type", "text/csv")
    c.Writer.WriteString("email,username,bucket,points,occurred_at,note\n")
    for _, r := range rows {
      // basic CSV escape for commas/quotes
      note := strings.ReplaceAll(r.Note, `"`, `""`)
      c.Writer.WriteString(fmt.Sprintf("%s,%s,%s,%d,%s,\"%s\"\n",
        r.Email, r.Username, r.Bucket, r.Points, r.When, note))
    }
  }
}

func adminSearchUsersHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        q := strings.TrimSpace(c.Query("query"))
        if q == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "query required"})
            return
        }

        var users []struct {
            ID        string   `json:"id"`
            Email     string   `json:"email"`
            Username  string   `json:"username"`
            BaseRole  BaseRole `json:"base_role"`
            IsAdmin   bool     `json:"is_admin"`
            YearIndex int      `json:"year_index"`
            IsAlumni  bool     `json:"is_alumni"`
        }

        db.Table("users").
            Select("id, email, username, base_role, is_admin, year_index, is_alumni").
            Where("email ILIKE ? OR username ILIKE ?", "%"+q+"%", "%"+q+"%").
            Limit(50).
            Scan(&users)

        c.JSON(http.StatusOK, users)
    }
}


  
func adminUserSummaryHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    uid := c.Param("id")
    var u User
    if err := db.First(&u, "id = ?", uid).Error; err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error":"user not found"}); return
    }
    start, end := academicYearWindow(time.Now())
    total, _ := sumYearPoints(db, u.ID, start, end)
    bonus, _ := sumYearBonus(db, u.ID, start, end)
    cap := YearCaps[u.YearIndex]
    if u.IsAlumni { cap = AlumniCap }
    next := cap
    if u.YearIndex == 1 { next = 50 } else if u.YearIndex == 2 { next = 100 } else if u.YearIndex == 3 { next = 150 } else { next = 200 }
    ptsToNext := next - total
    if ptsToNext < 0 { ptsToNext = 0 }

    c.JSON(http.StatusOK, gin.H{
      "user_id": u.ID,
      "email": u.Email,
      "username": u.Username,
      "base_role": u.BaseRole,
      "is_admin": u.IsAdmin,
      "year_index": u.YearIndex,
      "is_alumni": u.IsAlumni,
      "totals": gin.H{
        "year_points": total,
        "bonus_year":  bonus,
        "cap": cap,
        "next_threshold": next,
        "points_to_next": ptsToNext,
      },
    })
  }
}

// =========================
// Admin: User Data Mirrors
// =========================

// adminUserBadgesHandler: mirror of myBadgesHandler but admin-specified user
func adminUserBadgesHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.Param("id")
        var res []struct {
            Code        string    `json:"code"`
            Name        string    `json:"name"`
            Description string    `json:"description"`
            YearIndex   int       `json:"year_index"`
            AwardedAt   time.Time `json:"awarded_at"`
            IconPath    string    `json:"icon_path"`
        }
        err := db.Table("user_badges ub").
            Select("b.code, b.name, b.description, b.year_index, ub.awarded_at, b.icon_path").
            Joins("JOIN badges b ON b.id = ub.badge_id").
            Where("ub.user_id = ?", uid).
            Order("ub.awarded_at asc").
            Scan(&res).Error
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
            return
        }
        c.JSON(http.StatusOK, res)
    }
}

// adminUserLedgerHandler: mirror of myLedgerHandler but admin-specified user
func adminUserLedgerHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.Param("id")
        var rows []PointsLedger
        if err := db.Where("user_id = ?", uid).
            Order("occurred_at desc").
            Limit(200).
            Find(&rows).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
            return
        }
        c.JSON(http.StatusOK, rows)
    }
}

// adminUserBonusHandler: mirror of myBonusHandler but admin-specified user
func adminUserBonusHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.Param("id")
        var rows []BonusLedger
        if err := db.Where("user_id = ?", uid).
            Order("occurred_at desc").
            Limit(200).
            Find(&rows).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
            return
        }
        c.JSON(http.StatusOK, rows)
    }
}



type BulkManualAttendReq struct {
  Emails          []string `json:"emails,omitempty"` // alternative to CSV
  CSV             string   `json:"csv,omitempty"`    // newline/comma-separated emails
  Points          *int     `json:"points,omitempty"`
  ForceBucket     string   `json:"force_bucket,omitempty"` // auto|counted|bonus
  PreventDuplicate bool    `json:"prevent_duplicate,omitempty"`
  Note            string   `json:"note,omitempty"`
}

type AdminHealthStatus struct {
    Status  string `json:"status"`
    Version string `json:"version,omitempty"`
    DBOK    bool   `json:"db_ok"`
}


// adminHealthHandler returns health but only for authenticated admins
func adminHealthHandler(db *gorm.DB, version string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // optional: verify claims again if you want
        if _, ok := getClaims(c); !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
            return
        }

        dbOK := false
        if sqlDB, err := db.DB(); err == nil {
            ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
            defer cancel()
            if err := sqlDB.PingContext(ctx); err == nil {
                dbOK = true
            }
        }

        c.JSON(http.StatusOK, AdminHealthStatus{
            Status:  "ok",
            Version: version,
            DBOK:    dbOK,
        })
    }
}

// var adminInviteTokenEnv = os.Getenv("ADMIN_INVITE_TOKEN")

type InviteTokenResp struct {
    Token string `json:"token"`
}

// adminGetInviteTokenHandler returns the configured invite token to an admin.
func adminGetInviteTokenHandler() gin.HandlerFunc {
    return func(c *gin.Context) {

        // IMPORTANT: make sure this name EXACTLY matches your .env
        adminInviteToken := os.Getenv("ADMIN_INVITE_TOKEN")
        if _, ok := getClaims(c); !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
            return
        }

        if adminInviteToken == "" {
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no invite token configured"})
            return
        }

        c.JSON(http.StatusOK, InviteTokenResp{
            Token: adminInviteToken,
        })
    }
}


func adminAuditHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    limit, _ := strconv.Atoi(c.DefaultQuery("limit","100"))
    if limit <= 0 || limit > 500 { limit = 100 }

    // Collect from three sources and sort in-memory by Created/Occurred
    type item struct {
      Kind      string    `json:"kind"`  // MANUAL_ATTEND, ADJUST_POINTS, EVENT_UPDATED
      AdminID   string    `json:"admin_id"`
      UserEmail string    `json:"user_email,omitempty"`
      EventID   string    `json:"event_id,omitempty"`
      Delta     int       `json:"delta,omitempty"`
      Bucket    string    `json:"bucket,omitempty"`
      Note      string    `json:"note,omitempty"`
      At        time.Time `json:"at"`
      Changes   string    `json:"changes,omitempty"`
    }
    var out []item

    // from PointsLedger where AdminID not null
    var pl []struct{ AID, UID, EID, Note string; Delta int; At time.Time }
    db.Raw(`SELECT admin_id as aid, user_id as uid, coalesce(event_id,'') as eid, note, delta_points as delta, occurred_at as at
            FROM points_ledgers WHERE admin_id IS NOT NULL ORDER BY occurred_at DESC LIMIT ?`, limit).Scan(&pl)
    for _, x := range pl {
      var u User; db.Select("email").First(&u, "id = ?", x.UID)
      out = append(out, item{Kind:"ADJUST_POINTS", AdminID:x.AID, UserEmail:u.Email, EventID:x.EID, Delta:x.Delta, Bucket:"counted", Note:x.Note, At:x.At})
    }

    // from BonusLedger where AdminID not null
    var bl []struct{ AID, UID, EID, Note string; Bonus int; At time.Time }
    db.Raw(`SELECT admin_id as aid, user_id as uid, coalesce(event_id,'') as eid, note, bonus_points as bonus, occurred_at as at
            FROM bonus_ledgers WHERE admin_id IS NOT NULL ORDER BY occurred_at DESC LIMIT ?`, limit).Scan(&bl)
    for _, x := range bl {
      var u User; db.Select("email").First(&u, "id = ?", x.UID)
      out = append(out, item{Kind:"ADJUST_POINTS", AdminID:x.AID, UserEmail:u.Email, EventID:x.EID, Delta:x.Bonus, Bucket:"bonus", Note:x.Note, At:x.At})
    }

    // from EventUpdateLog
    var el []EventUpdateLog
    db.Order("created_at DESC").Limit(limit).Find(&el)
    for _, e := range el {
      out = append(out, item{Kind:"EVENT_UPDATED", AdminID:e.AdminID, EventID:e.EventID, At:e.CreatedAt, Changes:e.Changes})
    }

    // sort by At desc
    sort.Slice(out, func(i,j int) bool { return out[i].At.After(out[j].At) })
    if len(out) > limit { out = out[:limit] }
    c.JSON(http.StatusOK, out)
  }
}


func adminImpersonateHandler(cfg Config) gin.HandlerFunc {
  return func(c *gin.Context) {
    claims, ok := getClaims(c); if !ok { c.JSON(http.StatusUnauthorized, gin.H{"error":"no claims"}); return }
    adminID := fmt.Sprint(claims["uid"])
    targetUID := c.Param("id")
    email := c.Query("email") // optional convenience

    // Minimal checking; you can require target exists
    subEmail := email
    if subEmail == "" { subEmail = targetUID }

    // issue token with short TTL
    t, err := makeImpersonationJWT(targetUID, subEmail, cfg.JWTSecret, 10*time.Minute, adminID)
    if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error":"token error"}); return }
    c.JSON(http.StatusOK, gin.H{"impersonation_token": t, "expires_in":"10m"})
  }
}

func makeImpersonationJWT(uid, email, secret string, ttl time.Duration, adminID string) (string, error) {
  c := jwt.MapClaims{
    "uid": uid, "email": email, "base_role": "student", "is_admin": false,
    "impersonated_by": adminID,
    "exp": time.Now().Add(ttl).Unix(),
    "iat": time.Now().Unix(),
  }
  t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
  return t.SignedString([]byte(secret))
}


type UpsertBadgeReq struct {
  Code, Name, Description, IconPath string
  Threshold, YearIndex              int
}
func adminUpsertBadgeHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    var req UpsertBadgeReq
    if err := c.BindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error":"bad json"}); return }
    if req.Code == "" || req.Name == "" || req.YearIndex < 1 || req.YearIndex > 4 {
      c.JSON(http.StatusBadRequest, gin.H{"error":"invalid fields"}); return
    }
    var b Badge
    if err := db.Where("code = ?", req.Code).First(&b).Error; err != nil {
      // create
      b = Badge{ID: uuid.NewString(), Code: req.Code, Name: req.Name, Description: req.Description,
        Threshold: req.Threshold, YearIndex: req.YearIndex, IconPath: req.IconPath, CreatedAt: time.Now()}
      if err := db.Create(&b).Error; err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return }
      c.JSON(http.StatusCreated, gin.H{"id": b.ID}); return
    }
    // update
    b.Name = req.Name; b.Description = req.Description; b.Threshold = req.Threshold; b.YearIndex = req.YearIndex; b.IconPath = req.IconPath
    if err := db.Save(&b).Error; err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return }
    c.JSON(http.StatusOK, gin.H{"id": b.ID})
  }
}


type Webhook struct {
  ID        string    `gorm:"type:text;primaryKey"`
  URL       string    `gorm:"uniqueIndex;not null"`
  Event     string    `gorm:"not null"` // e.g., "event.updated","attendance.manual","points.adjusted"
  CreatedAt time.Time `gorm:"not null"`
}

func adminAddWebhookHandler(db *gorm.DB) gin.HandlerFunc {
  return func(c *gin.Context) {
    var req struct{ URL, Event string }
    if err := c.BindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error":"bad json"}); return }
    if req.URL == "" || req.Event == "" { c.JSON(http.StatusBadRequest, gin.H{"error":"url and event required"}); return }
    w := Webhook{ID: uuid.NewString(), URL: req.URL, Event: req.Event, CreatedAt: time.Now()}
    if err := db.Create(&w).Error; err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error":"db error"}); return }
    c.JSON(http.StatusCreated, gin.H{"id": w.ID})
  }
}

func fireWebhook(db *gorm.DB, event string, payload any) {
  var hooks []Webhook
  if err := db.Where("event = ?", event).Find(&hooks).Error; err != nil { return }
  body, _ := json.Marshal(payload)
  for _, h := range hooks {
    go func(url string) {
      http.Post(url, "application/json", strings.NewReader(string(body)))
    }(h.URL)
  }
}



// helper to read and split env safely
func splitCSVEnv(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

/* =========================
   Main / Routes
   ========================= */

func main() {
	cfg := loadConfig()
	gdb := openDB(cfg.DatabaseURL)

	r := gin.Default()
	r.SetTrustedProxies(nil)

	// CORS config
	allowed := splitCSVEnv("CORS_ALLOWED_ORIGINS")
	cfgCORS := cors.Config{
		AllowOrigins:     allowed, // if empty, we'll set a sane default below
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	if len(cfgCORS.AllowOrigins) == 0 {
		cfgCORS.AllowOrigins = []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}
	r.Use(cors.New(cfgCORS))

	r.Static("/assets", "./public/assets") // serve badge icons
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	v1 := r.Group("/v1")
	{
		v1.POST("/auth/register", registerHandler(gdb, cfg))
		v1.POST("/auth/login", loginHandler(gdb, cfg))
		v1.POST("/auth/register-admin", adminRegisterHandler(gdb, cfg))


		authz := v1.Group("/")
		authz.Use(authRequired(cfg.JWTSecret))
		authz.GET("me", meHandler(gdb))

		authz.GET("events", listEventsHandler(gdb))
		authz.POST("scan/attend", scanAttendHandler(gdb))

		authz.GET("badges", listBadgesHandler(gdb))
		authz.GET("me/badges", myBadgesHandler(gdb))
		authz.GET("me/ledger", myLedgerHandler(gdb))
		authz.GET("me/bonus", myBonusHandler(gdb)) 

		

		admin := authz.Group("admin")
		admin.Use(adminRequired())
		admin.POST("/events", createEventHandler(gdb))
		admin.GET("/events/:id/qr", eventQRHandler(gdb))
		admin.PATCH("/events/:id", updateEventHandler(gdb)) 
		admin.GET("/events/:id/attendees/basic", eventAttendanceListHandler(gdb))
		admin.GET("/events/:id/stats", eventAttendanceStatsHandler(gdb))
		admin.POST("/events/:id/attend-manual", adminBulkAttendHandler(gdb))
		admin.POST("/events/:id/manual-attend", adminManualAttendHandler(gdb))
		admin.POST("/users/:id/adjust-points", adminAdjustPointsHandler(gdb))
		admin.GET("/events/:id/attendees", adminEventAttendeesHandler(gdb))
		admin.GET("/events/:id/attendees.csv", adminEventAttendeesCSVHandler(gdb))

		admin.GET("/healthz", adminHealthHandler(gdb, "v1"))
        admin.GET("/invite-token", adminGetInviteTokenHandler())


		admin.GET("/users", adminSearchUsersHandler(gdb))
		admin.GET("/users/:id/summary", adminUserSummaryHandler(gdb))
		admin.GET("/users/:id/badges", adminUserBadgesHandler(gdb))
		admin.GET("/users/:id/ledger", adminUserLedgerHandler(gdb))
		admin.GET("/users/:id/bonus", adminUserBonusHandler(gdb))
		admin.GET("/audit", adminAuditHandler(gdb))
		admin.GET("/stats", adminStatsHandler(gdb)) 


		admin.POST("/events/:id/attend-bulk", adminBulkAttendHandler(gdb))
		admin.POST("/users/:id/impersonate", adminImpersonateHandler(cfg))
		admin.POST("/badges/upsert", adminUpsertBadgeHandler(gdb))
		admin.POST("/webhooks", adminAddWebhookHandler(gdb))



	}

	addr := ":" + cfg.Port
	fmt.Println("EcoTracker API on", addr)
	if err := r.Run(addr); err != nil {
		panic(err)
	}
}

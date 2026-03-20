package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		// 회원가입
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}

			if err := store.createUser(request); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "회원가입 실패: " + err.Error()})
				return
			}

			c.JSON(http.StatusAccepted, gin.H{
				"message": "회원가입 완료.",
				"user": gin.H{
					"username": request.Username,
					"name":     request.Name,
					"email":    request.Email,
					"phone":    request.Phone,
				},
			})
		})

		// 로그인
		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		// 로그아웃
		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
		})

		// 회원 탈퇴
		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid Password"})
				return
			}

			_, err := store.db.Exec("WHAT ID = ?", user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete account"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusAccepted, gin.H{
				"message": "Success withdraw",
				"user":    makeUserResponse(user),
			})
		})
	}

	protected := router.Group("/api")
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				sessions.delete(token)
				clearAuthorizationCookie(c)
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		//입금 코드
		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy deposit handler",
				"todo":    "replace with balance increment query",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		//출금 코드
		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy withdraw handler",
				"todo":    "replace with balance check and decrement query",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		//이체 코드
		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy transfer handler",
				"todo":    "replace with transfer transaction and balance checks",
				"user":    makeUserResponse(user),
				"target":  request.ToUsername,
				"amount":  request.Amount,
			})
		})

		//게시글
		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			posts, err := store.listPosts()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "fail view post" + err.Error()})
				return
			}

			c.JSON(http.StatusOK, PostListResponse{
				Posts: posts,
			})
		})

		//글쓰기
		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			post, err := store.createPost(user, request)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message:": "write fail" + err.Error()})
				return
			}

			now := time.Now().Format(time.RFC3339)
			c.JSON(http.StatusCreated, gin.H{
				"message": "dummy create post handler",
				"todo":    "replace with insert query",
				"post": PostView{
					ID:          1,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			})

			c.JSON(http.StatusCreated, PostResponse{Post: post})
		})

		//글 조회
		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID, err := strconv.ParseUint(c.Param("id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid ID"})
				return
			}

			post, found, err := store.findPostByID(uint(postID))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"messege": "게시글 조회 fail" + err.Error()})
				return
			}

			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "게시글이없슴ㅂ니다"})
				return
			}

			c.JSON(http.StatusOK, PostResponse{Post: post})

		})

		//글 수정하기
		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID, err := strconv.ParseUint(c.Param("id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid post id"})
				return
			}

			// 게시글 존재 및 소유권 확인
			existing, found, err := store.findPostByID(uint(postID))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "게시글 조회 실패"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "게시글을 찾을 수 없습니다"})
				return
			}
			if existing.OwnerID != user.ID && !user.IsAdmin {
				c.JSON(http.StatusForbidden, gin.H{"message": "수정 권한이 없습니다"})
				return
			}

			post, err := store.updatePost(uint(postID), request)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "게시글 수정 실패: " + err.Error()})
				return
			}

			c.JSON(http.StatusOK, PostResponse{Post: post})
		})

		//글삭
		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)

			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID, err := strconv.ParseUint(c.Param("id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid post id"})
				return
			}

			existing, found, err := store.findPostByID(uint(postID))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "게시글 조회 실패"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "게시글을 찾을 수 없습니다"})
				return
			}

			if existing.OwnerID != user.ID && !user.IsAdmin {
				c.JSON(http.StatusForbidden, gin.H{"message": "삭제 권한이 없습니다"})
				return
			}

			if _, err := store.db.Exec("DELETE FROM posts WHERE id = ?", postID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "게시글 삭제 실패: " + err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "delete complete",
				//"todo":    "replace with ownership check and delete query",
			})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) close() error { return s.db.Close() }

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	return s.execSQLFile(seedFile)
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(string(content))
	return err
}

// 유저 회원가입
func (s *Store) createUser(req RegisterRequest) error {
	query := `INSERT INTO users (username, name, email, phone, password, balance, is_admin) VALUES (?, ?, ?, ?, ?, 0, ?)`
	_, err := s.db.Exec(query, req.Username, req.Name, req.Email, req.Phone, req.Password, false)
	return err
}

// 유저 찾기
func (s *Store) findUserByUsername(username string) (User, bool, error) {
	return s.scanUser(s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users WHERE username = ?`, strings.TrimSpace(username)))
}

// ID로 찾기
func (s *Store) findUserByID(id uint) (User, bool, error) {
	return s.scanUser(s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users WHERE id = ?`, id))
}

// 유저 찾기
func (s *Store) scanUser(row *sql.Row) (User, bool, error) {
	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1
	return user, true, nil
}

// 입금
func (s *Store) deposit(userID uint, amount int64) (User, error) {
	_, err := s.db.Exec(`UPDATE users SET balance = balance + ? WHERE id = ?`, amount, userID)
	if err != nil {
		return User{}, err
	}
	user, _, err := s.findUserByID(userID)
	return user, err
}

// 출금
func (s *Store) balanceWithdraw(userID uint, amount int64) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var balance int64
	if err := tx.QueryRow(`SELECT balance FROM users WHERE id = ?`, userID).Scan(&balance); err != nil {
		return User{}, err
	}
	if balance < amount {
		return User{}, errors.New("잔액 부족")
	}

	if _, err := tx.Exec(`UPDATE users SET balance = balance - ? WHERE id = ?`, amount, userID); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	user, _, err := s.findUserByID(userID)
	return user, err
}

// 이체
func (s *Store) transfer(fromID uint, toUsername string, amount int64) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	// 수신자 확인
	var toID uint
	if err := tx.QueryRow(`SELECT id FROM users WHERE username = ?`, strings.TrimSpace(toUsername)).Scan(&toID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, errors.New("수신자 없음")
		}
		return User{}, err
	}

	// 송신자 잔액 확인
	var balance int64
	if err := tx.QueryRow(`SELECT balance FROM users WHERE id = ?`, fromID).Scan(&balance); err != nil {
		return User{}, err
	}
	if balance < amount {
		return User{}, errors.New("잔액 부족")
	}

	// 출금
	if _, err := tx.Exec(`UPDATE users SET balance = balance - ? WHERE id = ?`, amount, fromID); err != nil {
		return User{}, err
	}
	// 입금
	if _, err := tx.Exec(`UPDATE users SET balance = balance + ? WHERE id = ?`, amount, toID); err != nil {
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	user, _, err := s.findUserByID(fromID)
	return user, err
}

// 게시글 목록
func (s *Store) listPosts() ([]PostView, error) {
	rows, err := s.db.Query(`
		SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at
		FROM posts p
		JOIN users u ON p.owner_id = u.id
		ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []PostView
	for rows.Next() {
		var p PostView
		if err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		posts = append(posts, p)
	}
	if posts == nil {
		posts = []PostView{}
	}
	return posts, rows.Err()
}

// 게시글 조회하기
func (s *Store) findPostByID(id uint) (PostView, bool, error) {
	var p PostView
	err := s.db.QueryRow(`
		SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at
		FROM posts p
		JOIN users u ON p.owner_id = u.id
		WHERE p.id = ?`, id).
		Scan(&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PostView{}, false, nil
		}
		return PostView{}, false, err
	}
	return p, true, nil
}

// 게시글 작성
func (s *Store) createPost(user User, req CreatePostRequest) (PostView, error) {
	now := time.Now().Format(time.RFC3339)
	res, err := s.db.Exec(`
		INSERT INTO posts (title, content, owner_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`,
		strings.TrimSpace(req.Title), strings.TrimSpace(req.Content), user.ID, now, now)
	if err != nil {
		return PostView{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return PostView{}, err
	}
	return PostView{
		ID:          uint(id),
		Title:       strings.TrimSpace(req.Title),
		Content:     strings.TrimSpace(req.Content),
		OwnerID:     user.ID,
		Author:      user.Name,
		AuthorEmail: user.Email,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// 게시글 수정
func (s *Store) updatePost(id uint, req UpdatePostRequest) (PostView, error) {
	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE posts SET title = ?, content = ?, updated_at = ? WHERE id = ?`,
		strings.TrimSpace(req.Title), strings.TrimSpace(req.Content), now, id)
	if err != nil {
		return PostView{}, err
	}
	post, _, err := s.findPostByID(id)
	return post, err
}

func newSessionStore() *SessionStore {
	return &SessionStore{tokens: make(map[string]User)}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}
	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) { delete(s.tokens, token) }

func registerStaticRoutes(router *gin.Engine) {
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) { c.File("./static/index.html") })
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader("Authorization")); v != "" {
		return v
	}
	if v, err := c.Cookie(authorizationCookieName); err == nil {
		return strings.TrimSpace(v)
	}
	return ""
}

func newSessionToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

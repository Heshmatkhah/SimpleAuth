package SimpleAuth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"github.com/gin-gonic/gin"
	"github.com/boltdb/bolt"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"sync"
	"time"
)

type User struct {
	Username string   `json:"username"`
	Password []byte   `json:"pass"`
	Group    []string `json:"array"`
}

/* ***************************************** *
 *                                           *
 *                 Database                  *
 *                                           *
 * ***************************************** */

type database struct {
	lock     sync.Mutex
	count    int32
	path     string
	DataBase *bolt.DB
}

func (db *database) Close() error {
	db.lock.Lock()
	atomic.AddInt32(&db.count, -1)
	count := atomic.LoadInt32(&db.count)
	db.lock.Unlock()
	if count == 0 {
		return db.DataBase.Close()
	} else {
		return nil
	}
}

func (db *database) Open() (*database, error) {
	db.lock.Lock()
	atomic.AddInt32(&db.count, 1)
	count := atomic.LoadInt32(&db.count)
	db.lock.Unlock()
	if count == 1 {
		var err error
		db.DataBase, err = bolt.Open(db.path, 0644, nil)
		if err != nil {
			return nil, err
		}
		return db, nil
	} else {
		return db, nil
	}
}

func (db *database) Initialize(path string) error {
	if path == "" {
		return fmt.Errorf("path can't be empty")
	}
	db.count = 0
	db.path = path
	db.Open()
	defer db.Close()
	return db.DataBase.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}

		encoded, err := json.Marshal([]string{"Admins", "Users"})
		if err != nil {
			return err
		}

		err = bucket.Put([]byte("groups"), encoded)
		if err != nil {
			return err
		}

		bucket, err = tx.CreateBucketIfNotExists([]byte("sessions"))
		if err != nil {
			return err
		}

		return nil
	})
}

/* ***************************************** *
 *                                           *
 *                  Session                  *
 *                                           *
 * ***************************************** */

type Session interface {
	Set(key, value interface{}) bool
	Get(key interface{}) interface{}
	Delete(key interface{}) interface{}
	Validate(maxLife int64) bool
	SessionID() string
}

type SessionStorage struct {
	Username   string
	sessionID  string
	lastAccess int64
	values     map[string]interface{}
}

type storage struct {
	SessionID  string                 `json:"session_id"`
	Username   string                 `json:"username"`
	LastAccess int64                  `json:"last_access"`
	Values     map[string]interface{} `json:"values"`
}

func (s *SessionStorage) SessionID() string {
	return s.sessionID
}

func (s *SessionStorage) updateAccess() error {
	s.lastAccess = time.Now().Unix()
	return nil
}

func (s *SessionStorage) Set(key string, value interface{}) bool {
	s.updateAccess()
	s.values[key] = value
	return true
}

func (s *SessionStorage) Get(key string) interface{} {
	s.updateAccess()
	if v, ok := s.values[key]; ok {
		return v
	}
	return nil
}

func (s *SessionStorage) Delete(key string) interface{} {
	s.updateAccess()
	if v, ok := s.values[key]; ok {
		defer delete(s.values, key)
		return v
	}
	return nil
}

func (s *SessionStorage) Validate(maxLife int64) bool {
	if (s.lastAccess + maxLife) < time.Now().Unix() {
		return false
	}
	return true
}

func (s *SessionStorage) Save(manager Manager) error {
	return manager.SaveSession(*s)
}

func (s *SessionStorage) generateSessionToken() string {
	// We're using a random 16 character string as the session token
	// This is NOT a secure way of generating session tokens
	// DO NOT USE THIS IN PRODUCTION
	//return strconv.FormatInt(rand.Int63(), 16)	//"math/rand"	//"strconv"

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	s.sessionID = base64.URLEncoding.EncodeToString(b)
	s.updateAccess()
	return s.sessionID
}

/* ***************************************** *
 *                                           *
 *              Session Manager              *
 *                                           *
 * ***************************************** */

type Manager struct {
	db                         database
	LoginURL                   string
	LogoutURL                  string
	CookieName                 string
	UnauthorizedURL            string
	MaxCookieLifeTime          int64
	LoginSuccessfulRedirectURL string
}

type Options struct {
	LoginURL                   string
	LogoutURL                  string
	CookieName                 string
	UnauthorizedURL            string
	MaxCookieLifeTime          int64
	LoginSuccessfulRedirectURL string
}

var DefaultOptions = &Options{
	LoginURL:                   "/login",
	LogoutURL:                  "/logout",
	CookieName:                 "SimpleAuthCookie",
	UnauthorizedURL:            "/401",
	MaxCookieLifeTime:          86400, //One Day
	LoginSuccessfulRedirectURL: "/home",
}

func (m *Manager) Initialize(db_path string, options *Options) error {
	if options == nil {
		options = DefaultOptions
	}
	m.MaxCookieLifeTime = options.MaxCookieLifeTime
	m.CookieName = options.CookieName
	m.LoginURL = options.LoginURL
	m.LogoutURL = options.LogoutURL
	m.UnauthorizedURL = options.UnauthorizedURL
	m.LoginSuccessfulRedirectURL = options.LoginSuccessfulRedirectURL

	return m.db.Initialize(db_path)
}

func (m *Manager) NewSession() SessionStorage {
	s := SessionStorage{Username: "", values: make(map[string]interface{})}
	s.generateSessionToken()
	m.SaveSession(s)
	return s
}

func (m *Manager) SaveSession(s SessionStorage) error {

	m.db.Open()
	defer m.db.Close()

	return m.db.DataBase.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("sessions"))
		if err != nil {
			return err
		}

		encoded, err := json.Marshal(&storage{s.sessionID, s.Username, s.lastAccess, s.values})
		if err != nil {
			return err
		}

		err = bucket.Put([]byte(s.sessionID), encoded)
		if err != nil {
			return err
		}

		return nil
	})
}

func (m *Manager) RemoveSession(sessionID string) error {

	m.db.Open()
	defer m.db.Close()

	return m.db.DataBase.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("sessions"))
		if err != nil {
			return err
		}

		err = bucket.Delete([]byte(sessionID))
		if err != nil {
			return err
		}

		return nil
	})
}

func (m *Manager) GetSession(sessionID string) interface{} {
	m.db.Open()
	defer m.db.Close()

	var session SessionStorage

	err := m.db.DataBase.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("sessions"))
		if bucket == nil {
			return fmt.Errorf("session's Bucket not found")
		}

		val := bucket.Get([]byte(sessionID))
		if val != nil {
			s := storage{}
			err := json.Unmarshal(val, &s)
			if err == nil {
				session.sessionID = s.SessionID
				session.Username = s.Username
				session.lastAccess = s.LastAccess
				session.values = s.Values
			}
			return err

		} else {
			session = m.NewSession()
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	if session.Validate(m.MaxCookieLifeTime) {
		session.updateAccess()
		m.SaveSession(session)
		return session
	} else {
		m.RemoveSession(sessionID)
	}

	return nil

}

func (m *Manager) GetUser(username string) interface{} {
	m.db.Open()
	defer m.db.Close()

	var user User

	err := m.db.DataBase.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("users"))
		if bucket == nil {
			return fmt.Errorf("user's Bucket not found")
		}

		val := bucket.Get([]byte(username))
		if val != nil {
			err := json.Unmarshal(val, &user)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	if user.Username == username {
		return user
	}

	return nil
}

func (m *Manager) IsUsernameAvailable(username string) bool {
	u := m.GetUser(username)
	if u == nil {
		return true
	}
	return false
}

func (m *Manager) IsUserValid(username, password string) bool {
	user := m.GetUser(username).(User)
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
		return false
	}
	return true
}

func (m *Manager) RegisterNewUser(username, password string, groups []string) (*User, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("the password can't be empty")
	} else if !m.IsUsernameAvailable(username) {
		return nil, errors.New("the username isn't available")
	}

	pass, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := User{username, pass, groups}

	err := m.saveUser(&user)

	if err != nil {
		return nil, err
	}

	return &user, nil

}

func (m *Manager) saveUser(user *User) error {
	m.db.Open()
	defer m.db.Close()

	return m.db.DataBase.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}

		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(user.Username), encoded)
		if err != nil {
			return err
		}
		return nil
	})

}

func (m *Manager) ChangeUserPassword(username, password string) (*User, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("the password can't be empty")
	}
	pass, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	u := m.GetUser(username)
	if u != nil {
		u.(User).Password = pass
		err := m.saveUser(&u.(User))
		if err == nil {
			return &u.(User), nil
		}
		return nil, err
	}
	return nil, errors.New("user dose not exists")
}

/* ***************************************** *
 *                                           *
 *                 Middleware                *
 *                                           *
 * ***************************************** */

func (m *Manager) SessionHandler(context *gin.Context) {
	if token, err := context.Cookie(m.CookieName); err == nil || token != "" {
		s := m.GetSession(token)
		if s != nil {
			context.SetCookie(m.CookieName, s.(SessionStorage).sessionID, int(m.MaxCookieLifeTime), "", "", false, true)
			context.Set("session_id", s.(SessionStorage).sessionID)
		} else {
			context.Set("session_id", nil)
			context.SetCookie(m.CookieName, "", int(m.MaxCookieLifeTime), "", "", false, true)
		}
	} else {
		session := m.NewSession()
		context.SetCookie(m.CookieName, session.SessionID(), int(m.MaxCookieLifeTime), "", "", false, true)
		context.Set("session_id", session.sessionID)

	}
}

func (m *Manager) AuthenticatedOnly(context *gin.Context) {
	s, ok := context.Get("session_id")
	if !ok || s == nil {
		context.Redirect(307, m.LoginURL)
	} else {
		session := m.GetSession(s.(string)).(SessionStorage)
		if session.Username == "" {
			context.Redirect(307, m.LoginURL)
		}
	}
}

func (m *Manager) UnauthenticatedOnly(context *gin.Context) {
	s, _ := context.Get("session_id")
	if s != nil {
		session := m.GetSession(s.(string))
		if session != nil {
			if session.(SessionStorage).Username != "" {
				//context.AbortWithStatus(http.StatusUnauthorized)
				context.Redirect(307, m.UnauthorizedURL)
			}
		} else {
			context.Redirect(307, m.UnauthorizedURL)
		}
	}
}

func (m *Manager) Login(context *gin.Context) {
	username := context.PostForm("username")
	password := context.PostForm("password")
	if ok := m.IsUserValid(username, password); ok {
		s, _ := context.Get("session_id")
		if s == nil {
			session := m.NewSession()
			context.SetCookie(m.CookieName, session.SessionID(), int(m.MaxCookieLifeTime), "", "", false, true)
			session.Set("Login_status", true)
			session.Username = username
			session.Save(*m) // m.SaveSession(session)
			context.Set("session_id", session.SessionID())
		} else {
			session := m.GetSession(s.(string)).(SessionStorage)
			context.SetCookie(m.CookieName, session.SessionID(), int(m.MaxCookieLifeTime), "", "", false, true)
			session.Set("Login_status", true)
			session.Username = username
			session.Save(*m) // m.SaveSession(session)
		}
		context.Redirect(307, m.LoginSuccessfulRedirectURL)
	} else {
		context.Set("Login_error", "invalid username or password")
		context.Redirect(307, m.LoginURL)
	}
}

func (m *Manager) Logout(context *gin.Context) {
	s, _ := context.Get("session_id")
	if s != nil {
		session := m.GetSession(s.(string)).(SessionStorage)
		context.SetCookie(m.CookieName, session.SessionID(), int(m.MaxCookieLifeTime), "", "", false, true)
		session.Set("Login_status", false)
		session.Username = ""
		session.Save(*m) // m.SaveSession(session)
		context.Redirect(307, "/")
	}
}

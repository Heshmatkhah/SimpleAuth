package SimpleAuth

import (
	"encoding/json"
	"errors"
	"encoding/gob"
	"fmt"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/boltdb/bolt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"sync"
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
	defer db.lock.Unlock()
	db.count -= 1
	count := db.count
	if count == 0 {
		return db.DataBase.Close()
	} else {
		return nil
	}
}

func (db *database) Open() (*database, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	db.count += 1
	count := db.count
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

		return nil
	})
}

/* ***************************************** *
 *                                           *
 *                Auth Manager               *
 *                                           *
 * ***************************************** */

type Manager struct {
	db                         database
	LoginURL                   string
	LogoutURL                  string
	UnauthorizedURL            string
	LoginSuccessfulRedirectURL string
}

type Options struct {
	LoginURL                   string
	LogoutURL                  string
	UnauthorizedURL            string
	LoginSuccessfulRedirectURL string
}

var DefaultOptions = &Options{
	LoginURL:                   "/login",
	LogoutURL:                  "/logout",
	UnauthorizedURL:            "/401",
	LoginSuccessfulRedirectURL: "/home",
}

func (m *Manager) Initialize(db_path string, options *Options) error {
	gob.Register(User{})
	if options == nil {
		options = DefaultOptions
	}
	m.LoginURL = options.LoginURL
	m.LogoutURL = options.LogoutURL
	m.UnauthorizedURL = options.UnauthorizedURL
	m.LoginSuccessfulRedirectURL = options.LoginSuccessfulRedirectURL

	return m.db.Initialize(db_path)
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
		user := u.(User)
		user.Password = pass
		err := m.saveUser(&user)
		if err == nil {
			return &user, nil
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
func (m *Manager) AuthenticatedOnly() gin.HandlerFunc {
	return func(context *gin.Context) {
		session := sessions.Default(context)
		if user := session.Get("user"); user == nil {
			context.Redirect(http.StatusFound, m.LoginURL)
		} else {
			context.Next()
		}
	}
}

func (m *Manager) UnauthenticatedOnly() gin.HandlerFunc {
	return func(context *gin.Context) {
		session := sessions.Default(context)
		if user := session.Get("user"); user != nil {
			context.Redirect(http.StatusFound, m.UnauthorizedURL)
		} else {
			context.Next()
		}
	}
}

func (m *Manager) Login(context *gin.Context) {
	username := context.PostForm("username")
	password := context.PostForm("password")
	if ok := m.IsUserValid(username, password); ok {
		session := sessions.Default(context)
		session.Set("user", m.GetUser(username))
		session.Save()
		context.Redirect(http.StatusFound, m.LoginSuccessfulRedirectURL)
	} else {
		context.Set("Login_error", "invalid username or password")
		context.Redirect(http.StatusFound, m.LoginURL)
	}
}

func (m *Manager) Logout(context *gin.Context) {
	session := sessions.Default(context)
	session.Delete("user")
	session.Save()
	context.Redirect(http.StatusFound, "/")
}

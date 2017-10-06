package main

import (
	"github.com/MA-Heshmatkhah/SimpleAuth"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"path"
	"os"
)

var mySessionManager SimpleAuth.Manager

func main() {
	cwd, _ := os.Getwd()
	mySessionManager.Initialize(path.Join(cwd, "DataBase.db"), &SimpleAuth.Options{
		LoginURL:                   "/users/login",
		LogoutURL:                  "/users/logout",
		CookieName:                 "SimpleAuthCookie",
		UnauthorizedURL:            "/401",
		MaxCookieLifeTime:          86400, //One Day
		LoginSuccessfulRedirectURL: "/home",
	})

	//register a user
	mySessionManager.RegisterNewUser("admin", "123456", []string{"Admins"})

	fmt.Println("Start Development Server")

	gin.SetMode(gin.ReleaseMode)

	// Setup Gin-Gonic
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Set SessionHandler middleware for all routes
	router.Use(mySessionManager.SessionHandler)

	// Load templates
	router.LoadHTMLGlob("./templates/*")

	// Load static files (if they are not hosted by external service)
	router.Static("static/", "./static/")

	// set UnauthenticatedOnly middleware for this group, so only not-logged in users can access to theme
	userRoutes := router.Group("/users", mySessionManager.UnauthenticatedOnly)
	{
		userRoutes.GET("/login", ShowLoginPage)
		// use login  function for login
		userRoutes.POST("/login", mySessionManager.Login)
	}

	// set AuthenticatedOnly middleware for this route, so only logged in user can can access this
	router.GET("/users/logout", mySessionManager.AuthenticatedOnly, mySessionManager.Logout)

	router.GET("/home", mySessionManager.AuthenticatedOnly, ShowUserDashboard)

	// no middleware, so any one can access to this
	router.GET("/", ShowUserHomePage)

	router.GET("/401", Show401)

	// runs the server on port 8080
	router.Run(":8080")

}

func ShowUserDashboard(c *gin.Context) {
	var stat bool
	s, _ := c.Get("session_id")
	if s != nil {
		session := mySessionManager.GetSession(s.(string)).(SimpleAuth.SessionStorage)
		stat = (session.Username != "")
	}
	c.HTML(http.StatusOK, "user-dashboard.html", gin.H{"Message": "Welcome", "is_logged_in": stat,})
}

func ShowUserHomePage(c *gin.Context) {
	var stat bool
	s, _ := c.Get("session_id")
	if s != nil {
		session := mySessionManager.GetSession(s.(string)).(SimpleAuth.SessionStorage)
		stat = (session.Username != "")
	}
	fmt.Println(stat)
	c.HTML(http.StatusOK, "home.html", gin.H{"essage": "Welcome", "is_logged_in": stat,})
}

func Show401(c *gin.Context) {
	var stat bool
	s, _ := c.Get("session_id")
	if s != nil {
		session := mySessionManager.GetSession(s.(string)).(SimpleAuth.SessionStorage)
		stat = (session.Username != "")
	}
	c.HTML(http.StatusOK, "401.html", gin.H{"Message": "You can't access this page", "is_logged_in": stat,})
}

func ShowLoginPage(c *gin.Context) {
	var stat bool
	s, _ := c.Get("session_id")
	if s != nil {
		session := mySessionManager.GetSession(s.(string)).(SimpleAuth.SessionStorage)
		stat = (session.Username != "")
	}
	c.HTML(http.StatusOK, "login.html", gin.H{"is_logged_in": stat,})
}

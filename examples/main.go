package main

import (
	"fmt"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/MA-Heshmatkhah/SimpleAuth"
	"net/http"
	"os"
	"path"
)

var mySessionManager SimpleAuth.Manager

func main() {
	cwd, _ := os.Getwd()
	mySessionManager.Initialize(path.Join(cwd, "DataBase.db"), &SimpleAuth.Options{
		LoginURL:                   "/users/login",
		LogoutURL:                  "/users/logout",
		UnauthorizedURL:            "/401",
		LoginSuccessfulRedirectURL: "/home",
	})

	//register a user
	// You can use this function in your request handler to make a "Sign Up" page
	mySessionManager.RegisterNewUser("admin", "123456", []string{"Admins"})

	fmt.Println("Start Development Server")

	gin.SetMode(gin.ReleaseMode)

	// Setup Gin-Gonic
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// set session using gin-gonic/contrib/sessions
	store := sessions.NewCookieStore([]byte("secret"))
	router.Use(sessions.Sessions("SimpleAuthCookie", store))

	// Load templates
	router.LoadHTMLGlob("./templates/*")

	// Load static files (if they are not hosted by external service)
	router.Static("static/", "./static/")

	// set UnauthenticatedOnly middleware for this group, so only not-logged in users can access to theme
	userRoutes := router.Group("/users", mySessionManager.UnauthenticatedOnly())
	{
		userRoutes.GET("/login", ShowLoginPage)
		//use login  function for login
		userRoutes.POST("/login", mySessionManager.Login)
	}

	// set AuthenticatedOnly middleware for this route, so only logged in user can can access this
	router.GET("/users/logout", mySessionManager.AuthenticatedOnly(), mySessionManager.Logout)

	router.GET("/home", mySessionManager.AuthenticatedOnly(), ShowUserDashboard)

	// no middleware, so any one can access to this
	router.GET("/", ShowHomePage)

	router.GET("/401", Show401)

	// runs the server on port 8080
	router.Run(":8080")

}

func ShowUserDashboard(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user")
	if user != nil {
		user = user.(SimpleAuth.User)
	}
	c.HTML(http.StatusOK, "user-dashboard.html", gin.H{"Message": "Welcome", "user": user,})
}

func ShowHomePage(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user")
	if user != nil {
		user = user.(SimpleAuth.User)
	}
	c.HTML(http.StatusOK, "home.html", gin.H{"user": user,})
}

func Show401(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user")
	if user != nil {
		user = user.(SimpleAuth.User)
	}
	c.HTML(http.StatusOK, "401.html", gin.H{"Message": "You can't access this page", "user": user,})
}

func ShowLoginPage(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user")
	if user != nil {
		user = user.(SimpleAuth.User)
	}
	c.HTML(http.StatusOK, "login.html", gin.H{"user": user,})
}

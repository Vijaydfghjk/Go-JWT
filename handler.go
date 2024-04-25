package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	SecretKey = "your_secret_key"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	router := gin.Default()

	router.POST("/login", loginHandler)

	router.Use(validateToken())

	router.GET("/protected", protectedHandler)

	router.Run(":8080")
}

func loginHandler(c *gin.Context) {
	var credentials Credentials
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the username and password are correct (this is just a simple example)
	if credentials.Username != "Vijay" || credentials.Password != "Vijay@123" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// If credentials are valid, generate a JWT token
	token := jwt.New(jwt.SigningMethodHS256) // for generating the token
	claims := token.Claims.(jwt.MapClaims)   // This allows you to manipulate the claims as a map.
	claims["username"] = credentials.Username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(SecretKey)) // SecretKey basically asiic value that we are converting string
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func validateToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is missing"})
			c.Abort()
			return
		}

		// Split the token string into two parts: "Bearer" and the token itself
		parts := strings.Split(tokenString, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		tokenString = parts[1] // Get the token part

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Make sure the token signing method is valid
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(SecretKey), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Token is valid, you can access claims here if needed
			c.Set("username", claims["username"])
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

func protectedHandler(c *gin.Context) {
	// Retrieve username from context
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{"Hi": "Welcome, " + username.(string)})
}

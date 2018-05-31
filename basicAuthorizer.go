package auth

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/vgmdj/plugins/redis"
	"net/http"
)

// basicAuthorizer stores the casbin handler
type basicAuthorizer struct {
	enforcer *casbin.Enforcer
	userItem string
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *basicAuthorizer) CheckPermission(r http.Request, userId string) bool {
	method := r.Method
	path := r.URL.Path
	return a.enforcer.Enforce(userId, path, method)
}

// RequirePermission returns the 403 Forbidden to the client
func (a *basicAuthorizer) RequirePermission(w http.ResponseWriter) {
	w.WriteHeader(403)
	w.Write([]byte("Forbidden\n"))
}

// RequireToken returns the 400 BadRequest to the client
func (a *basicAuthorizer) RequireToken(w http.ResponseWriter) {
	w.WriteHeader(400)
	w.Write([]byte("Need Token\n"))
}

// LoginExpired returns the 400 BadRequest to the client
func (a *basicAuthorizer) LoginExpired(w http.ResponseWriter) {
	w.WriteHeader(400)
	w.Write([]byte("Login Expired\n"))
}

// GetUserId gets the user name from the request.
func (a *basicAuthorizer) GetUserId(token string) string {
	if !redis.IsOK() {
		fmt.Println("need connect redis first")
		return ""
	}

	userId, _ := redis.GetString(token, a.userItem)
	return userId
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *basicAuthorizer) SetUserId(r *http.Request, userId string) {
	r.SetBasicAuth(userId, BasicPasswd)
}

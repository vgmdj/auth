package auth

import (
	"github.com/casbin/casbin"
	"net/http"
)

// BasicAuthorizer stores the casbin handler
type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *BasicAuthorizer) CheckPermission(p *permission) bool {
	user := a.GetUserName(p.token)
	method := p.method
	path := p.path
	return a.enforcer.Enforce(user, path, method)
}

// RequirePermission returns the 403 Forbidden to the client
func (a *BasicAuthorizer) RequirePermission(w http.ResponseWriter) {
	w.WriteHeader(403)
	w.Write([]byte("403 Forbidden\n"))
}

// RequireToken returns the 400 BadRequest to the client
func (a *BasicAuthorizer) RequireToken(w http.ResponseWriter) {
	w.WriteHeader(400)
	w.Write([]byte("400 Need Token\n"))
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *BasicAuthorizer) GetUserName(token string) string {

	return ""
}

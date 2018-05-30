package auth

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/casbin/casbin"
	//"github.com/garyburd/redigo/redis"
)

type Auth struct {
}

type permission struct {
	token  string
	method string
	path   string
}

// NewAuthorizer returns the authorizer.
// Use a casbin enforcer as input
func (auth *Auth) NewBeegoAuthz(e *casbin.Enforcer, secret, key string) beego.FilterFunc {
	return func(ctx *context.Context) {
		a := &BasicAuthorizer{enforcer: e}

		token, ok := ctx.GetSecureCookie(secret, key)
		if !ok {
			a.RequireToken(ctx.ResponseWriter)
		}

		p := &permission{
			token:  token,
			method: ctx.Request.Method,
			path:   ctx.Request.URL.Path,
		}

		if !a.CheckPermission(p) {
			a.RequirePermission(ctx.ResponseWriter)
		}
	}
}

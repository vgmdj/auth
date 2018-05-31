package auth

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/casbin/casbin"
)

const (
	BasicPasswd = "basic authorizer"
)

type permission struct {
	token  string
	method string
	path   string
}

// NewAuthorizer returns the authorizer.
// Use a casbin enforcer as input
func NewBeegoAuthz(secret, key string, e *casbin.Enforcer) beego.FilterFunc {
	return func(ctx *context.Context) {
		a := &basicAuthorizer{
			enforcer: e,
			userItem: key,
		}

		token, ok := ctx.GetSecureCookie(secret, key)
		if !ok {
			a.RequireToken(ctx.ResponseWriter)
			return
		}

		userId := a.GetUserId(token)
		if userId == "" {
			a.LoginExpired(ctx.ResponseWriter)
			return
		}

		a.SetUserId(ctx.Request, userId)

		if e != nil && !a.CheckPermission(*ctx.Request, userId) {
			a.RequirePermission(ctx.ResponseWriter)
		}
	}
}

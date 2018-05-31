package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/casbin/casbin"
	"github.com/vgmdj/plugins/redis"
	"github.com/vgmdj/utils/chars"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	secret     = "secret"
	userItem   = "sessionInfo"
	sessionExp = 60 * 5
)

func prepare() {
	redis.NewRedis("", "", 0)
}

func setSecureCookie(value string) *http.Cookie {
	cookie := new(http.Cookie)
	vs := base64.URLEncoding.EncodeToString([]byte(value))
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	h := hmac.New(sha1.New, []byte(secret))
	fmt.Fprintf(h, "%s%s", vs, timestamp)
	sig := fmt.Sprintf("%02x", h.Sum(nil))

	cookie.Name = userItem
	cookie.Value = strings.Join([]string{vs, timestamp, sig}, "|")
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(time.Hour * 2)

	return cookie

}

func testRequest(t *testing.T, handler *beego.ControllerRegister, user string, path string, method string, code int) {
	r, _ := http.NewRequest(method, path, nil)
	token := chars.RandomAlphanumeric(16)
	redis.Store(token, userItem, user)
	redis.Expire(token, sessionExp)

	r.AddCookie(setSecureCookie(token))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, w.Code, code)
	}
}

func TestBasic(t *testing.T) {
	prepare()

	handler := beego.NewControllerRegister()

	handler.InsertFilter("*", beego.BeforeRouter,
		NewBeegoAuthz(secret, userItem, casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")))

	handler.Any("*", func(ctx *context.Context) {
		ctx.Output.SetStatus(200)
	})

	testRequest(t, handler, "alice", "/dataset1/resource1", "GET", 200)
	testRequest(t, handler, "alice", "/dataset1/resource1", "POST", 200)
	testRequest(t, handler, "alice", "/dataset1/resource2", "GET", 200)
	testRequest(t, handler, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	prepare()

	handler := beego.NewControllerRegister()

	handler.InsertFilter("*", beego.BeforeRouter,
		NewBeegoAuthz(secret, userItem, casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")))

	handler.Any("*", func(ctx *context.Context) {
		ctx.Output.SetStatus(200)
	})

	testRequest(t, handler, "bob", "/dataset2/resource1", "GET", 200)
	testRequest(t, handler, "bob", "/dataset2/resource1", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/resource1", "DELETE", 200)
	testRequest(t, handler, "bob", "/dataset2/resource2", "GET", 200)
	testRequest(t, handler, "bob", "/dataset2/resource2", "POST", 403)
	testRequest(t, handler, "bob", "/dataset2/resource2", "DELETE", 403)

	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "GET", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "GET", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	prepare()

	handler := beego.NewControllerRegister()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	handler.InsertFilter("*", beego.BeforeRouter, NewBeegoAuthz(secret, userItem, e))

	handler.Any("*", func(ctx *context.Context) {
		ctx.Output.SetStatus(200)
	})

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testRequest(t, handler, "cathy", "/dataset1/item", "GET", 200)
	testRequest(t, handler, "cathy", "/dataset1/item", "POST", 200)
	testRequest(t, handler, "cathy", "/dataset1/item", "DELETE", 200)
	testRequest(t, handler, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "DELETE", 403)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	e.DeleteRolesForUser("cathy")

	testRequest(t, handler, "cathy", "/dataset1/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset1/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset1/item", "DELETE", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "DELETE", 403)
}

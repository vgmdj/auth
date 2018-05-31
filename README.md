# web auth

## casbin authz
- beego
- echo
- gin

## session controller
- redis

## usage
### connect redis

```
    import "github.com/vgmdj/plugins/redis"

    redis.NewRedis("127.0.0.1:6379", "password", 0)
```

### beego
 
```
    handler := beego.NewControllerRegister()
    
    e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
    handler.InsertFilter("*", beego.BeforeRouter, NewBeegoAuthz(secret, userItem, e))
    
    handler.Any("*", func(ctx *context.Context) {
    	ctx.Output.SetStatus(200)
    })
```

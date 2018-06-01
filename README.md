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
    import(
        "github.com/vgmdj/auth"
        "github.com/vgmdj/plugins/redis"
    )
    
    ......

    redis.NewRedis("", "", 0)
    
    ......
    
    filter := auth.NewBeegoAuthz(FilterSecret, FilterUserItem, e)
    
    ns := beego.NewNamespace("/test",		
		beego.NSNamespace("/user",
			beego.NSInclude(
				&controllers.UserController{},
			),

			beego.NSBefore(filter.CasbinFilter),
		),
	)
	
    beego.AddNamespace(ns)
    
    
```

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/ops-cn/admin/app/ginplus"
	"github.com/ops-cn/admin/app/icontext"
	"github.com/ops-cn/common/auth"
	"github.com/ops-cn/common/config"
	"github.com/ops-cn/common/errors"
	"github.com/ops-cn/common/logger"
)

func wrapUserAuthContext(c *gin.Context, userID string) {
	ginplus.SetUserID(c, userID)
	ctx := icontext.NewUserID(c.Request.Context(), userID)
	ctx = logger.NewUserIDContext(ctx, userID)
	c.Request = c.Request.WithContext(ctx)
}

// UserAuthMiddleware 用户授权中间件
func UserAuthMiddleware(a auth.Auther, skippers ...SkipperFunc) gin.HandlerFunc {
	if !config.C.JWTAuth.Enable {
		return func(c *gin.Context) {
			wrapUserAuthContext(c, config.C.Root.UserName)
			c.Next()
		}
	}

	return func(c *gin.Context) {
		if SkipHandler(c, skippers...) {
			c.Next()
			return
		}

		userID, err := a.ParseUserID(c.Request.Context(), ginplus.GetToken(c))
		if err != nil {
			if err == auth.ErrInvalidToken {
				if config.C.IsDebugMode() {
					wrapUserAuthContext(c, config.C.Root.UserName)
					c.Next()
					return
				}
				ginplus.ResError(c, errors.ErrInvalidToken)
				return
			}
			ginplus.ResError(c, errors.WithStack(err))
			return
		}

		wrapUserAuthContext(c, userID)
		c.Next()
	}
}

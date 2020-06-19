package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/ops-cn/common/config"
)

// CORSMiddleware 跨域请求中间件
func CORSMiddleware() gin.HandlerFunc {
	cfg := config.C.CORS
	return cors.New(cors.Config{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     cfg.AllowMethods,
		AllowHeaders:     cfg.AllowHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           time.Second * time.Duration(cfg.MaxAge),
	})
}

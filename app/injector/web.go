package injector

import (
	"github.com/gin-gonic/gin"
	"github.com/ops-cn/admin/app/middleware"
	"github.com/ops-cn/admin/app/router"

	"github.com/ops-cn/common/config"
	"github.com/ops-cn/common/thirdparty/gzip"
	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/gin-swagger/swaggerFiles"
)

var app *gin.Engine

func GetRouter() *gin.Engine {
	return app
}

// InitGinEngine 初始化gin引擎
func InitGinEngine(r router.IRouter) *gin.Engine {
	gin.SetMode(config.C.RunMode)
	/*re, err := reporter.NewGRPCReporter("192.168.1.156:11800")
	if err != nil {
		log.Fatalf("new reporter error %v \n", err)
	}
	//defer re.Close()

	tracer, err := go2sky.NewTracer("gin-server", go2sky.WithReporter(re))
	if err != nil {
		log.Fatalf("create tracer error %v \n", err)
	}*/

	app = gin.New()
	app.NoMethod(middleware.NoMethodHandler())
	app.NoRoute(middleware.NoRouteHandler())

	prefixes := r.Prefixes()
	//app.Use(g.Middleware(app, tracer))
	// Trace ID
	app.Use(middleware.TraceMiddleware(middleware.AllowPathPrefixNoSkipper(prefixes...)))

	// Copy body
	app.Use(middleware.CopyBodyMiddleware(middleware.AllowPathPrefixNoSkipper(prefixes...)))

	// Access logger
	app.Use(middleware.LoggerMiddleware(middleware.AllowPathPrefixNoSkipper(prefixes...)))

	// Recover
	app.Use(middleware.RecoveryMiddleware())

	// CORS
	if config.C.CORS.Enable {
		app.Use(middleware.CORSMiddleware())
	}

	// GZIP
	if config.C.GZIP.Enable {
		app.Use(gzip.Gzip(gzip.BestCompression,
			gzip.WithExcludedExtensions(config.C.GZIP.ExcludedExtentions),
			gzip.WithExcludedPaths(config.C.GZIP.ExcludedPaths),
		))
	}

	// Router register
	r.Register(app)

	// Swagger
	if config.C.Swagger {
		app.GET("/api/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Website
	if dir := config.C.WWW; dir != "" {
		app.Use(middleware.WWWMiddleware(dir, middleware.AllowPathPrefixSkipper(prefixes...)))
	}

	return app
}

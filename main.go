package main

import (
	"context"
	"github.com/micro/cli/v2"
	"github.com/micro/go-micro/v2/web"
	"github.com/ops-cn/admin/app"
	"github.com/ops-cn/admin/app/injector"
	"github.com/ops-cn/common/logger"
)

// VERSION 版本号，可以通过编译的方式指定版本号：go build -ldflags "-X main.VERSION=x.x.x"
var VERSION = "6.3.1"

func main() {
	logger.SetVersion(VERSION)
	ctx := logger.NewTraceIDContext(context.Background(), "main")

	service := web.NewService(
		web.Name("ops.cn.api"),
		web.Flags(
			&cli.StringFlag{
				Name:     "conf",
				Aliases:  []string{"c"},
				Usage:    "配置文件(.json,.yaml,.toml)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "model",
				Aliases:  []string{"m"},
				Usage:    "casbin的访问控制模型(.conf)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "menu",
				Usage: "初始化菜单数据配置文件(.yaml)",
			},
			&cli.StringFlag{
				Name:  "www",
				Usage: "静态站点目录",
			},
		),
		web.Address(":10087"),
	)
	service.Init(
		web.Action(func(c *cli.Context) {
			app.Init(
				ctx,
				app.SetConfigFile(c.String("conf")),
				app.SetModelFile(c.String("model")),
				app.SetWWWDir(c.String("www")),
				app.SetMenuFile(c.String("menu")),
				app.SetVersion(VERSION))
		}),
	)
	service.Handle("/", injector.GetRouter())
	if err := service.Run(); err != nil {
		panic(err)
	}

}

/*func newWebCmd(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:  "web",
		Usage: "运行web服务",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "conf",
				Aliases:  []string{"c"},
				Usage:    "配置文件(.json,.yaml,.toml)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "model",
				Aliases:  []string{"m"},
				Usage:    "casbin的访问控制模型(.conf)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "menu",
				Usage: "初始化菜单数据配置文件(.yaml)",
			},
			&cli.StringFlag{
				Name:  "www",
				Usage: "静态站点目录",
			},
		},
		Action: func(c *cli.Context) error {
			return app.Run(ctx,
				app.SetConfigFile(c.String("conf")),
				app.SetModelFile(c.String("model")),
				app.SetWWWDir(c.String("www")),
				app.SetMenuFile(c.String("menu")),
				app.SetVersion(VERSION))
		},
	}
}*/

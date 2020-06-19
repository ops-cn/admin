package handler

import (
	"context"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/wire"
	"github.com/micro/go-micro/v2/metadata"
	"github.com/ops-cn/admin/app/bll"
	"github.com/ops-cn/admin/app/model"
	"github.com/ops-cn/common/auth"
	"github.com/ops-cn/common/captcha"
	"github.com/ops-cn/common/errors"
	proto "github.com/ops-cn/proto/admin/login"
	"github.com/ops-cn/proto/unified"
)

type LoginService struct{}

var LoginSet = wire.NewSet(wire.Struct(new(Login), "*"), wire.Bind(new(bll.ILogin), new(*Login)))

// Login 登录管理
type Login struct {
	Auth            auth.Auther
	UserModel       model.IUser
	UserRoleModel   model.IUserRole
	RoleModel       model.IRole
	RoleMenuModel   model.IRoleMenu
	MenuModel       model.IMenu
	MenuActionModel model.IMenuAction
}

func (loginService *LoginService) GetCaptcha(ctx context.Context, req *proto.Length, res *unified.Response) error {

	captchaID := captcha.NewLen(int(req.GetLength()))

	item := &proto.LoginCaptcha{
		CaptchaID: captchaID,
	}
	res.Status = 200
	res.Desc = "查询成功"
	res.Items, _ = ptypes.MarshalAny(item)

	return nil
}

func (loginService *LoginService) ResCaptcha(ctx context.Context, req *proto.LoginCaptcha, res *unified.Response) error {
	md, ok := metadata.FromContext(ctx)
	err := captcha.WriteImage(w, captchaID, width, height)
	if err != nil {
		if err == captcha.ErrNotFound {
			return errors.ErrNotFound
		}
		return errors.WithStack(err)
	}
	res.
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "image/png")
	return nil
}

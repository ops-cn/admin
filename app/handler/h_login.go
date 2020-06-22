package handler

import (
	"context"
	"github.com/golang/protobuf/ptypes"
	"github.com/ops-cn/common/config"
	loginPB "github.com/ops-cn/proto/admin/login"
	userPB "github.com/ops-cn/proto/admin/user"
	"github.com/ops-cn/proto/unified"
	"sort"

	"github.com/google/wire"
	"github.com/ops-cn/admin/app/bll"
	"github.com/ops-cn/admin/app/model"
	"github.com/ops-cn/common/auth"
	"github.com/ops-cn/common/errors"
	"github.com/ops-cn/common/schema"
	"github.com/ops-cn/common/thirdparty/captcha"
	"github.com/ops-cn/common/util"
)

//type LoginService struct{}

var LoginSet = wire.NewSet(wire.Struct(new(LoginService), "*"), wire.Bind(new(bll.ILogin), new(*LoginService)))

// Login 登录管理
type LoginService struct {
	Auth            auth.Auther
	UserModel       model.IUser
	UserRoleModel   model.IUserRole
	RoleModel       model.IRole
	RoleMenuModel   model.IRoleMenu
	MenuModel       model.IMenu
	MenuActionModel model.IMenuAction
}

func (loginService *LoginService) GetCaptcha(ctx context.Context, req *loginPB.Length, res *unified.Response) error {

	captchaID := captcha.NewLen(int(req.GetLength()))

	item := &loginPB.LoginCaptcha{
		CaptchaID: captchaID,
	}
	res.Status = 200
	res.Desc = "查询成功"
	res.Items, _ = ptypes.MarshalAny(item)

	return nil
}

func GetRootUser() *userPB.User {
	user := config.C.Root
	return &userPB.User{
		ID:       user.UserName,
		UserName: user.UserName,
		RealName: user.RealName,
		Password: util.MD5HashString(user.Password),
	}
}

// Verify 登录验证
func (loginService *LoginService) Verify(ctx context.Context, req *loginPB.LoginParam, res *unified.Response) error {
	// 检查是否是超级用户
	root := GetRootUser()

	if req.UserName == root.UserName && root.Password == req.Password {
		res.Items, _ = ptypes.MarshalAny(root)
		return nil
	}

	result, err := loginService.UserModel.Query(ctx, schema.UserQueryParam{
		UserName: req.UserName,
	})
	if err != nil {
		return err
	} else if len(result.Data) == 0 {
		return errors.ErrInvalidUserName
	}

	item := result.Data[0]
	if item.Password != util.SHA1HashString(req.Password) {
		return errors.ErrInvalidPassword
	} else if item.Status != 1 {
		return errors.ErrUserDisable
	}
	res.Items, _ = ptypes.MarshalAny(item)
	return nil
}

// GenerateToken 生成令牌
func (a *Login) GenerateToken(ctx context.Context, userID string) (*schema.LoginTokenInfo, error) {
	tokenInfo, err := a.Auth.GenerateToken(ctx, userID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	item := &schema.LoginTokenInfo{
		AccessToken: tokenInfo.GetAccessToken(),
		TokenType:   tokenInfo.GetTokenType(),
		ExpiresAt:   tokenInfo.GetExpiresAt(),
	}
	return item, nil
}

// DestroyToken 销毁令牌
func (a *Login) DestroyToken(ctx context.Context, tokenString string) error {
	err := a.Auth.DestroyToken(ctx, tokenString)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (a *Login) checkAndGetUser(ctx context.Context, userID string) (*schema.User, error) {
	user, err := a.UserModel.Get(ctx, userID)
	if err != nil {
		return nil, err
	} else if user == nil {
		return nil, errors.ErrInvalidUser
	} else if user.Status != 1 {
		return nil, errors.ErrUserDisable
	}
	return user, nil
}

// GetLoginInfo 获取当前用户登录信息
func (a *Login) GetLoginInfo(ctx context.Context, userID string) (*schema.UserLoginInfo, error) {
	if isRoot := schema.CheckIsRootUser(ctx, userID); isRoot {
		root := schema.GetRootUser()
		loginInfo := &schema.UserLoginInfo{
			UserName: root.UserName,
			RealName: root.RealName,
		}
		return loginInfo, nil
	}

	user, err := a.checkAndGetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	info := &schema.UserLoginInfo{
		UserID:   user.ID,
		UserName: user.UserName,
		RealName: user.RealName,
	}

	userRoleResult, err := a.UserRoleModel.Query(ctx, schema.UserRoleQueryParam{
		UserID: userID,
	})
	if err != nil {
		return nil, err
	}

	if roleIDs := userRoleResult.Data.ToRoleIDs(); len(roleIDs) > 0 {
		roleResult, err := a.RoleModel.Query(ctx, schema.RoleQueryParam{
			IDs:    roleIDs,
			Status: 1,
		})
		if err != nil {
			return nil, err
		}
		info.Roles = roleResult.Data
	}

	return info, nil
}

// QueryUserMenuTree 查询当前用户的权限菜单树
func (a *Login) QueryUserMenuTree(ctx context.Context, userID string) (schema.MenuTrees, error) {
	isRoot := schema.CheckIsRootUser(ctx, userID)
	// 如果是root用户，则查询所有显示的菜单树
	if isRoot {
		result, err := a.MenuModel.Query(ctx, schema.MenuQueryParam{
			Status: 1,
		}, schema.MenuQueryOptions{
			OrderFields: schema.NewOrderFields(schema.NewOrderField("sequence", schema.OrderByDESC)),
		})
		if err != nil {
			return nil, err
		}

		menuActionResult, err := a.MenuActionModel.Query(ctx, schema.MenuActionQueryParam{})
		if err != nil {
			return nil, err
		}
		return result.Data.FillMenuAction(menuActionResult.Data.ToMenuIDMap()).ToTree(), nil
	}

	userRoleResult, err := a.UserRoleModel.Query(ctx, schema.UserRoleQueryParam{
		UserID: userID,
	})
	if err != nil {
		return nil, err
	} else if len(userRoleResult.Data) == 0 {
		return nil, errors.ErrNoPerm
	}

	roleMenuResult, err := a.RoleMenuModel.Query(ctx, schema.RoleMenuQueryParam{
		RoleIDs: userRoleResult.Data.ToRoleIDs(),
	})
	if err != nil {
		return nil, err
	} else if len(roleMenuResult.Data) == 0 {
		return nil, errors.ErrNoPerm
	}

	menuResult, err := a.MenuModel.Query(ctx, schema.MenuQueryParam{
		IDs:    roleMenuResult.Data.ToMenuIDs(),
		Status: 1,
	})
	if err != nil {
		return nil, err
	} else if len(menuResult.Data) == 0 {
		return nil, errors.ErrNoPerm
	}

	mData := menuResult.Data.ToMap()
	var qIDs []string
	for _, pid := range menuResult.Data.SplitParentIDs() {
		if _, ok := mData[pid]; !ok {
			qIDs = append(qIDs, pid)
		}
	}

	if len(qIDs) > 0 {
		pmenuResult, err := a.MenuModel.Query(ctx, schema.MenuQueryParam{
			IDs: menuResult.Data.SplitParentIDs(),
		})
		if err != nil {
			return nil, err
		}
		menuResult.Data = append(menuResult.Data, pmenuResult.Data...)
	}

	sort.Sort(menuResult.Data)
	menuActionResult, err := a.MenuActionModel.Query(ctx, schema.MenuActionQueryParam{
		IDs: roleMenuResult.Data.ToActionIDs(),
	})
	if err != nil {
		return nil, err
	}
	return menuResult.Data.FillMenuAction(menuActionResult.Data.ToMenuIDMap()).ToTree(), nil
}

// UpdatePassword 更新当前用户登录密码
func (a *Login) UpdatePassword(ctx context.Context, userID string, params schema.UpdatePasswordParam) error {
	if schema.CheckIsRootUser(ctx, userID) {
		return errors.New400Response("root用户不允许更新密码")
	}

	user, err := a.checkAndGetUser(ctx, userID)
	if err != nil {
		return err
	} else if util.SHA1HashString(params.OldPassword) != user.Password {
		return errors.New400Response("旧密码不正确")
	}

	params.NewPassword = util.SHA1HashString(params.NewPassword)
	return a.UserModel.UpdatePassword(ctx, userID, params.NewPassword)
}

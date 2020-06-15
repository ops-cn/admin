package model

import (
	"context"

	"github.com/google/wire"
	"github.com/jinzhu/gorm"
	"github.com/ops-cn/admin/app/icontext"
	"github.com/ops-cn/admin/app/model"
	"github.com/ops-cn/common/errors"
)

var _ model.ITrans = new(Trans)

// TransSet 注入Trans
var TransSet = wire.NewSet(wire.Struct(new(Trans), "*"), wire.Bind(new(model.ITrans), new(*Trans)))

// Trans 事务管理
type Trans struct {
	DB *gorm.DB
}

// Exec 执行事务
func (a *Trans) Exec(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := icontext.FromTrans(ctx); ok {
		return fn(ctx)
	}

	err := a.DB.Transaction(func(db *gorm.DB) error {
		return fn(icontext.NewTrans(ctx, db))
	})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

package handler

import "github.com/google/wire"

// BllSet bll注入
var BllSet = wire.NewSet(
	LoginSet,
	MenuSet,
	RoleSet,
	UserSet,
)

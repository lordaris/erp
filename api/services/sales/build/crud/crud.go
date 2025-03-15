// Package crud binds the crud domain set of routes into the specified app.
package crud

import (
	"github.com/lordaris/erp/app/domain/checkapp"
	"github.com/lordaris/erp/app/domain/productapp"
	"github.com/lordaris/erp/app/domain/userapp"
	"github.com/lordaris/erp/app/sdk/mux"
	"github.com/lordaris/erp/foundation/web"
)

// Routes constructs the add value which provides the implementation of
// of RouteAdder for specifying what routes to bind to this instance.
func Routes() add {
	return add{}
}

type add struct{}

// Add implements the RouterAdder interface.
func (add) Add(app *web.App, cfg mux.Config) {
	checkapp.Routes(app, checkapp.Config{
		Build: cfg.Build,
		Log:   cfg.Log,
		DB:    cfg.DB,
	})

	// homeapp.Routes(app, homeapp.Config{
	// 	HomeBus:    cfg.BusConfig.HomeBus,
	// 	AuthClient: cfg.SalesConfig.AuthClient,
	// })
	//
	productapp.Routes(app, productapp.Config{
		ProductBus: cfg.BusConfig.ProductBus,
		AuthClient: cfg.SalesConfig.AuthClient,
	})

	// tranapp.Routes(app, tranapp.Config{
	// 	UserBus:    cfg.BusConfig.UserBus,
	// 	ProductBus: cfg.BusConfig.ProductBus,
	// 	Log:        cfg.Log,
	// 	AuthClient: cfg.SalesConfig.AuthClient,
	// 	DB:         cfg.DB,
	// })
	//
	userapp.Routes(app, userapp.Config{
		UserBus:    cfg.BusConfig.UserBus,
		AuthClient: cfg.SalesConfig.AuthClient,
	})
}

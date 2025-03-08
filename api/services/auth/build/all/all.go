// Package all binds all the routes into the specified app.
package all

import (
	"time"

	"github.com/lordaris/erp/app/domain/authapp"
	"github.com/lordaris/erp/app/domain/checkapp"
	"github.com/lordaris/erp/app/sdk/mux"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/domain/userbus/stores/usercache"
	"github.com/lordaris/erp/business/domain/userbus/stores/userdb"
	"github.com/lordaris/erp/business/sdk/delegate"
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

	// Construct the business domain packages we need here so we are using the
	// sames instances for the different set of domain apis.
	delegate := delegate.New(cfg.Log)
	userBus := userbus.NewBusiness(cfg.Log, delegate, usercache.NewStore(cfg.Log, userdb.NewStore(cfg.Log, cfg.DB), time.Minute))

	checkapp.Routes(app, checkapp.Config{
		Build: cfg.Build,
		Log:   cfg.Log,
		DB:    cfg.DB,
	})

	authapp.Routes(app, authapp.Config{
		UserBus: userBus,
		Auth:    cfg.Auth,
	})
}

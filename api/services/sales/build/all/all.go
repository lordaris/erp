// Package all binds all the routes into the specified app.
package all

import (
	"time"

	"github.com/lordaris/erp/app/domain/checkapp"
	"github.com/lordaris/erp/app/domain/homeapp"
	"github.com/lordaris/erp/app/domain/inventoryapp"
	"github.com/lordaris/erp/app/domain/productapp"
	"github.com/lordaris/erp/app/domain/rawapp"
	"github.com/lordaris/erp/app/domain/tranapp"
	"github.com/lordaris/erp/app/domain/userapp"
	"github.com/lordaris/erp/app/domain/vproductapp"
	"github.com/lordaris/erp/app/sdk/mux"
	"github.com/lordaris/erp/business/domain/homebus"
	"github.com/lordaris/erp/business/domain/homebus/stores/homedb"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/domain/inventorybus/stores/inventorydb"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/productbus/stores/productdb"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/domain/userbus/stores/usercache"
	"github.com/lordaris/erp/business/domain/userbus/stores/userdb"
	"github.com/lordaris/erp/business/domain/vproductbus"
	"github.com/lordaris/erp/business/domain/vproductbus/stores/vproductdb"
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
	productBus := productbus.NewBusiness(cfg.Log, userBus, delegate, productdb.NewStore(cfg.Log, cfg.DB))
	homeBus := homebus.NewBusiness(cfg.Log, userBus, delegate, homedb.NewStore(cfg.Log, cfg.DB))
	vproductBus := vproductbus.NewBusiness(vproductdb.NewStore(cfg.Log, cfg.DB))
	inventoryBus := inventorybus.NewBusiness(cfg.Log, productBus, delegate, inventorydb.NewStore(cfg.Log, cfg.DB))

	checkapp.Routes(app, checkapp.Config{
		Build: cfg.Build,
		Log:   cfg.Log,
		DB:    cfg.DB,
	})

	homeapp.Routes(app, homeapp.Config{
		Log:        cfg.Log,
		HomeBus:    homeBus,
		AuthClient: cfg.AuthClient,
	})

	inventoryapp.Routes(app, inventoryapp.Config{
		Log:          cfg.Log,
		InventoryBus: inventoryBus,
		AuthClient:   cfg.AuthClient,
	})

	productapp.Routes(app, productapp.Config{
		Log:        cfg.Log,
		ProductBus: productBus,
		AuthClient: cfg.AuthClient,
	})

	rawapp.Routes(app)

	tranapp.Routes(app, tranapp.Config{
		Log:        cfg.Log,
		DB:         cfg.DB,
		UserBus:    userBus,
		ProductBus: productBus,
		AuthClient: cfg.AuthClient,
	})

	userapp.Routes(app, userapp.Config{
		Log:        cfg.Log,
		UserBus:    userBus,
		AuthClient: cfg.AuthClient,
	})

	vproductapp.Routes(app, vproductapp.Config{
		Log:         cfg.Log,
		UserBus:     userBus,
		VProductBus: vproductBus,
		AuthClient:  cfg.AuthClient,
	})
}

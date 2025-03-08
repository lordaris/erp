package inventoryapp

import (
	"net/http"

	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/app/sdk/authclient"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/foundation/logger"
	"github.com/lordaris/erp/foundation/web"
)

// Config contains all the mandatory systems required by handlers.
type Config struct {
	Log          *logger.Logger
	InventoryBus *inventorybus.Business
	AuthClient   *authclient.Client
}

// Routes adds specific routes for this group.
func Routes(app *web.App, cfg Config) {
	const version = "v1"

	authen := mid.Authenticate(cfg.AuthClient)
	ruleAny := mid.Authorize(cfg.AuthClient, auth.RuleAny)
	ruleUserOnly := mid.Authorize(cfg.AuthClient, auth.RuleUserOnly)
	ruleAuthorizeInventory := mid.AuthorizeInventory(cfg.AuthClient, cfg.InventoryBus)

	api := newApp(cfg.InventoryBus)

	app.HandlerFunc(http.MethodGet, version, "/inventories", api.query, authen, ruleAny)
	app.HandlerFunc(http.MethodGet, version, "/inventories/{inventory_id}", api.queryByID, authen, ruleAuthorizeInventory)
	app.HandlerFunc(http.MethodPost, version, "/inventories", api.create, authen, ruleUserOnly)
	app.HandlerFunc(http.MethodPut, version, "/inventories/{inventory_id}", api.update, authen, ruleAuthorizeInventory)
	app.HandlerFunc(http.MethodDelete, version, "/inventories/{inventory_id}", api.delete, authen, ruleAuthorizeInventory)
}

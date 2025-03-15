package productapp

import (
	"net/http"

	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/app/sdk/authclient"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/foundation/logger"
	"github.com/lordaris/erp/foundation/web"
)

// Config contains all the mandatory systems required by handlers.
type Config struct {
	Log        *logger.Logger
	ProductBus *productbus.Business
	AuthClient *authclient.Client
}

// Routes adds specific routes for this group.
func Routes(app *web.App, cfg Config) {
	const version = "v1"

	authen := mid.Authenticate(cfg.AuthClient)
	ruleAny := mid.Authorize(cfg.AuthClient, auth.RuleAny)
	ruleUserOnly := mid.Authorize(cfg.AuthClient, auth.RuleUserOnly)
	ruleAuthorizeProduct := mid.AuthorizeProduct(cfg.AuthClient, cfg.ProductBus)
	ruleAuthorizeVariant := mid.AuthorizeVariant(cfg.AuthClient, cfg.ProductBus)

	api := newApp(cfg.ProductBus)

	// Product routes
	app.HandlerFunc(http.MethodGet, version, "/products", api.query, authen, ruleAny)
	app.HandlerFunc(http.MethodGet, version, "/products/{product_id}", api.queryByID, authen, ruleAuthorizeProduct)
	app.HandlerFunc(http.MethodPost, version, "/products", api.create, authen, ruleUserOnly)
	app.HandlerFunc(http.MethodPut, version, "/products/{product_id}", api.update, authen, ruleAuthorizeProduct)
	app.HandlerFunc(http.MethodDelete, version, "/products/{product_id}", api.delete, authen, ruleAuthorizeProduct)

	// Product variant routes
	app.HandlerFunc(http.MethodPost, version, "/products/{product_id}/variants", api.createVariant, authen, ruleAuthorizeProduct)
	app.HandlerFunc(http.MethodPut, version, "/products/variants/{variant_id}", api.updateVariant, authen, ruleAuthorizeVariant)
	app.HandlerFunc(http.MethodDelete, version, "/products/variants/{variant_id}", api.deleteVariant, authen, ruleAuthorizeVariant)

	// Add search endpoint
	app.HandlerFunc(http.MethodGet, version, "/products/search", api.search, authen, ruleAny)

	// Add image management routes
	app.HandlerFunc(http.MethodPost, version, "/products/{product_id}/images", api.addImage, authen, ruleAuthorizeProduct)
	app.HandlerFunc(http.MethodDelete, version, "/products/{product_id}/images/{image_id}", api.removeImage, authen, ruleAuthorizeProduct)
	app.HandlerFunc(http.MethodPut, version, "/products/{product_id}/images/{image_id}", api.updateImage, authen, ruleAuthorizeProduct)
}

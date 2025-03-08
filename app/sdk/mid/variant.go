package mid

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/app/sdk/authclient"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/foundation/web"
)

// ctxProductVariantKey represents the type of value for the context key.
type ctxProductVariantKey int

// key is used to store/retrieve a ProductVariant value from a context.Context.
const productVariantKey ctxProductVariantKey = 1

// GetProductVariant returns the product variant from the context.
func GetProductVariant(ctx context.Context) (productbus.ProductVariant, error) {
	v, ok := ctx.Value(productVariantKey).(productbus.ProductVariant)
	if !ok {
		return productbus.ProductVariant{}, errors.New("product variant value missing from context")
	}
	return v, nil
}

// AuthorizeVariant validates that a user has access to the specified product variant.
func AuthorizeVariant(client *authclient.Client, productBus *productbus.Business) web.Middleware {
	m := func(handler web.Handler) web.Handler {
		h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			variantIDStr := web.Param(r, "variant_id")
			if variantIDStr == "" {
				return web.Encode(ctx, w, errs.Newf(errs.InvalidArgument, "missing variant_id in path"), http.StatusBadRequest)
			}

			variantID, err := uuid.Parse(variantIDStr)
			if err != nil {
				return web.Encode(ctx, w, errs.Newf(errs.InvalidArgument, "invalid variant_id: %s", err), http.StatusBadRequest)
			}

			// Get the variant first
			variant, err := productBus.QueryVariantByID(ctx, variantID)
			if err != nil {
				if errors.Is(err, productbus.ErrNotFound) {
					return web.Encode(ctx, w, errs.Newf(errs.NotFound, "variant not found: %s", variantID), http.StatusNotFound)
				}
				return fmt.Errorf("query variant: variantID[%s]: %w", variantID, err)
			}

			// Get the associated product
			product, err := productBus.QueryByID(ctx, variant.ProductID)
			if err != nil {
				if errors.Is(err, productbus.ErrNotFound) {
					return web.Encode(ctx, w, errs.Newf(errs.NotFound, "product not found: %s", variant.ProductID), http.StatusNotFound)
				}
				return fmt.Errorf("query product: productID[%s]: %w", variant.ProductID, err)
			}

			// Get the claims from the request context
			claims, err := auth.GetClaims(ctx)
			if err != nil {
				return web.Encode(ctx, w, errs.Newf(errs.Unauthorized, "you are not authorized for this action"), http.StatusUnauthorized)
			}

			// If the user is an admin or owns the product, they have access
			if auth.HasRole(claims, auth.RoleAdmin) {
				ctx = context.WithValue(ctx, productVariantKey, variant)
				return handler(ctx, w, r)
			}

			// If not an admin, check if user owns the product
			if product.UserID.String() != claims.Subject {
				return web.Encode(ctx, w, errs.Newf(errs.Unauthorized, "you are not authorized for this action"), http.StatusUnauthorized)
			}

			ctx = context.WithValue(ctx, productVariantKey, variant)
			return handler(ctx, w, r)
		}

		return h
	}

	return m
}

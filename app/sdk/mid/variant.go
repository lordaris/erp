package mid

import (
	"context"
	"errors"
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
func AuthorizeVariant(client *authclient.Client, productBus *productbus.Business) web.MidFunc {
	m := func(next web.HandlerFunc) web.HandlerFunc {
		h := func(ctx context.Context, r *http.Request) web.Encoder {
			variantIDStr := web.Param(r, "variant_id")
			if variantIDStr == "" {
				return errs.Newf(errs.InvalidArgument, "missing variant_id in path")
			}

			variantID, err := uuid.Parse(variantIDStr)
			if err != nil {
				return errs.Newf(errs.InvalidArgument, "invalid variant_id: %s", err)
			}

			// Query variants and their product
			variant, err := productBus.QueryVariantByID(ctx, variantID)
			if err != nil {
				if errors.Is(err, productbus.ErrNotFound) {
					return errs.Newf(errs.NotFound, "variant not found: %s", variantID)
				}
				return errs.Newf(errs.Internal, "query variant: variantID[%s]: %s", variantID, err)
			}

			// Get the product that owns this variant
			product, err := productBus.QueryByID(ctx, variant.ProductID)
			if err != nil {
				if errors.Is(err, productbus.ErrNotFound) {
					return errs.Newf(errs.NotFound, "product not found: %s", variant.ProductID)
				}
				return errs.Newf(errs.Internal, "query product: productID[%s]: %s", variant.ProductID, err)
			}

			// Authorize with admin-or-subject rule
			auth := authclient.Authorize{
				UserID: product.UserID,
				Claims: GetClaims(ctx),
				Rule:   auth.RuleAdminOrSubject,
			}

			if err := client.Authorize(ctx, auth); err != nil {
				return errs.New(errs.Unauthenticated, err)
			}

			ctx = setProductVariant(ctx, variant)
			return next(ctx, r)
		}

		return h
	}

	return m
}

// Helper function to store variant in context
func setProductVariant(ctx context.Context, variant productbus.ProductVariant) context.Context {
	return context.WithValue(ctx, productVariantKey, variant)
}

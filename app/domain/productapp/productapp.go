package productapp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/foundation/web"
)

type app struct {
	productbus *productbus.Business
}

func newApp(productBus *productbus.Business) *app {
	return &app{
		productBus: productBus,
	}
}

// Enhanced app implementation to include new product model features

func (a *app) queryBySKU(ctx context.Context, r *http.Request) web.Encoder {
	sku := web.Param(r, "sku")
	if sku == "" {
		return errs.NewFieldErrors("sku", fmt.Errorf("missing sku"))
	}

	prd, err := a.productBus.QueryBySKU(ctx, sku)
	if err != nil {
		return errs.Newf(errs.Internal, "querybysku: %s", err)
	}

	return toAppProduct(prd)
}

func (a *app) queryByUPC(ctx context.Context, r *http.Request) web.Encoder {
	upc := web.Param(r, "upc")
	if upc == "" {
		return errs.NewFieldErrors("upc", fmt.Errorf("missing upc"))
	}

	prd, err := a.productBus.QueryByUPC(ctx, upc)
	if err != nil {
		return errs.Newf(errs.Internal, "querybyupc: %s", err)
	}

	return toAppProduct(prd)
}

func (a *app) queryByCategory(ctx context.Context, r *http.Request) web.Encoder {
	categoryName := web.Param(r, "category")
	if categoryName == "" {
		return errs.NewFieldErrors("category", fmt.Errorf("missing category"))
	}

	qp := parseQueryParams(r)

	page, err := page.Parse(qp.Page, qp.Rows)
	if err != nil {
		return errs.NewFieldErrors("page", err)
	}

	prds, err := a.productBus.QueryByCategory(ctx, categoryName, page)
	if err != nil {
		return errs.Newf(errs.Internal, "querybycategory: %s", err)
	}

	return toAppProducts(prds)
}

// Variant operations
func (a *app) createVariant(ctx context.Context, r *http.Request) web.Encoder {
	var app NewProductVariant
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	nv, err := toBusNewProductVariant(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	// Verify the user has access to the product
	prd, err := a.productBus.QueryByID(ctx, nv.ProductID)
	if err != nil {
		return errs.Newf(errs.Internal, "product.querybyid: %s: %w", nv.ProductID, err)
	}

	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "getuserid: %w", err)
	}

	if prd.UserID != userID {
		return errs.Newf(errs.Unauthenticated, "user does not own this product")
	}

	variant, err := a.productBus.CreateVariant(ctx, nv)
	if err != nil {
		return errs.Newf(errs.Internal, "create variant: %s", err)
	}

	return toAppProductVariant(variant)
}

func (a *app) updateVariant(ctx context.Context, r *http.Request) web.Encoder {
	var app UpdateProductVariant
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	variantID, err := uuid.Parse(web.Param(r, "variant_id"))
	if err != nil {
		return errs.NewFieldErrors("variant_id", err)
	}

	uv, err := toBusUpdateProductVariant(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	// Get the variant to update
	variant, err := a.productBus.QueryVariantByID(ctx, variantID)
	if err != nil {
		return errs.Newf(errs.Internal, "queryvariantbyid: %s: %w", variantID, err)
	}

	// Verify the user has access to the product
	prd, err := a.productBus.QueryByID(ctx, variant.ProductID)
	if err != nil {
		return errs.Newf(errs.Internal, "product.querybyid: %s: %w", variant.ProductID, err)
	}

	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "getuserid: %w", err)
	}

	if prd.UserID != userID {
		return errs.Newf(errs.Unauthenticated, "user does not own this product")
	}

	updVariant, err := a.productBus.UpdateVariant(ctx, variant, uv)
	if err != nil {
		return errs.Newf(errs.Internal, "update variant: %s", err)
	}

	return toAppProductVariant(updVariant)
}

func (a *app) deleteVariant(ctx context.Context, r *http.Request) web.Encoder {
	variantID, err := uuid.Parse(web.Param(r, "variant_id"))
	if err != nil {
		return errs.NewFieldErrors("variant_id", err)
	}

	// Get the variant to delete
	variant, err := a.productBus.QueryVariantByID(ctx, variantID)
	if err != nil {
		return errs.Newf(errs.Internal, "queryvariantbyid: %s: %w", variantID, err)
	}

	// Verify the user has access to the product
	prd, err := a.productBus.QueryByID(ctx, variant.ProductID)
	if err != nil {
		return errs.Newf(errs.Internal, "product.querybyid: %s: %w", variant.ProductID, err)
	}

	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "getuserid: %w", err)
	}

	if prd.UserID != userID {
		return errs.Newf(errs.Unauthenticated, "user does not own this product")
	}

	if err := a.productBus.DeleteVariant(ctx, variant); err != nil {
		return errs.Newf(errs.Internal, "delete variant: %s", err)
	}

	return nil
}

func (a *app) queryVariants(ctx context.Context, r *http.Request) web.Encoder {
	productID, err := uuid.Parse(web.Param(r, "product_id"))
	if err != nil {
		return errs.NewFieldErrors("product_id", err)
	}

	// Verify the user has access to the product
	prd, err := a.productBus.QueryByID(ctx, productID)
	if err != nil {
		return errs.Newf(errs.Internal, "product.querybyid: %s: %w", productID, err)
	}

	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "getuserid: %w", err)
	}

	if prd.UserID != userID {
		return errs.Newf(errs.Unauthenticated, "user does not own this product")
	}

	variants, err := a.productBus.QueryVariantsByProductID(ctx, productID)
	if err != nil {
		return errs.Newf(errs.Internal, "queryvariants: %s", err)
	}

	appVariants := make([]ProductVariant, len(variants))
	for i, variant := range variants {
		appVariants[i] = toAppProductVariant(variant)
	}

	return variants
}

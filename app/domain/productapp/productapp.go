package productapp

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/app/sdk/query"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/foundation/web"
)

type app struct {
	productBus *productbus.Business
}

func newApp(productBus *productbus.Business) *app {
	return &app{
		productBus: productBus,
	}
}

// create adds a new product to the system.
func (a *app) create(ctx context.Context, r *http.Request) web.Encoder {
	var app NewProduct
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	np, err := toBusNewProduct(ctx, app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	prd, err := a.productBus.Create(ctx, np)
	if err != nil {
		switch {
		case errors.Is(err, productbus.ErrUserDisabled):
			return errs.New(errs.PermissionDenied, err)
		case errors.Is(err, productbus.ErrInvalidCost):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrCategoryRequired):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrInvalidPricing):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrDuplicateSKU):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrSKUAlreadyExists):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrInvalidBarcode):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrInvalidDimensions):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrRequiredFieldMissing):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrInvalidTaxCategory):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrRelatedProductNotFound):
			return errs.New(errs.InvalidArgument, err)
		default:
			return errs.Newf(errs.Internal, "create: product[%+v]: %s", app, err)
		}
	}

	return toAppProduct(prd)
}

// update modifies data about a product.
func (a *app) update(ctx context.Context, r *http.Request) web.Encoder {
	var app UpdateProduct
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	up, err := toBusUpdateProduct(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "product missing in context: %s", err)
	}

	updPrd, err := a.productBus.Update(ctx, prd, up)
	if err != nil {
		switch {
		case errors.Is(err, productbus.ErrNotFound):
			return errs.New(errs.NotFound, err)
		case errors.Is(err, productbus.ErrUserDisabled):
			return errs.New(errs.PermissionDenied, err)
		case errors.Is(err, productbus.ErrProductLocked):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrProductDiscontinued):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrInvalidPricing):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrDuplicateSKU):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrInvalidBarcode):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrSKUAlreadyExists):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrInvalidDimensions):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrImageLimitExceeded):
			return errs.New(errs.ResourceExhausted, err)
		case errors.Is(err, productbus.ErrIllegalStatusTransition):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrInvalidTaxCategory):
			return errs.New(errs.InvalidArgument, err)
		case errors.Is(err, productbus.ErrRelatedProductNotFound):
			return errs.New(errs.InvalidArgument, err)
		default:
			return errs.Newf(errs.Internal, "update: productID[%s] up[%+v]: %s", prd.ID, app, err)
		}
	}

	return toAppProduct(updPrd)
}

// delete removes the product identified by a given ID.
func (a *app) delete(ctx context.Context, _ *http.Request) web.Encoder {
	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "productID missing in context: %s", err)
	}

	if err := a.productBus.Delete(ctx, prd); err != nil {
		switch {
		case errors.Is(err, productbus.ErrNotFound):
			return errs.New(errs.NotFound, err)
		case errors.Is(err, productbus.ErrUserDisabled):
			return errs.New(errs.PermissionDenied, err)
		case errors.Is(err, productbus.ErrProductLocked):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrInsufficientInventory):
			// Can't delete product with existing inventory
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrProductDiscontinued):
			// Can return a more specific message that discontinued products need special handling
			return errs.Newf(errs.FailedPrecondition, "cannot delete discontinued product [%s], archive instead", prd.ID)
		default:
			return errs.Newf(errs.Internal, "delete: productID[%s]: %s", prd.ID, err)
		}
	}

	return nil
}

// query retrieves a list of existing products with filter capabilities.
func (a *app) query(ctx context.Context, r *http.Request) web.Encoder {
	qp := parseQueryParams(r)

	page, err := page.Parse(qp.Page, qp.Rows)
	if err != nil {
		return errs.NewFieldErrors("page", err)
	}

	filter, err := parseFilter(qp)
	if err != nil {
		return err.(*errs.Error)
	}

	orderBy, err := order.Parse(orderByFields, qp.OrderBy, productbus.DefaultOrderBy)
	if err != nil {
		return errs.NewFieldErrors("order", err)
	}

	prds, err := a.productBus.Query(ctx, filter, orderBy, page)
	if err != nil {
		return errs.Newf(errs.Internal, "query: %s", err)
	}

	total, err := a.productBus.Count(ctx, filter)
	if err != nil {
		return errs.Newf(errs.Internal, "count: %s", err)
	}

	return query.NewResult(toAppProducts(prds), total, page)
}

// queryByID finds the product identified by a given ID.
func (a *app) queryByID(ctx context.Context, r *http.Request) web.Encoder {
	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "querybyid: %s", err)
	}

	return toAppProduct(prd)
}

// createVariant adds a new product variant.

func (a *app) createVariant(ctx context.Context, r *http.Request) web.Encoder {
	var app NewProductVariant
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	// Override the productID from path param to ensure it's correct
	productID := web.Param(r, "product_id")
	if productID == "" {
		return errs.Newf(errs.InvalidArgument, "missing product_id in path")
	}
	app.ProductID = productID

	npv, err := toBusNewProductVariant(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	// Ensure the user has access to the product
	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "product missing in context: %s", err)
	}

	if prd.ID.String() != app.ProductID {
		return errs.Newf(errs.InvalidArgument, "product_id mismatch between path and body")
	}

	variant, err := a.productBus.CreateVariant(ctx, npv)
	if err != nil {
		switch {
		case errors.Is(err, productbus.ErrNotFound):
			return errs.New(errs.NotFound, err)
		case errors.Is(err, productbus.ErrProductLocked):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrProductDiscontinued):
			return errs.New(errs.FailedPrecondition, err)
		case errors.Is(err, productbus.ErrVariantLimitExceeded):
			return errs.New(errs.ResourceExhausted, err)
		case errors.Is(err, productbus.ErrDuplicateSKU):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrSKUAlreadyExists):
			return errs.New(errs.AlreadyExists, err)
		case errors.Is(err, productbus.ErrInvalidBarcode):
			return errs.New(errs.InvalidArgument, err)
		default:
			return errs.Newf(errs.Internal, "create variant: %s", err)
		}
	}

	return toAppProductVariant(variant)
}

// updateVariant modifies data about a product variant.
func (a *app) updateVariant(ctx context.Context, r *http.Request) web.Encoder {
	var app UpdateProductVariant
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	variantIDStr := web.Param(r, "variant_id")
	if variantIDStr == "" {
		return errs.Newf(errs.InvalidArgument, "missing variant_id in path")
	}

	variantID, err := uuid.Parse(variantIDStr)
	if err != nil {
		return errs.Newf(errs.InvalidArgument, "invalid variant_id: %s", err)
	}

	upv, err := toBusUpdateProductVariant(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	// TODO: Add middleware to check if user has access to variant's product
	// For now, we'll handle at business layer

	variant, err := a.productBus.UpdateVariant(ctx, variantID, upv)
	if err != nil {
		return errs.Newf(errs.Internal, "update variant: variantID[%s]: %s", variantID, err)
	}

	return toAppProductVariant(variant)
}

// deleteVariant removes the product variant identified by a given ID.
func (a *app) deleteVariant(ctx context.Context, r *http.Request) web.Encoder {
	variantIDStr := web.Param(r, "variant_id")
	if variantIDStr == "" {
		return errs.Newf(errs.InvalidArgument, "missing variant_id in path")
	}

	variantID, err := uuid.Parse(variantIDStr)
	if err != nil {
		return errs.Newf(errs.InvalidArgument, "invalid variant_id: %s", err)
	}

	// TODO: Add middleware to check if user has access to variant's product
	// For now, we'll handle at business layer

	if err := a.productBus.DeleteVariant(ctx, variantID); err != nil {
		return errs.Newf(errs.Internal, "delete variant: variantID[%s]: %s", variantID, err)
	}

	return nil
}

// search finds products based on a search term.

func (a *app) search(ctx context.Context, r *http.Request) web.Encoder {
	searchTerm := r.URL.Query().Get("q")
	if searchTerm == "" {
		return errs.Newf(errs.InvalidArgument, "search term is required")
	}

	// Add category and other filters if provided
	category := r.URL.Query().Get("category")
	status := r.URL.Query().Get("status")
	brand := r.URL.Query().Get("brand")

	// Prepare a filter with search term and optional filters
	filter := productbus.QueryFilter{
		SearchTerm: &searchTerm,
	}

	if category != "" {
		cat, err := categoryFromString(category)
		if err == nil {
			filter.Category = &cat
		}
	}

	if status != "" {
		stat, err := statusFromString(status)
		if err == nil {
			filter.Status = &stat
		}
	}

	if brand != "" {
		filter.Brand = &brand
	}

	// Parse page parameters
	pageNum := r.URL.Query().Get("page")
	rows := r.URL.Query().Get("rows")

	pg, err := page.Parse(pageNum, rows)
	if err != nil {
		return errs.NewFieldErrors("page", err)
	}

	// Use default order for search results or specified order
	orderByStr := r.URL.Query().Get("orderBy")
	orderBy := productbus.DefaultOrderBy
	if orderByStr != "" {
		var err error
		orderBy, err = order.Parse(orderByFields, orderByStr, productbus.DefaultOrderBy)
		if err != nil {
			return errs.NewFieldErrors("order", err)
		}
	}

	// The optimized Query method will handle batch loading of variants
	prds, err := a.productBus.Query(ctx, filter, orderBy, pg)
	if err != nil {
		return errs.Newf(errs.Internal, "search: %s", err)
	}

	total, err := a.productBus.Count(ctx, filter)
	if err != nil {
		return errs.Newf(errs.Internal, "count: %s", err)
	}

	return query.NewResult(toAppProducts(prds), total, pg)
}

func categoryFromString(categoryStr string) (category.Category, error) {
	return category.Parse(categoryStr)
}

func statusFromString(statusStr string) (productstatus.ProductStatus, error) {
	return productstatus.Parse(statusStr)
}

// addImage adds a new image to a product
func (a *app) addImage(ctx context.Context, r *http.Request) web.Encoder {
	var app AddProductImage
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "product missing in context: %s", err)
	}

	// Update the product's image URLs
	if prd.ImageURLs == nil {
		prd.ImageURLs = make(productbus.StringArray, 0)
	}
	prd.ImageURLs = append(prd.ImageURLs, app.ImageURL)

	up := productbus.UpdateProduct{
		ImageURLs: &prd.ImageURLs,
	}

	updPrd, err := a.productBus.Update(ctx, prd, up)
	if err != nil {
		return errs.Newf(errs.Internal, "update: productID[%s]: %s", prd.ID, err)
	}

	return toAppProduct(updPrd)
}

// removeImage removes an image from a product
func (a *app) removeImage(ctx context.Context, r *http.Request) web.Encoder {
	imageIndex, err := strconv.Atoi(web.Param(r, "image_id"))
	if err != nil {
		return errs.Newf(errs.InvalidArgument, "invalid image index: %s", err)
	}

	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "product missing in context: %s", err)
	}

	// Validate image index
	if imageIndex < 0 || imageIndex >= len(prd.ImageURLs) {
		return errs.Newf(errs.InvalidArgument, "image index out of bounds")
	}

	// Remove the image from the array
	newImages := make(productbus.StringArray, 0, len(prd.ImageURLs)-1)
	for i, img := range prd.ImageURLs {
		if i != imageIndex {
			newImages = append(newImages, img)
		}
	}

	up := productbus.UpdateProduct{
		ImageURLs: &newImages,
	}

	updPrd, err := a.productBus.Update(ctx, prd, up)
	if err != nil {
		return errs.Newf(errs.Internal, "update: productID[%s]: %s", prd.ID, err)
	}

	return toAppProduct(updPrd)
}

// updateImage updates an image's position or URL
func (a *app) updateImage(ctx context.Context, r *http.Request) web.Encoder {
	var app UpdateProductImage
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	imageIndex, err := strconv.Atoi(web.Param(r, "image_id"))
	if err != nil {
		return errs.Newf(errs.InvalidArgument, "invalid image index: %s", err)
	}

	prd, err := mid.GetProduct(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "product missing in context: %s", err)
	}

	// Validate image index
	if imageIndex < 0 || imageIndex >= len(prd.ImageURLs) {
		return errs.Newf(errs.InvalidArgument, "image index out of bounds")
	}

	// Update the image URL
	prd.ImageURLs[imageIndex] = app.ImageURL

	up := productbus.UpdateProduct{
		ImageURLs: &prd.ImageURLs,
	}

	updPrd, err := a.productBus.Update(ctx, prd, up)
	if err != nil {
		return errs.Newf(errs.Internal, "update: productID[%s]: %s", prd.ID, err)
	}

	return toAppProduct(updPrd)
}

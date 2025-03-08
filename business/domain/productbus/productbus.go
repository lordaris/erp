package productbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/sdk/delegate"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/foundation/logger"
	"github.com/lordaris/erp/foundation/otel"
)

// Set of error variables for CRUD operations.
var (
	ErrNotFound     = errors.New("product not found")
	ErrUserDisabled = errors.New("user disabled")
	ErrInvalidCost  = errors.New("cost not valid")
)

// Storer interface declares the behavior this package needs to persist and
// retrieve data.
type Storer interface {
	NewWithTx(tx sqldb.CommitRollbacker) (Storer, error)
	Create(ctx context.Context, prd Product) error
	Update(ctx context.Context, prd Product) error
	Delete(ctx context.Context, prd Product) error
	Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Product, error)
	Count(ctx context.Context, filter QueryFilter) (int, error)
	QueryByID(ctx context.Context, productID uuid.UUID) (Product, error)
	QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Product, error)
	// New methods for enhanced model
	QueryBySKU(ctx context.Context, sku string) (Product, error)
	QueryByUPC(ctx context.Context, upc string) (Product, error)
	QueryByCategory(ctx context.Context, categoryName string, page page.Page) ([]Product, error)
	CreateVariant(ctx context.Context, variant ProductVariant) error
	UpdateVariant(ctx context.Context, variant ProductVariant) error
	DeleteVariant(ctx context.Context, variantID uuid.UUID) error
	QueryVariantsByProductID(ctx context.Context, productID uuid.UUID) ([]ProductVariant, error)
	QueryVariantByID(ctx context.Context, variantID uuid.UUID) (ProductVariant, error)
}

// Business manages the set of APIs for product access.
type Business struct {
	log      *logger.Logger
	userBus  *userbus.Business
	delegate *delegate.Delegate
	storer   Storer
}

// NewBusiness constructs a product business API for use.
func NewBusiness(log *logger.Logger, userBus *userbus.Business, delegate *delegate.Delegate, storer Storer) *Business {
	b := Business{
		log:      log,
		userBus:  userBus,
		delegate: delegate,
		storer:   storer,
	}

	b.registerDelegateFunctions()

	return &b
}

// NewWithTx constructs a new business value that will use the
// specified transaction in any store related calls.
func (b *Business) NewWithTx(tx sqldb.CommitRollbacker) (*Business, error) {
	storer, err := b.storer.NewWithTx(tx)
	if err != nil {
		return nil, err
	}

	userBus, err := b.userBus.NewWithTx(tx)
	if err != nil {
		return nil, err
	}

	bus := Business{
		log:      b.log,
		userBus:  userBus,
		delegate: b.delegate,
		storer:   storer,
	}

	return &bus, nil
}

// Create adds a new product to the system.
func (b *Business) Create(ctx context.Context, np NewProduct) (Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.create")
	defer span.End()

	usr, err := b.userBus.QueryByID(ctx, np.UserID)
	if err != nil {
		return Product{}, fmt.Errorf("user.querybyid: %s: %w", np.UserID, err)
	}

	if !usr.Enabled {
		return Product{}, ErrUserDisabled
	}

	now := time.Now()

	prd := Product{
		ID:          uuid.New(),
		Name:        np.Name,
		Cost:        np.Cost,
		Quantity:    np.Quantity,
		UserID:      np.UserID,
		DateCreated: now,
		DateUpdated: now,
	}

	if err := b.storer.Create(ctx, prd); err != nil {
		return Product{}, fmt.Errorf("create: %w", err)
	}

	return prd, nil
}

// Update modifies information about a product.
func (b *Business) Update(ctx context.Context, prd Product, up UpdateProduct) (Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.update")
	defer span.End()

	if up.Name != nil {
		prd.Name = *up.Name
	}

	if up.Cost != nil {
		prd.Cost = *up.Cost
	}

	if up.Quantity != nil {
		prd.Quantity = *up.Quantity
	}

	prd.DateUpdated = time.Now()

	if err := b.storer.Update(ctx, prd); err != nil {
		return Product{}, fmt.Errorf("update: %w", err)
	}

	return prd, nil
}

// Delete removes the specified product.
func (b *Business) Delete(ctx context.Context, prd Product) error {
	ctx, span := otel.AddSpan(ctx, "business.productbus.delete")
	defer span.End()

	if err := b.storer.Delete(ctx, prd); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	return nil
}

// Query retrieves a list of existing products.
func (b *Business) Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.query")
	defer span.End()

	prds, err := b.storer.Query(ctx, filter, orderBy, page)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	return prds, nil
}

// Count returns the total number of products.
func (b *Business) Count(ctx context.Context, filter QueryFilter) (int, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.count")
	defer span.End()

	return b.storer.Count(ctx, filter)
}

// QueryByID finds the product by the specified ID.
func (b *Business) QueryByID(ctx context.Context, productID uuid.UUID) (Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.querybyid")
	defer span.End()

	prd, err := b.storer.QueryByID(ctx, productID)
	if err != nil {
		return Product{}, fmt.Errorf("query: productID[%s]: %w", productID, err)
	}

	return prd, nil
}

// QueryByUserID finds the products by a specified User ID.
func (b *Business) QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.querybyuserid")
	defer span.End()

	prds, err := b.storer.QueryByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	return prds, nil
}

// CreateVariant adds a new variant to an existing product.
func (b *Business) CreateVariant(ctx context.Context, nv NewProductVariant) (ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.createvariant")
	defer span.End()

	// Verify the product exists
	prd, err := b.QueryByID(ctx, nv.ProductID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("product.querybyid: %s: %w", nv.ProductID, err)
	}

	// Verify the user is active
	usr, err := b.userBus.QueryByID(ctx, prd.UserID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("user.querybyid: %s: %w", prd.UserID, err)
	}

	if !usr.Enabled {
		return ProductVariant{}, ErrUserDisabled
	}

	now := time.Now()

	variant := ProductVariant{
		ID:             uuid.New(),
		ProductID:      nv.ProductID,
		SKU:            nv.SKU,
		VariantOptions: nv.VariantOptions,
		Price:          nv.Price,
		Quantity:       nv.Quantity,
		IsActive:       nv.IsActive,
		DateCreated:    now,
		DateUpdated:    now,
	}

	if err := b.storer.CreateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("create variant: %w", err)
	}

	return variant, nil
}

// UpdateVariant modifies information about a product variant.
func (b *Business) UpdateVariant(ctx context.Context, variant ProductVariant, uv UpdateProductVariant) (ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.updatevariant")
	defer span.End()

	// Check if the product exists and is owned by an active user
	prd, err := b.QueryByID(ctx, variant.ProductID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("product.querybyid: %s: %w", variant.ProductID, err)
	}

	usr, err := b.userBus.QueryByID(ctx, prd.UserID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("user.querybyid: %s: %w", prd.UserID, err)
	}

	if !usr.Enabled {
		return ProductVariant{}, ErrUserDisabled
	}

	// Apply updates
	if uv.SKU != nil {
		variant.SKU = *uv.SKU
	}

	if uv.VariantOptions != nil {
		variant.VariantOptions = *uv.VariantOptions
	}

	if uv.Price != nil {
		variant.Price = *uv.Price
	}

	if uv.Quantity != nil {
		variant.Quantity = *uv.Quantity
	}

	if uv.IsActive != nil {
		variant.IsActive = *uv.IsActive
	}

	variant.DateUpdated = time.Now()

	if err := b.storer.UpdateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("update variant: %w", err)
	}

	return variant, nil
}

// DeleteVariant removes the specified product variant.
func (b *Business) DeleteVariant(ctx context.Context, variant ProductVariant) error {
	ctx, span := otel.AddSpan(ctx, "business.productbus.deletevariant")
	defer span.End()

	// Check if the product exists and is owned by an active user
	prd, err := b.QueryByID(ctx, variant.ProductID)
	if err != nil {
		return fmt.Errorf("product.querybyid: %s: %w", variant.ProductID, err)
	}

	usr, err := b.userBus.QueryByID(ctx, prd.UserID)
	if err != nil {
		return fmt.Errorf("user.querybyid: %s: %w", prd.UserID, err)
	}

	if !usr.Enabled {
		return ErrUserDisabled
	}

	if err := b.storer.DeleteVariant(ctx, variant.ID); err != nil {
		return fmt.Errorf("delete variant: %w", err)
	}

	return nil
}

// QueryVariantByID finds a variant by the specified ID.
func (b *Business) QueryVariantByID(ctx context.Context, variantID uuid.UUID) (ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.queryvariantbyid")
	defer span.End()

	variant, err := b.storer.QueryVariantByID(ctx, variantID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("query: variantID[%s]: %w", variantID, err)
	}

	return variant, nil
}

// QueryVariantsByProductID finds all variants for a specific product.
func (b *Business) QueryVariantsByProductID(ctx context.Context, productID uuid.UUID) ([]ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.queryvariantsbyproductid")
	defer span.End()

	variants, err := b.storer.QueryVariantsByProductID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("query: productID[%s]: %w", productID, err)
	}

	return variants, nil
}

// QueryBySKU finds a product by its SKU.
func (b *Business) QueryBySKU(ctx context.Context, sku string) (Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.querybysku")
	defer span.End()

	prd, err := b.storer.QueryBySKU(ctx, sku)
	if err != nil {
		return Product{}, fmt.Errorf("query: sku[%s]: %w", sku, err)
	}

	return prd, nil
}

// QueryByUPC finds a product by its UPC.
func (b *Business) QueryByUPC(ctx context.Context, upc string) (Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.querybyupc")
	defer span.End()

	prd, err := b.storer.QueryByUPC(ctx, upc)
	if err != nil {
		return Product{}, fmt.Errorf("query: upc[%s]: %w", upc, err)
	}

	return prd, nil
}

// QueryByCategory finds products by their category.
func (b *Business) QueryByCategory(ctx context.Context, categoryName string, page page.Page) ([]Product, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.querybycategory")
	defer span.End()

	prds, err := b.storer.QueryByCategory(ctx, categoryName, page)
	if err != nil {
		return nil, fmt.Errorf("query: category[%s]: %w", categoryName, err)
	}

	return prds, nil
}

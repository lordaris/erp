// Package productbus provides business access to product domain.
package productbus

import (
	"context"
	"database/sql/driver"
	"encoding/json"
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

// StringArray is a custom type for storing arrays in PostgreSQL
type StringArray []string

// Value implements the driver.Valuer interface for StringArray
func (a StringArray) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface for StringArray
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = StringArray{}
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	return json.Unmarshal(data, a)
}

// JSONMap is a custom type for storing JSON data in PostgreSQL
type JSONMap map[string]interface{}

// Value implements the driver.Valuer interface for JSONMap
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for JSONMap
func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = make(JSONMap)
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	return json.Unmarshal(data, m)
}

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
		ID:              uuid.New(),
		UserID:          np.UserID,
		SKU:             np.SKU,
		Name:            np.Name,
		Description:     np.Description,
		Category:        np.Category,
		Subcategory:     np.Subcategory,
		UPC:             np.UPC,
		Brand:           np.Brand,
		Manufacturer:    np.Manufacturer,
		Status:          np.Status,
		TaxCategory:     np.TaxCategory,
		UnitOfMeasure:   np.UnitOfMeasure,
		Weight:          np.Weight,
		Length:          np.Length,
		Width:           np.Width,
		Height:          np.Height,
		MSRP:            np.MSRP,
		Cost:            np.Cost,
		MinimumPrice:    np.MinimumPrice,
		Quantity:        np.Quantity,
		IsDigital:       np.IsDigital,
		HasSerialNumber: np.HasSerialNumber,
		HasLotNumber:    np.HasLotNumber,
		Attributes:      np.Attributes,
		ImageURLs:       np.ImageURLs,
		DateCreated:     now,
		DateUpdated:     now,
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

	if up.SKU != nil {
		prd.SKU = *up.SKU
	}

	if up.Name != nil {
		prd.Name = *up.Name
	}

	if up.Description != nil {
		prd.Description = *up.Description
	}

	if up.Category != nil {
		prd.Category = *up.Category
	}

	if up.Subcategory != nil {
		prd.Subcategory = *up.Subcategory
	}

	if up.UPC != nil {
		prd.UPC = *up.UPC
	}

	if up.Brand != nil {
		prd.Brand = *up.Brand
	}

	if up.Manufacturer != nil {
		prd.Manufacturer = *up.Manufacturer
	}

	if up.Status != nil {
		prd.Status = *up.Status
	}

	if up.TaxCategory != nil {
		prd.TaxCategory = *up.TaxCategory
	}

	if up.UnitOfMeasure != nil {
		prd.UnitOfMeasure = *up.UnitOfMeasure
	}

	if up.Weight != nil {
		prd.Weight = *up.Weight
	}

	if up.Length != nil {
		prd.Length = *up.Length
	}

	if up.Width != nil {
		prd.Width = *up.Width
	}

	if up.Height != nil {
		prd.Height = *up.Height
	}

	if up.MSRP != nil {
		prd.MSRP = *up.MSRP
	}

	if up.Cost != nil {
		prd.Cost = *up.Cost
	}

	if up.MinimumPrice != nil {
		prd.MinimumPrice = *up.MinimumPrice
	}

	if up.Quantity != nil {
		prd.Quantity = *up.Quantity
	}

	if up.IsDigital != nil {
		prd.IsDigital = *up.IsDigital
	}

	if up.HasSerialNumber != nil {
		prd.HasSerialNumber = *up.HasSerialNumber
	}

	if up.HasLotNumber != nil {
		prd.HasLotNumber = *up.HasLotNumber
	}

	if up.Attributes != nil {
		prd.Attributes = *up.Attributes
	}

	if up.ImageURLs != nil {
		prd.ImageURLs = *up.ImageURLs
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

	// Load variants
	variants, err := b.storer.QueryVariantsByProductID(ctx, productID)
	if err != nil {
		return Product{}, fmt.Errorf("query variants: productID[%s]: %w", productID, err)
	}
	prd.Variants = variants

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

	// Load variants for each product
	for i, prd := range prds {
		variants, err := b.storer.QueryVariantsByProductID(ctx, prd.ID)
		if err != nil {
			return nil, fmt.Errorf("query variants: productID[%s]: %w", prd.ID, err)
		}
		prds[i].Variants = variants
	}

	return prds, nil
}

// CreateVariant adds a new product variant to the system.
func (b *Business) CreateVariant(ctx context.Context, npv NewProductVariant) (ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.createvariant")
	defer span.End()

	// Verify the product exists
	_, err := b.storer.QueryByID(ctx, npv.ProductID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("product.querybyid: %s: %w", npv.ProductID, err)
	}

	now := time.Now()

	variant := ProductVariant{
		ID:             uuid.New(),
		ProductID:      npv.ProductID,
		SKU:            npv.SKU,
		VariantOptions: npv.VariantOptions,
		Price:          npv.Price,
		Quantity:       npv.Quantity,
		IsActive:       npv.IsActive,
		DateCreated:    now,
		DateUpdated:    now,
	}

	if err := b.storer.CreateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("create variant: %w", err)
	}

	return variant, nil
}

// UpdateVariant modifies information about a product variant.
func (b *Business) UpdateVariant(ctx context.Context, variantID uuid.UUID, upv UpdateProductVariant) (ProductVariant, error) {
	ctx, span := otel.AddSpan(ctx, "business.productbus.updatevariant")
	defer span.End()

	variant, err := b.storer.QueryVariantByID(ctx, variantID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("query variant: variantID[%s]: %w", variantID, err)
	}

	if upv.SKU != nil {
		variant.SKU = *upv.SKU
	}

	if upv.VariantOptions != nil {
		variant.VariantOptions = *upv.VariantOptions
	}

	if upv.Price != nil {
		variant.Price = *upv.Price
	}

	if upv.Quantity != nil {
		variant.Quantity = *upv.Quantity
	}

	if upv.IsActive != nil {
		variant.IsActive = *upv.IsActive
	}

	variant.DateUpdated = time.Now()

	if err := b.storer.UpdateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("update variant: %w", err)
	}

	return variant, nil
}

// DeleteVariant removes the specified product variant.
func (b *Business) DeleteVariant(ctx context.Context, variantID uuid.UUID) error {
	ctx, span := otel.AddSpan(ctx, "business.productbus.deletevariant")
	defer span.End()

	if err := b.storer.DeleteVariant(ctx, variantID); err != nil {
		return fmt.Errorf("delete variant: %w", err)
	}

	return nil
}

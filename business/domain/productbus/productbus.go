// Package productbus provides business access to product domain.
package productbus

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/sdk/delegate"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/foundation/logger"
)

// Set of error variables for CRUD operations.
var (
	ErrNotFound                = errors.New("product not found")
	ErrUserDisabled            = errors.New("user disabled")
	ErrInvalidCost             = errors.New("cost not valid")
	ErrProductLocked           = errors.New("product is locked for editing")
	ErrInsufficientInventory   = errors.New("insufficient inventory")
	ErrProductDiscontinued     = errors.New("product has been discontinued")
	ErrDuplicateSKU            = errors.New("duplicate SKU")
	ErrInvalidPricing          = errors.New("invalid pricing structure")
	ErrCategoryRequired        = errors.New("product category is required")
	ErrInvalidDimensions       = errors.New("invalid product dimensions")
	ErrImageLimitExceeded      = errors.New("maximum number of product images exceeded")
	ErrVariantLimitExceeded    = errors.New("maximum number of product variants exceeded")
	ErrInvalidBarcode          = errors.New("invalid barcode format")
	ErrRequiredFieldMissing    = errors.New("required field missing")
	ErrInvalidTaxCategory      = errors.New("invalid tax category for product type")
	ErrRelatedProductNotFound  = errors.New("related product not found")
	ErrSKUAlreadyExists        = errors.New("SKU already exists")
	ErrIllegalStatusTransition = errors.New("illegal product status transition")
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
	QueryVariantsByProductIDs(ctx context.Context, productIDs []uuid.UUID) ([]ProductVariant, error)
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
		userBus:  userBus,
		delegate: b.delegate,
		storer:   storer,
	}

	return &bus, nil
}

// Create adds a new product to the system.

func (b *Business) Create(ctx context.Context, np NewProduct) (Product, error) {
	// Validate that the provided userID exists and is enabled
	usr, err := b.userBus.QueryByID(ctx, np.UserID)
	if err != nil {
		if errors.Is(err, userbus.ErrNotFound) {
			return Product{}, fmt.Errorf("query user: %w", err)
		}
		return Product{}, fmt.Errorf("query user: %w", err)
	}

	if !usr.Enabled {
		return Product{}, ErrUserDisabled
	}

	// Validate product name
	if np.Name.String() == "" {
		return Product{}, fmt.Errorf("%w: name", ErrRequiredFieldMissing)
	}

	// Validate category
	if np.Category.String() == "" {
		return Product{}, ErrCategoryRequired
	}

	// Validate pricing structure
	if np.CostPrice.Value() <= 0 {
		return Product{}, fmt.Errorf("%w: cost price must be positive", ErrInvalidPricing)
	}

	if np.RetailPrice.Value() < np.CostPrice.Value() {
		return Product{}, fmt.Errorf("%w: retail price cannot be less than cost price", ErrInvalidPricing)
	}

	if np.WholesalePrice.Value() > 0 && (np.WholesalePrice.Value() < np.CostPrice.Value() || np.WholesalePrice.Value() > np.RetailPrice.Value()) {
		return Product{}, fmt.Errorf("%w: wholesale price must be between cost and retail", ErrInvalidPricing)
	}

	// Validate SKU
	if np.SKU == "" {
		return Product{}, fmt.Errorf("%w: SKU", ErrRequiredFieldMissing)
	}

	// Check for duplicate SKU
	filter := QueryFilter{
		SKU: &np.SKU,
	}
	count, err := b.storer.Count(ctx, filter)
	if err != nil {
		return Product{}, fmt.Errorf("checking SKU: %w", err)
	}
	if count > 0 {
		return Product{}, ErrSKUAlreadyExists
	}

	// Validate barcode if provided
	if np.Barcode != "" {
		if !isValidBarcode(np.Barcode) {
			return Product{}, ErrInvalidBarcode
		}
	}

	// Validate dimensions if physical product
	if !np.IsDigital {
		if np.Weight < 0 || np.Length < 0 || np.Width < 0 || np.Height < 0 {
			return Product{}, ErrInvalidDimensions
		}
	}

	// Check related products
	if np.RelatedProducts != uuid.Nil {
		_, err := b.storer.QueryByID(ctx, np.RelatedProducts)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return Product{}, ErrRelatedProductNotFound
			}
			return Product{}, fmt.Errorf("checking related product: %w", err)
		}
	}

	// Validate tax category based on product type
	if np.IsDigital && np.TaxCategory.String() == taxcategory.Standard {
		return Product{}, fmt.Errorf("%w: digital products cannot use standard tax category", ErrInvalidTaxCategory)
	}

	now := time.Now()

	prd := Product{
		ID:               uuid.New(),
		UserID:           np.UserID,
		SKU:              np.SKU,
		Barcode:          np.Barcode,
		Name:             np.Name,
		Description:      np.Description,
		ShortDescription: np.ShortDescription,
		Category:         np.Category,
		Subcategory:      np.Subcategory,
		UPC:              np.UPC,
		Brand:            np.Brand,
		Manufacturer:     np.Manufacturer,
		Status:           np.Status,
		TaxCategory:      np.TaxCategory,
		UnitOfMeasure:    np.UnitOfMeasure,
		Weight:           np.Weight,
		Length:           np.Length,
		Width:            np.Width,
		Height:           np.Height,
		CostPrice:        np.CostPrice,
		WholesalePrice:   np.WholesalePrice,
		RetailPrice:      np.RetailPrice,
		IsWeighted:       np.IsWeighted,
		IsDigital:        np.IsDigital,
		IsTaxable:        np.IsTaxable,
		ReturnPolicy:     np.ReturnPolicy,
		HasSerialNumber:  np.HasSerialNumber,
		HasLotNumber:     np.HasLotNumber,
		Attributes:       np.Attributes,
		ImageURLs:        np.ImageURLs,
		Notes:            np.Notes,
		RelatedProducts:  np.RelatedProducts,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := b.storer.Create(ctx, prd); err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			return Product{}, ErrDuplicateSKU
		}
		return Product{}, fmt.Errorf("create: %w", err)
	}

	return prd, nil
}

// Checks if a product is administratively locked
func isProductLocked(prd Product) bool {
	// A product might be locked if:
	// 1. It's in a special administrative status
	// 2. It has specific attributes indicating a lock

	// Example implementation:
	if lockValue, exists := prd.Attributes["locked"]; exists {
		if locked, ok := lockValue.(bool); ok && locked {
			return true
		}
	}

	return false
}

func isValidBarcode(barcode string) bool {
	// Basic implementation for common barcode formats
	// In a real system, you'd use a barcode validation library

	// EAN-13 (13 digits)
	if len(barcode) == 13 && isNumeric(barcode) {
		return true
	}

	// UPC-A (12 digits)
	if len(barcode) == 12 && isNumeric(barcode) {
		return true
	}

	// EAN-8 (8 digits)
	if len(barcode) == 8 && isNumeric(barcode) {
		return true
	}

	// Code 39 (variable length with specific characters)
	if isCode39Format(barcode) {
		return true
	}

	return false
}

// Helper to check if a string is numeric
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Helper to check Code 39 format
func isCode39Format(s string) bool {
	validChars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%"
	for _, c := range s {
		if !strings.ContainsRune(validChars, c) {
			return false
		}
	}
	return true
}

// Helper function to validate product status transitions
func isValidStatusTransition(current, new productstatus.ProductStatus) bool {
	// Define valid transitions
	validTransitions := map[string][]string{
		productstatus.Active: {
			productstatus.Inactive,
			productstatus.Discontinued,
		},
		productstatus.Inactive: {
			productstatus.Active,
			productstatus.Discontinued,
		},
		productstatus.Discontinued: {
			// Once discontinued, products can't be changed back
		},
		productstatus.ComingSoon: {
			productstatus.Active,
			productstatus.Inactive,
		},
	}

	// Check if transition is valid
	for _, validStatus := range validTransitions[current.String()] {
		if new.String() == validStatus {
			return true
		}
	}

	// Allow transition to same status
	return current.String() == new.String()
}

// Update modifies information about a product.

func (b *Business) Update(ctx context.Context, prd Product, up UpdateProduct) (Product, error) {
	// Check if product is locked
	if isProductLocked(prd) {
		return Product{}, ErrProductLocked
	}

	// Cannot update discontinued products
	if prd.Status.IsDiscontinued() {
		return Product{}, ErrProductDiscontinued
	}

	// Validate product status transition if status is being updated
	if up.Status != nil && !isValidStatusTransition(prd.Status, *up.Status) {
		return Product{}, ErrIllegalStatusTransition
	}

	// SKU validation
	if up.SKU != nil {
		if *up.SKU == "" {
			return Product{}, fmt.Errorf("%w: SKU cannot be empty", ErrRequiredFieldMissing)
		}

		// Check for duplicate SKU only if changing
		if *up.SKU != prd.SKU {
			filter := QueryFilter{
				SKU: up.SKU,
			}
			count, err := b.storer.Count(ctx, filter)
			if err != nil {
				return Product{}, fmt.Errorf("checking SKU: %w", err)
			}
			if count > 0 {
				return Product{}, ErrSKUAlreadyExists
			}
		}
	}

	// Barcode validation
	if up.Barcode != nil && *up.Barcode != "" && !isValidBarcode(*up.Barcode) {
		return Product{}, ErrInvalidBarcode
	}

	// Dimension validation
	if !prd.IsDigital {
		if (up.Weight != nil && *up.Weight < 0) ||
			(up.Length != nil && *up.Length < 0) ||
			(up.Width != nil && *up.Width < 0) ||
			(up.Height != nil && *up.Height < 0) {
			return Product{}, ErrInvalidDimensions
		}
	}

	// Image limit validation
	if up.ImageURLs != nil && len(*up.ImageURLs) > 10 {
		return Product{}, ErrImageLimitExceeded
	}

	// Pricing validation
	newCostPrice := prd.CostPrice
	if up.Cost != nil {
		if up.Cost.Value() <= 0 {
			return Product{}, fmt.Errorf("%w: cost price must be positive", ErrInvalidPricing)
		}
		newCostPrice = *up.Cost
	}

	// Process updates
	if up.SKU != nil {
		prd.SKU = *up.SKU
	}

	if up.Barcode != nil {
		prd.Barcode = *up.Barcode
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
		// Validate tax category based on product type
		if prd.IsDigital && up.TaxCategory.String() == taxcategory.Standard {
			return Product{}, fmt.Errorf("%w: digital products cannot use standard tax category", ErrInvalidTaxCategory)
		}
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

	// Handle renamed fields mapping correctly
	if up.Cost != nil {
		prd.CostPrice = *up.Cost
	}

	if up.MinimumPrice != nil {
		// Validate wholesale price
		if up.MinimumPrice.Value() < newCostPrice.Value() {
			return Product{}, fmt.Errorf("%w: wholesale price cannot be less than cost price", ErrInvalidPricing)
		}
		prd.WholesalePrice = *up.MinimumPrice
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

	prd.UpdatedAt = time.Now()

	if err := b.storer.Update(ctx, prd); err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			return Product{}, ErrDuplicateSKU
		}
		return Product{}, fmt.Errorf("update: %w", err)
	}

	return prd, nil
}

// Delete removes the specified product.
func (b *Business) Delete(ctx context.Context, prd Product) error {
	if err := b.storer.Delete(ctx, prd); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	return nil
}

// Count returns the total number of products.
func (b *Business) Count(ctx context.Context, filter QueryFilter) (int, error) {
	return b.storer.Count(ctx, filter)
}

// QueryByID finds the product by the specified ID and loads its variants.
func (b *Business) QueryByID(ctx context.Context, productID uuid.UUID) (Product, error) {
	prd, err := b.storer.QueryByID(ctx, productID)
	if err != nil {
		return Product{}, fmt.Errorf("query: productID[%s]: %w", productID, err)
	}

	// Load variants
	prd.Variants, err = b.storer.QueryVariantsByProductID(ctx, productID)
	if err != nil {
		return Product{}, fmt.Errorf("query variants: productID[%s]: %w", productID, err)
	}

	return prd, nil
}

// Optimize Query method to efficiently load variants in batches

func (b *Business) Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Product, error) {
	startTime := time.Now()

	// First, fetch all products with the filter
	prds, err := b.storer.Query(ctx, filter, orderBy, page)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	queryDuration := time.Since(startTime)

	// Early return if no products found
	if len(prds) == 0 {
		return prds, nil
	}

	startVariantTime := time.Now()

	// Collect all product IDs for a single batch query
	productIDs := make([]uuid.UUID, len(prds))
	productMap := make(map[uuid.UUID]*Product)

	for i := range prds {
		productIDs[i] = prds[i].ID
		productMap[prds[i].ID] = &prds[i]
	}

	// Single batch query for all variants
	variants, err := b.storer.QueryVariantsByProductIDs(ctx, productIDs)
	if err != nil {
		return nil, fmt.Errorf("query variants: %w", err)
	}

	// Distribute variants to their respective products
	for _, v := range variants {
		if prod, exists := productMap[v.ProductID]; exists {
			prod.Variants = append(prod.Variants, v)
		}
	}

	variantDuration := time.Since(startVariantTime)
	totalDuration := time.Since(startTime)

	// Log performance metrics
	b.log.Info(ctx, "product_query_performance",
		"product_count", len(prds),
		"variant_count", len(variants),
		"products_query_ms", queryDuration.Milliseconds(),
		"variants_query_ms", variantDuration.Milliseconds(),
		"total_query_ms", totalDuration.Milliseconds(),
	)

	return prds, nil
}

// QueryByUserID finds the products by a specified User ID.

func (b *Business) QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Product, error) {
	prds, err := b.storer.QueryByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	// Early return if no products found
	if len(prds) == 0 {
		return prds, nil
	}

	// Collect all product IDs for a single batch query
	productIDs := make([]uuid.UUID, len(prds))
	productMap := make(map[uuid.UUID]*Product)

	for i := range prds {
		productIDs[i] = prds[i].ID
		productMap[prds[i].ID] = &prds[i]
	}

	// Single batch query for all variants
	variants, err := b.storer.QueryVariantsByProductIDs(ctx, productIDs)
	if err != nil {
		return nil, fmt.Errorf("query variants: %w", err)
	}

	// Distribute variants to their respective products
	for _, v := range variants {
		if prod, exists := productMap[v.ProductID]; exists {
			prod.Variants = append(prod.Variants, v)
		}
	}

	return prds, nil
}

// CreateVariant adds a new product variant to the system.
func (b *Business) CreateVariant(ctx context.Context, npv NewProductVariant) (ProductVariant, error) {
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
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := b.storer.CreateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("create variant: %w", err)
	}

	return variant, nil
}

// UpdateVariant modifies information about a product variant.
func (b *Business) UpdateVariant(ctx context.Context, variantID uuid.UUID, upv UpdateProductVariant) (ProductVariant, error) {
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

	variant.UpdatedAt = time.Now()

	if err := b.storer.UpdateVariant(ctx, variant); err != nil {
		return ProductVariant{}, fmt.Errorf("update variant: %w", err)
	}

	return variant, nil
}

// DeleteVariant removes the specified product variant.
func (b *Business) DeleteVariant(ctx context.Context, variantID uuid.UUID) error {
	if err := b.storer.DeleteVariant(ctx, variantID); err != nil {
		return fmt.Errorf("delete variant: %w", err)
	}

	return nil
}

// QueryVariantByID finds the variant identified by a given ID.
func (b *Business) QueryVariantByID(ctx context.Context, variantID uuid.UUID) (ProductVariant, error) {
	variant, err := b.storer.QueryVariantByID(ctx, variantID)
	if err != nil {
		return ProductVariant{}, fmt.Errorf("query: variantID[%s]: %w", variantID, err)
	}

	return variant, nil
}

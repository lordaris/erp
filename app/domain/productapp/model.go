package productapp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/money"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/quantity"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

// Product represents information about an individual product for the API.
type Product struct {
	ID               string           `json:"id"`
	UserID           string           `json:"userID"`
	SKU              string           `json:"sku"`
	Barcode          string           `json:"barcode,omitempty"`
	Name             string           `json:"name"`
	Description      string           `json:"description,omitempty"`
	ShortDescription string           `json:"shortDescription,omitempty"`
	Category         string           `json:"category"`
	Subcategory      string           `json:"subcategory,omitempty"`
	UPC              string           `json:"upc,omitempty"`
	Brand            string           `json:"brand,omitempty"`
	Manufacturer     string           `json:"manufacturer,omitempty"`
	Status           string           `json:"status"`
	TaxCategory      string           `json:"taxCategory"`
	UnitOfMeasure    string           `json:"unitOfMeasure"`
	Weight           float64          `json:"weight,omitempty"`
	Length           float64          `json:"length,omitempty"`
	Width            float64          `json:"width,omitempty"`
	Height           float64          `json:"height,omitempty"`
	CostPrice        float64          `json:"costPrice"`
	WholesalePrice   float64          `json:"wholesalePrice,omitempty"`
	RetailPrice      float64          `json:"retailPrice"`
	IsWeighted       bool             `json:"isWeighted,omitempty"`
	IsDigital        bool             `json:"isDigital,omitempty"`
	IsTaxable        bool             `json:"isTaxable,omitempty"`
	ReturnPolicy     string           `json:"returnPolicy,omitempty"`
	HasSerialNumber  bool             `json:"hasSerialNumber,omitempty"`
	HasLotNumber     bool             `json:"hasLotNumber,omitempty"`
	Attributes       interface{}      `json:"attributes,omitempty"`
	ImageURLs        []string         `json:"imageUrls,omitempty"`
	Notes            string           `json:"notes,omitempty"`
	Variants         []ProductVariant `json:"variants,omitempty"`
	CreatedAt        string           `json:"CreatedAt"`
	UpdatedAt        string           `json:"UpdatedAt"`
}

// Encode implements the encoder interface.
func (app Product) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

func toAppProduct(prd productbus.Product) Product {
	variants := make([]ProductVariant, len(prd.Variants))
	for i, v := range prd.Variants {
		variants[i] = toAppProductVariant(v)
	}

	return Product{
		ID:               prd.ID.String(),
		SKU:              prd.SKU,
		Barcode:          prd.Barcode,
		Name:             prd.Name.String(),
		Description:      prd.Description,
		ShortDescription: prd.ShortDescription,
		Category:         prd.Category.String(),
		Subcategory:      prd.Subcategory.String(),
		UPC:              prd.UPC,
		Brand:            prd.Brand,
		Manufacturer:     prd.Manufacturer,
		Status:           prd.Status.String(),
		TaxCategory:      prd.TaxCategory.String(),
		UnitOfMeasure:    prd.UnitOfMeasure.String(),
		Weight:           prd.Weight,
		Length:           prd.Length,
		Width:            prd.Width,
		Height:           prd.Height,
		CostPrice:        prd.CostPrice.Value(),
		WholesalePrice:   prd.WholesalePrice.Value(),
		RetailPrice:      prd.RetailPrice.Value(),
		IsWeighted:       prd.IsWeighted,
		IsDigital:        prd.IsDigital,
		IsTaxable:        prd.IsTaxable,
		ReturnPolicy:     prd.ReturnPolicy,
		HasSerialNumber:  prd.HasSerialNumber,
		HasLotNumber:     prd.HasLotNumber,
		Attributes:       prd.Attributes,
		ImageURLs:        prd.ImageURLs,
		Notes:            prd.Notes,
		Variants:         variants,
		CreatedAt:        prd.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        prd.UpdatedAt.Format(time.RFC3339),
	}
}

func toAppProducts(prds []productbus.Product) []Product {
	app := make([]Product, len(prds))
	for i, prd := range prds {
		app[i] = toAppProduct(prd)
	}

	return app
}

// =============================================================================

// NewProduct defines the data needed to add a new product.
type NewProduct struct {
	SKU              string      `json:"sku,omitempty"`
	Barcode          string      `json:"barcode,omitempty"`
	Name             string      `json:"name" validate:"required"`
	Description      string      `json:"description,omitempty"`
	ShortDescription string      `json:"shortDescription,omitempty"`
	Category         string      `json:"category,omitempty"`
	Subcategory      string      `json:"subcategory,omitempty"`
	UPC              string      `json:"upc,omitempty"`
	Brand            string      `json:"brand,omitempty"`
	Manufacturer     string      `json:"manufacturer,omitempty"`
	Status           string      `json:"status,omitempty"`
	TaxCategory      string      `json:"taxCategory,omitempty"`
	UnitOfMeasure    string      `json:"unitOfMeasure,omitempty"`
	Weight           float64     `json:"weight,omitempty"`
	Length           float64     `json:"length,omitempty"`
	Width            float64     `json:"width,omitempty"`
	Height           float64     `json:"height,omitempty"`
	CostPrice        float64     `json:"costPrice" validate:"required,gte=0"`
	WholesalePrice   float64     `json:"wholesalePrice,omitempty"`
	RetailPrice      float64     `json:"retailPrice,omitempty"`
	IsWeighted       bool        `json:"isWeighted,omitempty"`
	IsDigital        bool        `json:"isDigital,omitempty"`
	IsTaxable        bool        `json:"isTaxable,omitempty"`
	ReturnPolicy     string      `json:"returnPolicy,omitempty"`
	HasSerialNumber  bool        `json:"hasSerialNumber,omitempty"`
	HasLotNumber     bool        `json:"hasLotNumber,omitempty"`
	Attributes       interface{} `json:"attributes,omitempty"`
	ImageURLs        []string    `json:"imageUrls,omitempty"`
	Notes            string      `json:"notes,omitempty"`
}

// UpdateProductImage defines data needed to update a product image
type UpdateProductImage struct {
	ImageURL string `json:"imageUrl" validate:"required,url"`
	AltText  string `json:"altText,omitempty"`
}

// Decode implements the decoder interface.
func (app *UpdateProductImage) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Decode implements the decoder interface.
func (app *NewProduct) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

func toBusNewProduct(ctx context.Context, app NewProduct) (productbus.NewProduct, error) {
	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("getuserid: %w", err)
	}

	name, err := name.Parse(app.Name)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse name: %w", err)
	}

	// Set default values for required fields if not provided
	status := app.Status
	if status == "" {
		status = productstatus.Active
	}

	categoryStr := app.Category
	if categoryStr == "" {
		categoryStr = "General"
	}

	taxCategoryStr := app.TaxCategory
	if taxCategoryStr == "" {
		taxCategoryStr = taxcategory.Standard
	}

	uomStr := app.UnitOfMeasure
	if uomStr == "" {
		uomStr = uom.Each
	}

	// Parse all type-specific fields
	categoryVal, err := category.Parse(categoryStr)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse category: %w", err)
	}

	// Handle subcategory - create empty subcategory if none provided
	var subcategoryVal subcategory.Subcategory
	if app.Subcategory != "" {
		subcategoryVal, err = subcategory.Parse(app.Subcategory)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse subcategory: %w", err)
		}
	} else {
		// Create an empty subcategory
		subcategoryVal, _ = subcategory.Parse("General")
	}

	statusVal, err := productstatus.Parse(status)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse status: %w", err)
	}

	taxCategoryVal, err := taxcategory.Parse(taxCategoryStr)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse tax category: %w", err)
	}

	unitOfMeasureVal, err := uom.Parse(uomStr)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse unit of measure: %w", err)
	}

	costPrice, err := money.Parse(app.CostPrice)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse cost price: %w", err)
	}

	// Default wholesale price to 1.3x cost if not provided
	wholesalePriceVal := app.WholesalePrice
	if wholesalePriceVal == 0 {
		wholesalePriceVal = app.CostPrice * 1.3
	}
	wholesalePrice, err := money.Parse(wholesalePriceVal)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse wholesale price: %w", err)
	}

	// Default retail price to 2x cost if not provided
	retailPriceVal := app.RetailPrice
	if retailPriceVal == 0 {
		retailPriceVal = app.CostPrice * 2
	}
	retailPrice, err := money.Parse(retailPriceVal)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse retail price: %w", err)
	}

	// Convert string array to StringArray type
	imageURLs := productbus.StringArray{}
	if app.ImageURLs != nil {
		imageURLs = app.ImageURLs
	}

	// Convert attributes to JSONMap
	attributes := productbus.JSONMap{}
	if app.Attributes != nil {
		// Handle attributes based on their type
		switch attr := app.Attributes.(type) {
		case map[string]interface{}:
			attributes = attr
		default:
			// Attempt to marshal and unmarshal to handle various input types
			data, err := json.Marshal(app.Attributes)
			if err != nil {
				return productbus.NewProduct{}, fmt.Errorf("parse attributes: %w", err)
			}
			if err := json.Unmarshal(data, &attributes); err != nil {
				return productbus.NewProduct{}, fmt.Errorf("parse attributes: %w", err)
			}
		}
	}

	// Generate SKU if not provided
	sku := app.SKU
	if sku == "" {
		// Simple SKU generation - would be more complex in production
		sku = fmt.Sprintf("%s-%d", strings.ToUpper(app.Name[:min(3, len(app.Name))]), time.Now().Unix())
	}

	bus := productbus.NewProduct{
		UserID:           userID,
		SKU:              sku,
		Barcode:          app.Barcode,
		Name:             name,
		Description:      app.Description,
		ShortDescription: app.ShortDescription,
		Category:         categoryVal,
		Subcategory:      subcategoryVal,
		UPC:              app.UPC,
		Brand:            app.Brand,
		Manufacturer:     app.Manufacturer,
		Status:           statusVal,
		TaxCategory:      taxCategoryVal,
		UnitOfMeasure:    unitOfMeasureVal,
		Weight:           app.Weight,
		Length:           app.Length,
		Width:            app.Width,
		Height:           app.Height,
		CostPrice:        costPrice,
		WholesalePrice:   wholesalePrice,
		RetailPrice:      retailPrice,
		IsWeighted:       app.IsWeighted,
		IsDigital:        app.IsDigital,
		IsTaxable:        app.IsTaxable,
		ReturnPolicy:     app.ReturnPolicy,
		HasSerialNumber:  app.HasSerialNumber,
		HasLotNumber:     app.HasLotNumber,
		Attributes:       attributes,
		ImageURLs:        imageURLs,
		Notes:            app.Notes,
	}

	return bus, nil
}

// Min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// =============================================================================

// UpdateProduct defines the data needed to update a product.
type UpdateProduct struct {
	SKU              *string      `json:"sku,omitempty"`
	Barcode          *string      `json:"barcode,omitempty"`
	Name             *string      `json:"name,omitempty"`
	Description      *string      `json:"description,omitempty"`
	ShortDescription *string      `json:"shortDescription,omitempty"`
	Category         *string      `json:"category,omitempty"`
	Subcategory      *string      `json:"subcategory,omitempty"`
	UPC              *string      `json:"upc,omitempty"`
	Brand            *string      `json:"brand,omitempty"`
	Manufacturer     *string      `json:"manufacturer,omitempty"`
	Status           *string      `json:"status,omitempty"`
	TaxCategory      *string      `json:"taxCategory,omitempty"`
	UnitOfMeasure    *string      `json:"unitOfMeasure,omitempty"`
	Weight           *float64     `json:"weight,omitempty"`
	Length           *float64     `json:"length,omitempty"`
	Width            *float64     `json:"width,omitempty"`
	Height           *float64     `json:"height,omitempty"`
	CostPrice        *float64     `json:"costPrice,omitempty" validate:"omitempty,gte=0"`
	WholesalePrice   *float64     `json:"wholesalePrice,omitempty" validate:"omitempty,gte=0"`
	RetailPrice      *float64     `json:"retailPrice,omitempty" validate:"omitempty,gte=0"`
	IsWeighted       *bool        `json:"isWeighted,omitempty"`
	IsDigital        *bool        `json:"isDigital,omitempty"`
	IsTaxable        *bool        `json:"isTaxable,omitempty"`
	ReturnPolicy     *string      `json:"returnPolicy,omitempty"`
	HasSerialNumber  *bool        `json:"hasSerialNumber,omitempty"`
	HasLotNumber     *bool        `json:"hasLotNumber,omitempty"`
	Attributes       *interface{} `json:"attributes,omitempty"`
	ImageURLs        *[]string    `json:"imageUrls,omitempty"`
	Notes            *string      `json:"notes,omitempty"`
	Quantity         *int         `json:"quantity,omitempty" validate:"omitempty,gte=0"`
}

// Decode implements the decoder interface.
func (app *UpdateProduct) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app NewProduct) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	// Add additional validation checks
	if len(app.Description) > 5000 {
		return fmt.Errorf("description exceeds 5000 character limit")
	}

	if len(app.ShortDescription) > 500 {
		return fmt.Errorf("short description exceeds 500 character limit")
	}

	if app.RetailPrice < app.CostPrice {
		return fmt.Errorf("retail price cannot be less than cost price")
	}

	return nil
}

func toBusUpdateProduct(app UpdateProduct) (productbus.UpdateProduct, error) {
	var nameVal *name.Name
	if app.Name != nil {
		n, err := name.Parse(*app.Name)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse name: %w", err)
		}
		nameVal = &n
	}

	var categoryVal *category.Category
	if app.Category != nil {
		c, err := category.Parse(*app.Category)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse category: %w", err)
		}
		categoryVal = &c
	}

	var subcategoryVal *subcategory.Subcategory
	if app.Subcategory != nil {
		s, err := subcategory.Parse(*app.Subcategory)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse subcategory: %w", err)
		}
		subcategoryVal = &s
	}

	var statusVal *productstatus.ProductStatus
	if app.Status != nil {
		s, err := productstatus.Parse(*app.Status)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse status: %w", err)
		}
		statusVal = &s
	}

	var taxCategoryVal *taxcategory.TaxCategory
	if app.TaxCategory != nil {
		t, err := taxcategory.Parse(*app.TaxCategory)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse tax category: %w", err)
		}
		taxCategoryVal = &t
	}

	var unitOfMeasureVal *uom.UnitOfMeasure
	if app.UnitOfMeasure != nil {
		u, err := uom.Parse(*app.UnitOfMeasure)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse unit of measure: %w", err)
		}
		unitOfMeasureVal = &u
	}

	var costPriceVal *money.Money
	if app.CostPrice != nil {
		c, err := money.Parse(*app.CostPrice)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse cost price: %w", err)
		}
		costPriceVal = &c
	}

	var wholesalePriceVal *money.Money
	if app.WholesalePrice != nil {
		w, err := money.Parse(*app.WholesalePrice)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse wholesale price: %w", err)
		}
		wholesalePriceVal = &w
	}

	var quantityVal *quantity.Quantity
	if app.Quantity != nil {
		q, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse quantity: %w", err)
		}
		quantityVal = &q
	}

	var imageURLsVal *productbus.StringArray
	if app.ImageURLs != nil {
		urls := productbus.StringArray(*app.ImageURLs)
		imageURLsVal = &urls
	}

	var attributesVal *productbus.JSONMap
	if app.Attributes != nil {
		// Convert interface{} to JSONMap
		var jsonMap productbus.JSONMap

		// Handle attributes based on their type
		switch attr := (*app.Attributes).(type) {
		case map[string]interface{}:
			jsonMap = productbus.JSONMap(attr)
		default:
			// Attempt to marshal and unmarshal to handle various input types
			data, err := json.Marshal(*app.Attributes)
			if err != nil {
				return productbus.UpdateProduct{}, fmt.Errorf("parse attributes: %w", err)
			}
			if err := json.Unmarshal(data, &jsonMap); err != nil {
				return productbus.UpdateProduct{}, fmt.Errorf("parse attributes: %w", err)
			}
		}

		attributesVal = &jsonMap
	}

	return productbus.UpdateProduct{
		SKU:             app.SKU,
		Barcode:         app.Barcode,
		Name:            nameVal,
		Description:     app.Description,
		Category:        categoryVal,
		Subcategory:     subcategoryVal,
		UPC:             app.UPC,
		Brand:           app.Brand,
		Manufacturer:    app.Manufacturer,
		Status:          statusVal,
		TaxCategory:     taxCategoryVal,
		UnitOfMeasure:   unitOfMeasureVal,
		Weight:          app.Weight,
		Length:          app.Length,
		Width:           app.Width,
		Height:          app.Height,
		Cost:            costPriceVal,
		MinimumPrice:    wholesalePriceVal,
		Quantity:        quantityVal,
		IsDigital:       app.IsDigital,
		HasSerialNumber: app.HasSerialNumber,
		HasLotNumber:    app.HasLotNumber,
		Attributes:      attributesVal,
		ImageURLs:       imageURLsVal,
	}, nil
}

// =============================================================================

// ProductVariant represents information about a product variant.
type ProductVariant struct {
	ID             string   `json:"id"`
	ProductID      string   `json:"productID"`
	SKU            string   `json:"sku"`
	Barcode        string   `json:"barcode,omitempty"`
	VariantOptions []string `json:"variantOptions"`
	Weight         float64  `json:"weight,omitempty"`
	CostPrice      float64  `json:"costPrice,omitempty"`
	RetailPrice    float64  `json:"retailPrice,omitempty"`
	CurrentPrice   float64  `json:"currentPrice,omitempty"`
	Price          float64  `json:"price"`
	Quantity       int      `json:"quantity"`
	IsActive       bool     `json:"isActive"`
	ImageURL       string   `json:"imageUrl,omitempty"`
	CreatedAt      string   `json:"CreatedAt"`
	UpdatedAt      string   `json:"UpdatedAt"`
}

// Encode implements the encoder interface.
func (app ProductVariant) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

func toAppProductVariant(variant productbus.ProductVariant) ProductVariant {
	return ProductVariant{
		ID:             variant.ID.String(),
		ProductID:      variant.ProductID.String(),
		SKU:            variant.SKU,
		Barcode:        variant.Barcode,
		VariantOptions: variant.VariantOptions,
		Weight:         variant.Weight,
		CostPrice:      variant.CostPrice.Value(),
		RetailPrice:    variant.RetailPrice.Value(),
		CurrentPrice:   variant.CurrentPrice.Value(),
		Price:          variant.Price.Value(),
		Quantity:       variant.Quantity.Value(),
		IsActive:       variant.IsActive,
		ImageURL:       variant.ImageURL,
		CreatedAt:      variant.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      variant.UpdatedAt.Format(time.RFC3339),
	}
}

func toAppProductVariants(variants []productbus.ProductVariant) []ProductVariant {
	app := make([]ProductVariant, len(variants))
	for i, variant := range variants {
		app[i] = toAppProductVariant(variant)
	}
	return app
}

// =============================================================================

// NewProductVariant defines the data needed to add a new product variant.
type NewProductVariant struct {
	ProductID      string   `json:"productID" validate:"required,uuid"`
	SKU            string   `json:"sku" validate:"required"`
	Barcode        string   `json:"barcode,omitempty"`
	VariantOptions []string `json:"variantOptions" validate:"required"`
	Weight         float64  `json:"weight,omitempty"`
	CostPrice      float64  `json:"costPrice,omitempty" validate:"omitempty,gte=0"`
	RetailPrice    float64  `json:"retailPrice,omitempty" validate:"omitempty,gte=0"`
	Price          float64  `json:"price" validate:"required,gte=0"`
	Quantity       int      `json:"quantity" validate:"required,gte=0"`
	IsActive       bool     `json:"isActive"`
	ImageURL       string   `json:"imageUrl,omitempty"`
}

// Decode implements the decoder interface.
func (app *NewProductVariant) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

func toBusNewProductVariant(app NewProductVariant) (productbus.NewProductVariant, error) {
	productID, err := uuid.Parse(app.ProductID)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse productID: %w", err)
	}

	price, err := money.Parse(app.Price)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse price: %w", err)
	}

	qty, err := quantity.Parse(app.Quantity)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse quantity: %w", err)
	}

	variantOptions := productbus.StringArray(app.VariantOptions)

	return productbus.NewProductVariant{
		ProductID:      productID,
		SKU:            app.SKU,
		VariantOptions: variantOptions,
		Price:          price,
		Quantity:       qty,
		IsActive:       app.IsActive,
	}, nil
}

// =============================================================================

// UpdateProductVariant defines the data needed to update a product variant.
type UpdateProductVariant struct {
	SKU            *string   `json:"sku,omitempty"`
	Barcode        *string   `json:"barcode,omitempty"`
	VariantOptions *[]string `json:"variantOptions,omitempty"`
	Weight         *float64  `json:"weight,omitempty"`
	CostPrice      *float64  `json:"costPrice,omitempty" validate:"omitempty,gte=0"`
	RetailPrice    *float64  `json:"retailPrice,omitempty" validate:"omitempty,gte=0"`
	CurrentPrice   *float64  `json:"currentPrice,omitempty" validate:"omitempty,gte=0"`
	Price          *float64  `json:"price,omitempty" validate:"omitempty,gte=0"`
	Quantity       *int      `json:"quantity,omitempty" validate:"omitempty,gte=0"`
	IsActive       *bool     `json:"isActive,omitempty"`
	ImageURL       *string   `json:"imageUrl,omitempty"`
}

// Decode implements the decoder interface.
func (app *UpdateProductVariant) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

func toBusUpdateProductVariant(app UpdateProductVariant) (productbus.UpdateProductVariant, error) {
	var variantOptions *productbus.StringArray
	if app.VariantOptions != nil {
		vo := productbus.StringArray(*app.VariantOptions)
		variantOptions = &vo
	}

	var price *money.Money
	if app.Price != nil {
		p, err := money.Parse(*app.Price)
		if err != nil {
			return productbus.UpdateProductVariant{}, fmt.Errorf("parse price: %w", err)
		}
		price = &p
	}

	var qty *quantity.Quantity
	if app.Quantity != nil {
		q, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return productbus.UpdateProductVariant{}, fmt.Errorf("parse quantity: %w", err)
		}
		qty = &q
	}

	return productbus.UpdateProductVariant{
		SKU:            app.SKU,
		VariantOptions: variantOptions,
		Price:          price,
		Quantity:       qty,
		IsActive:       app.IsActive,
	}, nil
}

// AddProductImage defines data needed to add a product image
type AddProductImage struct {
	ImageURL string `json:"imageUrl" validate:"required,url"`
	AltText  string `json:"altText,omitempty"`
}

// Decode implements the decoder interface.
func (app *AddProductImage) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// ImportResponse represents the response for an import operation
type ImportResponse struct {
	ImportID string `json:"importId"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
}

// Encode implements the encoder interface.
func (app ImportResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

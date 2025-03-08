package productbus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/money"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/quantity"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

// Dimensions represents the physical dimensions of a product.
type Dimensions struct {
	Length float64 `json:"length,omitempty"`
	Width  float64 `json:"width,omitempty"`
	Height float64 `json:"height,omitempty"`
}

// VariantOption represents a single variant option like size or color.
type VariantOption struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ProductVariant represents a specific variant of a product.
type ProductVariant struct {
	ID             string          `json:"id"`
	ProductID      string          `json:"productID"`
	SKU            string          `json:"sku"`
	VariantOptions []VariantOption `json:"variantOptions"`
	Price          float64         `json:"price"`
	Quantity       int             `json:"quantity"`
	IsActive       bool            `json:"isActive"`
	DateCreated    string          `json:"dateCreated"`
	DateUpdated    string          `json:"dateUpdated"`
}

// Product represents information about an individual product.
type Product struct {
	ID              string            `json:"id"`
	UserID          string            `json:"userID"`
	SKU             string            `json:"sku,omitempty"`
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	Category        string            `json:"category,omitempty"`
	Subcategory     string            `json:"subcategory,omitempty"`
	UPC             string            `json:"upc,omitempty"`
	Brand           string            `json:"brand,omitempty"`
	Manufacturer    string            `json:"manufacturer,omitempty"`
	Status          string            `json:"status,omitempty"`
	TaxCategory     string            `json:"taxCategory,omitempty"`
	UnitOfMeasure   string            `json:"unitOfMeasure,omitempty"`
	Weight          float64           `json:"weight,omitempty"`
	Dimensions      Dimensions        `json:"dimensions,omitempty"`
	MSRP            float64           `json:"msrp,omitempty"`
	Cost            float64           `json:"cost"`
	MinimumPrice    float64           `json:"minimumPrice,omitempty"`
	Quantity        int               `json:"quantity"`
	IsDigital       bool              `json:"isDigital,omitempty"`
	HasSerialNumber bool              `json:"hasSerialNumber,omitempty"`
	HasLotNumber    bool              `json:"hasLotNumber,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
	ImageURLs       []string          `json:"imageURLs,omitempty"`
	Variants        []ProductVariant  `json:"variants,omitempty"`
	DateCreated     string            `json:"dateCreated"`
	DateUpdated     string            `json:"dateUpdated"`
}

// Encode implements the encoder interface.
func (app Product) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

// toAppProduct converts a business product to an app product.
func toAppProduct(prd productbus.Product) Product {
	variants := make([]ProductVariant, len(prd.Variants))
	for i, variant := range prd.Variants {
		variants[i] = toAppProductVariant(variant)
	}

	return Product{
		ID:            prd.ID.String(),
		UserID:        prd.UserID.String(),
		SKU:           prd.SKU,
		Name:          prd.Name.String(),
		Description:   prd.Description,
		Category:      prd.Category.String(),
		Subcategory:   prd.Subcategory.String(),
		UPC:           prd.UPC,
		Brand:         prd.Brand,
		Manufacturer:  prd.Manufacturer,
		Status:        prd.Status.String(),
		TaxCategory:   prd.TaxCategory.String(),
		UnitOfMeasure: prd.UnitOfMeasure.String(),
		Weight:        prd.Weight,
		Dimensions: Dimensions{
			Length: prd.Dimensions.Length,
			Width:  prd.Dimensions.Width,
			Height: prd.Dimensions.Height,
		},
		MSRP:            prd.MSRP.Value(),
		Cost:            prd.Cost.Value(),
		MinimumPrice:    prd.MinimumPrice.Value(),
		Quantity:        prd.Quantity.Value(),
		IsDigital:       prd.IsDigital,
		HasSerialNumber: prd.HasSerialNumber,
		HasLotNumber:    prd.HasLotNumber,
		Attributes:      prd.Attributes,
		ImageURLs:       prd.ImageURLs,
		Variants:        variants,
		DateCreated:     prd.DateCreated.Format(time.RFC3339),
		DateUpdated:     prd.DateUpdated.Format(time.RFC3339),
	}
}

// toAppProductVariant converts a business product variant to an app product variant.
func toAppProductVariant(variant productbus.ProductVariant) ProductVariant {
	variantOptions := make([]VariantOption, len(variant.VariantOptions))
	for i, option := range variant.VariantOptions {
		variantOptions[i] = VariantOption{
			Name:  option.Name,
			Value: option.Value,
		}
	}

	return ProductVariant{
		ID:             variant.ID.String(),
		ProductID:      variant.ProductID.String(),
		SKU:            variant.SKU,
		VariantOptions: variantOptions,
		Price:          variant.Price.Value(),
		Quantity:       variant.Quantity.Value(),
		IsActive:       variant.IsActive,
		DateCreated:    variant.DateCreated.Format(time.RFC3339),
		DateUpdated:    variant.DateUpdated.Format(time.RFC3339),
	}
}

// toAppProducts converts business products to app products.
func toAppProducts(prds []productbus.Product) []Product {
	app := make([]Product, len(prds))
	for i, prd := range prds {
		app[i] = toAppProduct(prd)
	}

	return app
}

// ======================================================================
// Input Models

// NewDimensions represents the dimensions when creating a new product.
type NewDimensions struct {
	Length float64 `json:"length,omitempty"`
	Width  float64 `json:"width,omitempty"`
	Height float64 `json:"height,omitempty"`
}

// NewProduct defines the data needed to add a new product.
type NewProduct struct {
	SKU             string            `json:"sku,omitempty" validate:"omitempty,min=3,max=50"`
	Name            string            `json:"name" validate:"required"`
	Description     string            `json:"description,omitempty"`
	Category        string            `json:"category,omitempty" validate:"omitempty,min=2"`
	Subcategory     string            `json:"subcategory,omitempty" validate:"omitempty,min=2"`
	UPC             string            `json:"upc,omitempty" validate:"omitempty,min=12,max=14"`
	Brand           string            `json:"brand,omitempty"`
	Manufacturer    string            `json:"manufacturer,omitempty"`
	Status          string            `json:"status,omitempty" validate:"omitempty,oneof=ACTIVE INACTIVE DISCONTINUED COMING_SOON"`
	TaxCategory     string            `json:"taxCategory,omitempty" validate:"omitempty,oneof=STANDARD REDUCED ZERO EXEMPT"`
	UnitOfMeasure   string            `json:"unitOfMeasure,omitempty" validate:"omitempty,oneof=EACH PAIR KG G L ML M CM BOX PACK"`
	Weight          float64           `json:"weight,omitempty" validate:"omitempty,gte=0"`
	Dimensions      NewDimensions     `json:"dimensions,omitempty"`
	MSRP            float64           `json:"msrp,omitempty" validate:"omitempty,gte=0"`
	Cost            float64           `json:"cost" validate:"required,gte=0"`
	MinimumPrice    float64           `json:"minimumPrice,omitempty" validate:"omitempty,gte=0"`
	Quantity        int               `json:"quantity" validate:"required,gte=0"`
	IsDigital       bool              `json:"isDigital,omitempty"`
	HasSerialNumber bool              `json:"hasSerialNumber,omitempty"`
	HasLotNumber    bool              `json:"hasLotNumber,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
	ImageURLs       []string          `json:"imageURLs,omitempty"`
}

// Decode implements the decoder interface.
func (app *NewProduct) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app NewProduct) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

// toBusNewProduct converts an app new product to a business new product.
func toBusNewProduct(ctx context.Context, app NewProduct) (productbus.NewProduct, error) {
	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("getuserid: %w", err)
	}

	name, err := name.Parse(app.Name)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse name: %w", err)
	}

	var cat category.Category
	if app.Category != "" {
		cat, err = category.Parse(app.Category)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse category: %w", err)
		}
	}

	var subcat subcategory.Subcategory
	if app.Subcategory != "" {
		subcat, err = subcategory.Parse(app.Subcategory)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse subcategory: %w", err)
		}
	}

	var status productstatus.ProductStatus
	if app.Status != "" {
		status, err = productstatus.Parse(app.Status)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse status: %w", err)
		}
	} else {
		status = productstatus.MustParse(productstatus.Active)
	}

	var taxCat taxcategory.TaxCategory
	if app.TaxCategory != "" {
		taxCat, err = taxcategory.Parse(app.TaxCategory)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse tax category: %w", err)
		}
	} else {
		taxCat = taxcategory.MustParse(taxcategory.Standard)
	}

	var unitOfMeasure uom.UnitOfMeasure
	if app.UnitOfMeasure != "" {
		unitOfMeasure, err = uom.Parse(app.UnitOfMeasure)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse unit of measure: %w", err)
		}
	} else {
		unitOfMeasure = uom.MustParse(uom.Each)
	}

	cost, err := money.Parse(app.Cost)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse cost: %w", err)
	}

	var msrp money.Money
	if app.MSRP > 0 {
		msrp, err = money.Parse(app.MSRP)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse msrp: %w", err)
		}
	}

	var minPrice money.Money
	if app.MinimumPrice > 0 {
		minPrice, err = money.Parse(app.MinimumPrice)
		if err != nil {
			return productbus.NewProduct{}, fmt.Errorf("parse minimum price: %w", err)
		}
	}

	quantity, err := quantity.Parse(app.Quantity)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := productbus.NewProduct{
		UserID:        userID,
		SKU:           app.SKU,
		Name:          name,
		Description:   app.Description,
		Category:      cat,
		Subcategory:   subcat,
		UPC:           app.UPC,
		Brand:         app.Brand,
		Manufacturer:  app.Manufacturer,
		Status:        status,
		TaxCategory:   taxCat,
		UnitOfMeasure: unitOfMeasure,
		Weight:        app.Weight,
		Dimensions: productbus.Dimensions{
			Length: app.Dimensions.Length,
			Width:  app.Dimensions.Width,
			Height: app.Dimensions.Height,
		},
		MSRP:            msrp,
		Cost:            cost,
		MinimumPrice:    minPrice,
		Quantity:        quantity,
		IsDigital:       app.IsDigital,
		HasSerialNumber: app.HasSerialNumber,
		HasLotNumber:    app.HasLotNumber,
		Attributes:      app.Attributes,
		ImageURLs:       app.ImageURLs,
	}

	return bus, nil
}

// NewProductVariant defines the data needed to add a new product variant.
type NewProductVariant struct {
	ProductID      string          `json:"productID" validate:"required,uuid"`
	SKU            string          `json:"sku" validate:"required,min=3,max=50"`
	VariantOptions []VariantOption `json:"variantOptions" validate:"required,min=1"`
	Price          float64         `json:"price" validate:"required,gte=0"`
	Quantity       int             `json:"quantity" validate:"required,gte=0"`
	IsActive       bool            `json:"isActive"`
}

// Decode implements the decoder interface.
func (app *NewProductVariant) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app NewProductVariant) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

// toBusNewProductVariant converts an app new product variant to a business new product variant.
func toBusNewProductVariant(app NewProductVariant) (productbus.NewProductVariant, error) {
	productID, err := uuid.Parse(app.ProductID)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse product id: %w", err)
	}

	price, err := money.Parse(app.Price)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse price: %w", err)
	}

	quantity, err := quantity.Parse(app.Quantity)
	if err != nil {
		return productbus.NewProductVariant{}, fmt.Errorf("parse quantity: %w", err)
	}

	variantOptions := make([]productbus.VariantOption, len(app.VariantOptions))
	for i, option := range app.VariantOptions {
		variantOptions[i] = productbus.VariantOption{
			Name:  option.Name,
			Value: option.Value,
		}
	}

	bus := productbus.NewProductVariant{
		ProductID:      productID,
		SKU:            app.SKU,
		VariantOptions: variantOptions,
		Price:          price,
		Quantity:       quantity,
		IsActive:       app.IsActive,
	}

	return bus, nil
}

// ======================================================================
// Update Models

// UpdateDimensions defines what information may be provided to modify product dimensions.
type UpdateDimensions struct {
	Length *float64 `json:"length,omitempty"`
	Width  *float64 `json:"width,omitempty"`
	Height *float64 `json:"height,omitempty"`
}

// UpdateProduct defines what information may be provided to modify an existing Product.
// All fields are optional so clients can send just the fields they want changed.
type UpdateProduct struct {
	SKU             *string            `json:"sku,omitempty" validate:"omitempty,min=3,max=50"`
	Name            *string            `json:"name,omitempty" validate:"omitempty,min=3"`
	Description     *string            `json:"description,omitempty"`
	Category        *string            `json:"category,omitempty" validate:"omitempty,min=2"`
	Subcategory     *string            `json:"subcategory,omitempty" validate:"omitempty,min=2"`
	UPC             *string            `json:"upc,omitempty" validate:"omitempty,min=12,max=14"`
	Brand           *string            `json:"brand,omitempty"`
	Manufacturer    *string            `json:"manufacturer,omitempty"`
	Status          *string            `json:"status,omitempty" validate:"omitempty,oneof=ACTIVE INACTIVE DISCONTINUED COMING_SOON"`
	TaxCategory     *string            `json:"taxCategory,omitempty" validate:"omitempty,oneof=STANDARD REDUCED ZERO EXEMPT"`
	UnitOfMeasure   *string            `json:"unitOfMeasure,omitempty" validate:"omitempty,oneof=EACH PAIR KG G L ML M CM BOX PACK"`
	Weight          *float64           `json:"weight,omitempty" validate:"omitempty,gte=0"`
	Dimensions      *UpdateDimensions  `json:"dimensions,omitempty"`
	MSRP            *float64           `json:"msrp,omitempty" validate:"omitempty,gte=0"`
	Cost            *float64           `json:"cost,omitempty" validate:"omitempty,gte=0"`
	MinimumPrice    *float64           `json:"minimumPrice,omitempty" validate:"omitempty,gte=0"`
	Quantity        *int               `json:"quantity,omitempty" validate:"omitempty,gte=0"`
	IsDigital       *bool              `json:"isDigital,omitempty"`
	HasSerialNumber *bool              `json:"hasSerialNumber,omitempty"`
	HasLotNumber    *bool              `json:"hasLotNumber,omitempty"`
	Attributes      *map[string]string `json:"attributes,omitempty"`
	ImageURLs       *[]string          `json:"imageURLs,omitempty"`
}

// Decode implements the decoder interface.
func (app *UpdateProduct) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app UpdateProduct) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

// toBusUpdateProduct converts an app update product to a business update product.
func toBusUpdateProduct(app UpdateProduct) (productbus.UpdateProduct, error) {
	var err error
	var bus productbus.UpdateProduct

	if app.Name != nil {
		n, err := name.Parse(*app.Name)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse name: %w", err)
		}
		bus.Name = &n
	}

	if app.Category != nil {
		cat, err := category.Parse(*app.Category)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse category: %w", err)
		}
		bus.Category = &cat
	}

	if app.Subcategory != nil {
		subcat, err := subcategory.Parse(*app.Subcategory)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse subcategory: %w", err)
		}
		bus.Subcategory = &subcat
	}

	if app.Status != nil {
		status, err := productstatus.Parse(*app.Status)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse status: %w", err)
		}
		bus.Status = &status
	}

	if app.TaxCategory != nil {
		taxCat, err := taxcategory.Parse(*app.TaxCategory)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse tax category: %w", err)
		}
		bus.TaxCategory = &taxCat
	}

	if app.UnitOfMeasure != nil {
		unitOfMeasure, err := uom.Parse(*app.UnitOfMeasure)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse unit of measure: %w", err)
		}
		bus.UnitOfMeasure = &unitOfMeasure
	}

	if app.Cost != nil {
		cost, err := money.Parse(*app.Cost)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse cost: %w", err)
		}
		bus.Cost = &cost
	}

	if app.MSRP != nil {
		msrp, err := money.Parse(*app.MSRP)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse msrp: %w", err)
		}
		bus.MSRP = &msrp
	}

	if app.MinimumPrice != nil {
		minPrice, err := money.Parse(*app.MinimumPrice)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse minimum price: %w", err)
		}
		bus.MinimumPrice = &minPrice
	}

	if app.Quantity != nil {
		qty, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse quantity: %w", err)
		}
		bus.Quantity = &qty
	}

	if app.Dimensions != nil {
		dims := productbus.Dimensions{
			Length: 0,
			Width:  0,
			Height: 0,
		}

		if app.Dimensions.Length != nil {
			dims.Length = *app.Dimensions.Length
		}

		if app.Dimensions.Width != nil {
			dims.Width = *app.Dimensions.Width
		}

		if app.Dimensions.Height != nil {
			dims.Height = *app.Dimensions.Height
		}

		bus.Dimensions = &dims
	}

	bus.SKU = app.SKU
	bus.Description = app.Description
	bus.UPC = app.UPC
	bus.Brand = app.Brand
	bus.Manufacturer = app.Manufacturer
	bus.Weight = app.Weight
	bus.IsDigital = app.IsDigital
	bus.HasSerialNumber = app.HasSerialNumber
	bus.HasLotNumber = app.HasLotNumber
	bus.Attributes = app.Attributes
	bus.ImageURLs = app.ImageURLs

	return bus, nil
}

// UpdateProductVariant defines what information may be provided to modify an existing ProductVariant.
type UpdateProductVariant struct {
	SKU            *string          `json:"sku,omitempty" validate:"omitempty,min=3,max=50"`
	VariantOptions *[]VariantOption `json:"variantOptions,omitempty" validate:"omitempty,min=1"`
	Price          *float64         `json:"price,omitempty" validate:"omitempty,gte=0"`
	Quantity       *int             `json:"quantity,omitempty" validate:"omitempty,gte=0"`
	IsActive       *bool            `json:"isActive,omitempty"`
}

// Decode implements the decoder interface.
func (app *UpdateProductVariant) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app UpdateProductVariant) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

// toBusUpdateProductVariant converts an app update product variant to a business update product variant.
func toBusUpdateProductVariant(app UpdateProductVariant) (productbus.UpdateProductVariant, error) {
	var bus productbus.UpdateProductVariant

	if app.SKU != nil {
		bus.SKU = app.SKU
	}

	if app.VariantOptions != nil {
		variantOptions := make([]productbus.VariantOption, len(*app.VariantOptions))
		for i, option := range *app.VariantOptions {
			variantOptions[i] = productbus.VariantOption{
				Name:  option.Name,
				Value: option.Value,
			}
		}
		bus.VariantOptions = &variantOptions
	}

	if app.Price != nil {
		price, err := money.Parse(*app.Price)
		if err != nil {
			return productbus.UpdateProductVariant{}, fmt.Errorf("parse price: %w", err)
		}
		bus.Price = &price
	}

	if app.Quantity != nil {
		quantity, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return productbus.UpdateProductVariant{}, fmt.Errorf("parse quantity: %w", err)
		}
		bus.Quantity = &quantity
	}

	if app.IsActive != nil {
		bus.IsActive = app.IsActive
	}

	return bus, nil
}

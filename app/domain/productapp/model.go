package productapp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/types/money"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/quantity"
)

// Product represents information about an individual product.
type Product struct {
	ID          string  `json:"id"`
	UserID      string  `json:"userID"`
	Name        string  `json:"name"`
	Cost        float64 `json:"cost"`
	Quantity    int     `json:"quantity"`
	DateCreated string  `json:"dateCreated"`
	DateUpdated string  `json:"dateUpdated"`
}

// Encode implements the encoder interface.
func (app Product) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

func toAppProduct(prd productbus.Product) Product {
	return Product{
		ID:          prd.ID.String(),
		UserID:      prd.UserID.String(),
		Name:        prd.Name.String(),
		Cost:        prd.Cost.Value(),
		Quantity:    prd.Quantity.Value(),
		DateCreated: prd.DateCreated.Format(time.RFC3339),
		DateUpdated: prd.DateUpdated.Format(time.RFC3339),
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
	Name     string  `json:"name" validate:"required"`
	Cost     float64 `json:"cost" validate:"required,gte=0"`
	Quantity int     `json:"quantity" validate:"required,gte=1"`
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

func toBusNewProduct(ctx context.Context, app NewProduct) (productbus.NewProduct, error) {
	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("getuserid: %w", err)
	}

	name, err := name.Parse(app.Name)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse name: %w", err)
	}

	cost, err := money.Parse(app.Cost)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse cost: %w", err)
	}

	quantity, err := quantity.Parse(app.Quantity)
	if err != nil {
		return productbus.NewProduct{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := productbus.NewProduct{
		UserID:   userID,
		Name:     name,
		Cost:     cost,
		Quantity: quantity,
	}

	return bus, nil
}

// =============================================================================

// UpdateProduct defines the data needed to update a product.
type UpdateProduct struct {
	Name     *string  `json:"name"`
	Cost     *float64 `json:"cost" validate:"omitempty,gte=0"`
	Quantity *int     `json:"quantity" validate:"omitempty,gte=1"`
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

func toBusUpdateProduct(app UpdateProduct) (productbus.UpdateProduct, error) {
	var nme *name.Name
	if app.Name != nil {
		nm, err := name.Parse(*app.Name)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse: %w", err)
		}
		nme = &nm
	}

	var cost *money.Money
	if app.Cost != nil {
		cst, err := money.Parse(*app.Cost)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse: %w", err)
		}
		cost = &cst
	}

	var qnt *quantity.Quantity
	if app.Quantity != nil {
		qn, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return productbus.UpdateProduct{}, fmt.Errorf("parse: %w", err)
		}
		qnt = &qn
	}

	bus := productbus.UpdateProduct{
		Name:     nme,
		Cost:     cost,
		Quantity: qnt,
	}

	return bus, nil
}

// ProductVariant represents information about a product variant.
type ProductVariant struct {
	ID             string   `json:"id"`
	ProductID      string   `json:"productID"`
	SKU            string   `json:"sku"`
	VariantOptions []string `json:"variantOptions"`
	Price          float64  `json:"price"`
	Quantity       int      `json:"quantity"`
	IsActive       bool     `json:"isActive"`
	DateCreated    string   `json:"dateCreated"`
	DateUpdated    string   `json:"dateUpdated"`
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
		VariantOptions: variant.VariantOptions,
		Price:          variant.Price.Value(),
		Quantity:       variant.Quantity.Value(),
		IsActive:       variant.IsActive,
		DateCreated:    variant.DateCreated.Format(time.RFC3339),
		DateUpdated:    variant.DateUpdated.Format(time.RFC3339),
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
	VariantOptions []string `json:"variantOptions" validate:"required"`
	Price          float64  `json:"price" validate:"required,gte=0"`
	Quantity       int      `json:"quantity" validate:"required,gte=0"`
	IsActive       bool     `json:"isActive"`
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

	return productbus.NewProductVariant{
		ProductID:      productID,
		SKU:            app.SKU,
		VariantOptions: productbus.StringArray(app.VariantOptions),
		Price:          price,
		Quantity:       qty,
		IsActive:       app.IsActive,
	}, nil
}

// =============================================================================

// UpdateProductVariant defines the data needed to update a product variant.
type UpdateProductVariant struct {
	SKU            *string   `json:"sku,omitempty"`
	VariantOptions *[]string `json:"variantOptions,omitempty"`
	Price          *float64  `json:"price,omitempty" validate:"omitempty,gte=0"`
	Quantity       *int      `json:"quantity,omitempty" validate:"omitempty,gte=0"`
	IsActive       *bool     `json:"isActive,omitempty"`
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

func toBusUpdateProductVariant(app UpdateProductVariant) (productbus.UpdateProductVariant, error) {
	var sku *string
	if app.SKU != nil {
		sku = app.SKU
	}

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
		SKU:            sku,
		VariantOptions: variantOptions,
		Price:          price,
		Quantity:       qty,
		IsActive:       app.IsActive,
	}, nil
}

package productdb

import (
	"fmt"
	"time"

	"github.com/google/uuid"
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

// product represents a product in the database.
type product struct {
	ID               uuid.UUID              `db:"product_id"`
	UserID           uuid.UUID              `db:"user_id"` // Keep this as it might be needed
	SKU              string                 `db:"sku"`
	Barcode          string                 `db:"barcode"`
	Name             string                 `db:"name"`
	Description      string                 `db:"description"`
	ShortDescription string                 `db:"short_description"`
	Category         string                 `db:"category"`
	Subcategory      string                 `db:"subcategory"`
	UPC              string                 `db:"upc"`
	Brand            string                 `db:"brand"`
	Manufacturer     string                 `db:"manufacturer"`
	Status           string                 `db:"status"`
	TaxCategory      string                 `db:"tax_category"`
	UnitOfMeasure    string                 `db:"unit_of_measure"`
	Weight           float64                `db:"weight"`
	Length           float64                `db:"length"`
	Width            float64                `db:"width"`
	Height           float64                `db:"height"`
	CostPrice        float64                `db:"cost_price"`
	WholesalePrice   float64                `db:"wholesale_price"`
	RetailPrice      float64                `db:"retail_price"`
	IsWeighted       bool                   `db:"is_weighted"`
	IsDigital        bool                   `db:"is_digital"`
	IsTaxable        bool                   `db:"is_taxable"`
	ReturnPolicy     string                 `db:"return_policy"`
	HasSerialNumber  bool                   `db:"has_serial_number"`
	HasLotNumber     bool                   `db:"has_lot_number"`
	Attributes       productbus.JSONMap     `db:"attributes"`
	ImageURLs        productbus.StringArray `db:"image_urls"`
	Notes            string                 `db:"notes"`
	RelatedProducts  uuid.UUID              `db:"related_products"`
	CreatedAt        time.Time              `db:"created_at"`
	UpdatedAt        time.Time              `db:"updated_at"`
}

// productVariant represents a product variant in the database.
type productVariant struct {
	ID             uuid.UUID              `db:"variant_id"`
	ProductID      uuid.UUID              `db:"product_id"`
	SKU            string                 `db:"sku"`
	Barcode        string                 `db:"barcode"`
	VariantOptions productbus.StringArray `db:"variant_options"`
	Weight         float64                `db:"weight"`
	CostPrice      float64                `db:"cost_price"`
	RetailPrice    float64                `db:"retail_price"`
	CurrentPrice   float64                `db:"current_price"`
	Price          float64                `db:"price"`
	Quantity       int                    `db:"quantity"`
	IsActive       bool                   `db:"is_active"`
	ImageURL       string                 `db:"image_url"`
	CreatedAt      time.Time              `db:"created_at"`
	UpdatedAt      time.Time              `db:"updated_at"`
}

func toDBProduct(bus productbus.Product) product {
	db := product{
		ID:               bus.ID,
		UserID:           bus.UserID,
		SKU:              bus.SKU,
		Barcode:          bus.Barcode,
		Name:             bus.Name.String(),
		Description:      bus.Description,
		ShortDescription: bus.ShortDescription,
		Category:         bus.Category.String(),
		Subcategory:      bus.Subcategory.String(),
		UPC:              bus.UPC,
		Brand:            bus.Brand,
		Manufacturer:     bus.Manufacturer,
		Status:           bus.Status.String(),
		TaxCategory:      bus.TaxCategory.String(),
		UnitOfMeasure:    bus.UnitOfMeasure.String(),
		Weight:           bus.Weight,
		Length:           bus.Length,
		Width:            bus.Width,
		Height:           bus.Height,
		CostPrice:        bus.CostPrice.Value(),
		WholesalePrice:   bus.WholesalePrice.Value(),
		RetailPrice:      bus.RetailPrice.Value(),
		IsWeighted:       bus.IsWeighted,
		IsDigital:        bus.IsDigital,
		IsTaxable:        bus.IsTaxable,
		ReturnPolicy:     bus.ReturnPolicy,
		HasSerialNumber:  bus.HasSerialNumber,
		HasLotNumber:     bus.HasLotNumber,
		Attributes:       bus.Attributes,
		ImageURLs:        bus.ImageURLs,
		Notes:            bus.Notes,
		RelatedProducts:  bus.RelatedProducts,
		CreatedAt:        bus.CreatedAt.UTC(),
		UpdatedAt:        bus.UpdatedAt.UTC(),
	}

	return db
}

func toDBVariant(bus productbus.ProductVariant) productVariant {
	db := productVariant{
		ID:             bus.ID,
		ProductID:      bus.ProductID,
		SKU:            bus.SKU,
		Barcode:        bus.Barcode,
		VariantOptions: bus.VariantOptions,
		Weight:         bus.Weight,
		CostPrice:      bus.CostPrice.Value(),
		RetailPrice:    bus.RetailPrice.Value(),
		CurrentPrice:   bus.CurrentPrice.Value(),
		Price:          bus.Price.Value(),
		Quantity:       bus.Quantity.Value(),
		IsActive:       bus.IsActive,
		ImageURL:       bus.ImageURL,
		CreatedAt:      bus.CreatedAt.UTC(),
		UpdatedAt:      bus.UpdatedAt.UTC(),
	}

	return db
}

func toBusProduct(db product) (productbus.Product, error) {
	name, err := name.Parse(db.Name)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse name: %w", err)
	}

	cat, err := category.Parse(db.Category)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse category: %w", err)
	}

	subcat, err := subcategory.Parse(db.Subcategory)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse subcategory: %w", err)
	}

	status, err := productstatus.Parse(db.Status)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse status: %w", err)
	}

	taxcat, err := taxcategory.Parse(db.TaxCategory)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse tax category: %w", err)
	}

	uom, err := uom.Parse(db.UnitOfMeasure)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse unit of measure: %w", err)
	}

	costPrice, err := money.Parse(db.CostPrice)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse cost price: %w", err)
	}

	wholesalePrice, err := money.Parse(db.WholesalePrice)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse wholesale price: %w", err)
	}

	retailPrice, err := money.Parse(db.RetailPrice)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse retail price: %w", err)
	}

	bus := productbus.Product{
		ID:               db.ID,
		UserID:           db.UserID,
		SKU:              db.SKU,
		Barcode:          db.Barcode,
		Name:             name,
		Description:      db.Description,
		ShortDescription: db.ShortDescription,
		Category:         cat,
		Subcategory:      subcat,
		UPC:              db.UPC,
		Brand:            db.Brand,
		Manufacturer:     db.Manufacturer,
		Status:           status,
		TaxCategory:      taxcat,
		UnitOfMeasure:    uom,
		Weight:           db.Weight,
		Length:           db.Length,
		Width:            db.Width,
		Height:           db.Height,
		CostPrice:        costPrice,
		WholesalePrice:   wholesalePrice,
		RetailPrice:      retailPrice,
		IsWeighted:       db.IsWeighted,
		IsDigital:        db.IsDigital,
		IsTaxable:        db.IsTaxable,
		ReturnPolicy:     db.ReturnPolicy,
		HasSerialNumber:  db.HasSerialNumber,
		HasLotNumber:     db.HasLotNumber,
		Attributes:       db.Attributes,
		ImageURLs:        db.ImageURLs,
		Notes:            db.Notes,
		RelatedProducts:  db.RelatedProducts,
		CreatedAt:        db.CreatedAt.In(time.Local),
		UpdatedAt:        db.UpdatedAt.In(time.Local),
	}

	return bus, nil
}

func toBusVariant(db productVariant) (productbus.ProductVariant, error) {
	price, err := money.Parse(db.Price)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse price: %w", err)
	}

	costPrice, err := money.Parse(db.CostPrice)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse cost price: %w", err)
	}

	retailPrice, err := money.Parse(db.RetailPrice)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse retail price: %w", err)
	}

	currentPrice, err := money.Parse(db.CurrentPrice)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse current price: %w", err)
	}

	quantity, err := quantity.Parse(db.Quantity)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := productbus.ProductVariant{
		ID:             db.ID,
		ProductID:      db.ProductID,
		SKU:            db.SKU,
		Barcode:        db.Barcode,
		VariantOptions: db.VariantOptions,
		Weight:         db.Weight,
		CostPrice:      costPrice,
		RetailPrice:    retailPrice,
		CurrentPrice:   currentPrice,
		Price:          price,
		Quantity:       quantity,
		IsActive:       db.IsActive,
		ImageURL:       db.ImageURL,
		CreatedAt:      db.CreatedAt.In(time.Local),
		UpdatedAt:      db.UpdatedAt.In(time.Local),
	}

	return bus, nil
}

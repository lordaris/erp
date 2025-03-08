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
	ID              uuid.UUID              `db:"product_id"`
	UserID          uuid.UUID              `db:"user_id"`
	SKU             string                 `db:"sku"`
	Name            string                 `db:"name"`
	Description     string                 `db:"description"`
	Category        string                 `db:"category"`
	Subcategory     string                 `db:"subcategory"`
	UPC             string                 `db:"upc"`
	Brand           string                 `db:"brand"`
	Manufacturer    string                 `db:"manufacturer"`
	Status          string                 `db:"status"`
	TaxCategory     string                 `db:"tax_category"`
	UnitOfMeasure   string                 `db:"unit_of_measure"`
	Weight          float64                `db:"weight"`
	Length          float64                `db:"length"`
	Width           float64                `db:"width"`
	Height          float64                `db:"height"`
	MSRP            float64                `db:"msrp"`
	Cost            float64                `db:"cost"`
	MinimumPrice    float64                `db:"minimum_price"`
	Quantity        int                    `db:"quantity"`
	IsDigital       bool                   `db:"is_digital"`
	HasSerialNumber bool                   `db:"has_serial_number"`
	HasLotNumber    bool                   `db:"has_lot_number"`
	Attributes      productbus.JSONMap     `db:"attributes"`
	ImageURLs       productbus.StringArray `db:"image_urls"`
	DateCreated     time.Time              `db:"date_created"`
	DateUpdated     time.Time              `db:"date_updated"`
}

// productVariant represents a product variant in the database.
type productVariant struct {
	ID             uuid.UUID              `db:"variant_id"`
	ProductID      uuid.UUID              `db:"product_id"`
	SKU            string                 `db:"sku"`
	VariantOptions productbus.StringArray `db:"variant_options"`
	Price          float64                `db:"price"`
	Quantity       int                    `db:"quantity"`
	IsActive       bool                   `db:"is_active"`
	DateCreated    time.Time              `db:"date_created"`
	DateUpdated    time.Time              `db:"date_updated"`
}

func toDBProduct(bus productbus.Product) product {
	db := product{
		ID:              bus.ID,
		UserID:          bus.UserID,
		SKU:             bus.SKU,
		Name:            bus.Name.String(),
		Description:     bus.Description,
		Category:        bus.Category.String(),
		Subcategory:     bus.Subcategory.String(),
		UPC:             bus.UPC,
		Brand:           bus.Brand,
		Manufacturer:    bus.Manufacturer,
		Status:          bus.Status.String(),
		TaxCategory:     bus.TaxCategory.String(),
		UnitOfMeasure:   bus.UnitOfMeasure.String(),
		Weight:          bus.Weight,
		Length:          bus.Length,
		Width:           bus.Width,
		Height:          bus.Height,
		MSRP:            bus.MSRP.Value(),
		Cost:            bus.Cost.Value(),
		MinimumPrice:    bus.MinimumPrice.Value(),
		Quantity:        bus.Quantity.Value(),
		IsDigital:       bus.IsDigital,
		HasSerialNumber: bus.HasSerialNumber,
		HasLotNumber:    bus.HasLotNumber,
		Attributes:      bus.Attributes,
		ImageURLs:       bus.ImageURLs,
		DateCreated:     bus.DateCreated.UTC(),
		DateUpdated:     bus.DateUpdated.UTC(),
	}

	return db
}

func toDBVariant(bus productbus.ProductVariant) productVariant {
	db := productVariant{
		ID:             bus.ID,
		ProductID:      bus.ProductID,
		SKU:            bus.SKU,
		VariantOptions: bus.VariantOptions,
		Price:          bus.Price.Value(),
		Quantity:       bus.Quantity.Value(),
		IsActive:       bus.IsActive,
		DateCreated:    bus.DateCreated.UTC(),
		DateUpdated:    bus.DateUpdated.UTC(),
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

	cost, err := money.Parse(db.Cost)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse cost: %w", err)
	}

	msrp, err := money.Parse(db.MSRP)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse msrp: %w", err)
	}

	minPrice, err := money.Parse(db.MinimumPrice)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse minimum price: %w", err)
	}

	quantity, err := quantity.Parse(db.Quantity)
	if err != nil {
		return productbus.Product{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := productbus.Product{
		ID:              db.ID,
		UserID:          db.UserID,
		SKU:             db.SKU,
		Name:            name,
		Description:     db.Description,
		Category:        cat,
		Subcategory:     subcat,
		UPC:             db.UPC,
		Brand:           db.Brand,
		Manufacturer:    db.Manufacturer,
		Status:          status,
		TaxCategory:     taxcat,
		UnitOfMeasure:   uom,
		Weight:          db.Weight,
		Length:          db.Length,
		Width:           db.Width,
		Height:          db.Height,
		MSRP:            msrp,
		Cost:            cost,
		MinimumPrice:    minPrice,
		Quantity:        quantity,
		IsDigital:       db.IsDigital,
		HasSerialNumber: db.HasSerialNumber,
		HasLotNumber:    db.HasLotNumber,
		Attributes:      db.Attributes,
		ImageURLs:       db.ImageURLs,
		DateCreated:     db.DateCreated.In(time.Local),
		DateUpdated:     db.DateUpdated.In(time.Local),
	}

	return bus, nil
}

func toBusVariant(db productVariant) (productbus.ProductVariant, error) {
	price, err := money.Parse(db.Price)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse price: %w", err)
	}

	quantity, err := quantity.Parse(db.Quantity)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := productbus.ProductVariant{
		ID:             db.ID,
		ProductID:      db.ProductID,
		SKU:            db.SKU,
		VariantOptions: db.VariantOptions,
		Price:          price,
		Quantity:       quantity,
		IsActive:       db.IsActive,
		DateCreated:    db.DateCreated.In(time.Local),
		DateUpdated:    db.DateUpdated.In(time.Local),
	}

	return bus, nil
}

func toBusProducts(dbs []product) ([]productbus.Product, error) {
	products := make([]productbus.Product, len(dbs))

	for i, db := range dbs {
		var err error
		products[i], err = toBusProduct(db)
		if err != nil {
			return nil, fmt.Errorf("converting product at index %d: %w", i, err)
		}
	}

	return products, nil
}

func toBusVariants(dbs []productVariant) ([]productbus.ProductVariant, error) {
	variants := make([]productbus.ProductVariant, len(dbs))

	for i, db := range dbs {
		var err error
		variants[i], err = toBusVariant(db)
		if err != nil {
			return nil, fmt.Errorf("converting variant at index %d: %w", i, err)
		}
	}

	return variants, nil
}

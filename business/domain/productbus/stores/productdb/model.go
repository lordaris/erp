package productdb

import (
	"database/sql/driver"
	"encoding/json"
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

// JSONMap is used for storing the Attributes map in the database.
type JSONMap map[string]string

// Value implements the driver.Valuer interface for JSONMap.
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for JSONMap.
func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}

	data, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("invalid data type for JSONMap: %T", value)
	}

	return json.Unmarshal(data, m)
}

// StringArray is used for storing string slices in the database.
type StringArray []string

// Value implements the driver.Valuer interface for StringArray.
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface for StringArray.
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	data, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("invalid data type for StringArray: %T", value)
	}

	return json.Unmarshal(data, a)
}

// Dimensions represents the product dimensions in the database.
type dbDimensions struct {
	Length float64 `db:"length"`
	Width  float64 `db:"width"`
	Height float64 `db:"height"`
}

// product represents a product in the database.
type product struct {
	ID              uuid.UUID   `db:"product_id"`
	UserID          uuid.UUID   `db:"user_id"`
	SKU             string      `db:"sku"`
	Name            string      `db:"name"`
	Description     string      `db:"description"`
	Category        string      `db:"category"`
	Subcategory     string      `db:"subcategory"`
	UPC             string      `db:"upc"`
	Brand           string      `db:"brand"`
	Manufacturer    string      `db:"manufacturer"`
	Status          string      `db:"status"`
	TaxCategory     string      `db:"tax_category"`
	UnitOfMeasure   string      `db:"unit_of_measure"`
	Weight          float64     `db:"weight"`
	Length          float64     `db:"length"`
	Width           float64     `db:"width"`
	Height          float64     `db:"height"`
	MSRP            float64     `db:"msrp"`
	Cost            float64     `db:"cost"`
	MinimumPrice    float64     `db:"minimum_price"`
	Quantity        int         `db:"quantity"`
	IsDigital       bool        `db:"is_digital"`
	HasSerialNumber bool        `db:"has_serial_number"`
	HasLotNumber    bool        `db:"has_lot_number"`
	Attributes      JSONMap     `db:"attributes"`
	ImageURLs       StringArray `db:"image_urls"`
	DateCreated     time.Time   `db:"date_created"`
	DateUpdated     time.Time   `db:"date_updated"`
}

// productVariant represents a product variant in the database.
type productVariant struct {
	ID             uuid.UUID   `db:"variant_id"`
	ProductID      uuid.UUID   `db:"product_id"`
	SKU            string      `db:"sku"`
	VariantOptions StringArray `db:"variant_options"`
	Price          float64     `db:"price"`
	Quantity       int         `db:"quantity"`
	IsActive       bool        `db:"is_active"`
	DateCreated    time.Time   `db:"date_created"`
	DateUpdated    time.Time   `db:"date_updated"`
}

// toDBProduct converts the business product model to a database product.
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
		Length:          bus.Dimensions.Length,
		Width:           bus.Dimensions.Width,
		Height:          bus.Dimensions.Height,
		MSRP:            bus.MSRP.Value(),
		Cost:            bus.Cost.Value(),
		MinimumPrice:    bus.MinimumPrice.Value(),
		Quantity:        bus.Quantity.Value(),
		IsDigital:       bus.IsDigital,
		HasSerialNumber: bus.HasSerialNumber,
		HasLotNumber:    bus.HasLotNumber,
		Attributes:      JSONMap(bus.Attributes),
		ImageURLs:       StringArray(bus.ImageURLs),
		DateCreated:     bus.DateCreated.UTC(),
		DateUpdated:     bus.DateUpdated.UTC(),
	}

	return db
}

// toDBProductVariant converts the business product variant model to a database product variant.
func toDBProductVariant(bus productbus.ProductVariant) (productVariant, error) {
	// Convert variant options to JSON
	optionsJSON, err := json.Marshal(bus.VariantOptions)
	if err != nil {
		return productVariant{}, fmt.Errorf("marshal variant options: %w", err)
	}

	var optionsArr StringArray
	err = json.Unmarshal(optionsJSON, &optionsArr)
	if err != nil {
		return productVariant{}, fmt.Errorf("unmarshal variant options: %w", err)
	}

	db := productVariant{
		ID:             bus.ID,
		ProductID:      bus.ProductID,
		SKU:            bus.SKU,
		VariantOptions: optionsArr,
		Price:          bus.Price.Value(),
		Quantity:       bus.Quantity.Value(),
		IsActive:       bus.IsActive,
		DateCreated:    bus.DateCreated.UTC(),
		DateUpdated:    bus.DateUpdated.UTC(),
	}

	return db, nil
}

// toBusProduct converts a database product to a business product.
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
		return productbus.Product{}, fmt.Errorf("parse product status: %w", err)
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

	// Convert map from database type to Go map
	attributes := make(map[string]string)
	for k, v := range db.Attributes {
		attributes[k] = v
	}

	// Convert image URLs array from database type to Go slice
	imageURLs := make([]string, len(db.ImageURLs))
	for i, v := range db.ImageURLs {
		imageURLs[i] = v
	}

	bus := productbus.Product{
		ID:            db.ID,
		UserID:        db.UserID,
		SKU:           db.SKU,
		Name:          name,
		Description:   db.Description,
		Category:      cat,
		Subcategory:   subcat,
		UPC:           db.UPC,
		Brand:         db.Brand,
		Manufacturer:  db.Manufacturer,
		Status:        status,
		TaxCategory:   taxcat,
		UnitOfMeasure: uom,
		Weight:        db.Weight,
		Dimensions: productbus.Dimensions{
			Length: db.Length,
			Width:  db.Width,
			Height: db.Height,
		},
		MSRP:            msrp,
		Cost:            cost,
		MinimumPrice:    minPrice,
		Quantity:        quantity,
		IsDigital:       db.IsDigital,
		HasSerialNumber: db.HasSerialNumber,
		HasLotNumber:    db.HasLotNumber,
		Attributes:      attributes,
		ImageURLs:       imageURLs,
		DateCreated:     db.DateCreated.In(time.Local),
		DateUpdated:     db.DateUpdated.In(time.Local),
	}

	return bus, nil
}

// toBusProductVariant converts a database product variant to a business product variant.
func toBusProductVariant(db productVariant) (productbus.ProductVariant, error) {
	var variantOptions []productbus.VariantOption

	// Convert from StringArray to JSON string first
	optionsJSON, err := json.Marshal(db.VariantOptions)
	if err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("marshal variant options: %w", err)
	}

	// Then unmarshal into the target struct
	if err := json.Unmarshal(optionsJSON, &variantOptions); err != nil {
		return productbus.ProductVariant{}, fmt.Errorf("unmarshal variant options: %w", err)
	}

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
		VariantOptions: variantOptions,
		Price:          price,
		Quantity:       quantity,
		IsActive:       db.IsActive,
		DateCreated:    db.DateCreated.In(time.Local),
		DateUpdated:    db.DateUpdated.In(time.Local),
	}

	return bus, nil
}

// toBusProducts converts database products to business products.
func toBusProducts(dbs []product) ([]productbus.Product, error) {
	bus := make([]productbus.Product, len(dbs))

	for i, db := range dbs {
		var err error
		bus[i], err = toBusProduct(db)
		if err != nil {
			return nil, err
		}
	}

	return bus, nil
}

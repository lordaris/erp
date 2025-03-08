package productbus

import (
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/money"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/quantity"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

// Product represents an individual product.
type Product struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	SKU             string
	Name            name.Name
	Description     string
	Category        category.Category
	Subcategory     subcategory.Subcategory
	UPC             string
	Brand           string
	Manufacturer    string
	Status          productstatus.ProductStatus
	TaxCategory     taxcategory.TaxCategory
	UnitOfMeasure   uom.UnitOfMeasure
	Weight          float64
	Length          float64
	Width           float64
	Height          float64
	MSRP            money.Money
	Cost            money.Money
	MinimumPrice    money.Money
	Quantity        quantity.Quantity
	IsDigital       bool
	HasSerialNumber bool
	HasLotNumber    bool
	Attributes      JSONMap
	ImageURLs       StringArray
	Variants        []ProductVariant
	DateCreated     time.Time
	DateUpdated     time.Time
}

// ProductVariant represents a product variant.
type ProductVariant struct {
	ID             uuid.UUID
	ProductID      uuid.UUID
	SKU            string
	VariantOptions StringArray
	Price          money.Money
	Quantity       quantity.Quantity
	IsActive       bool
	DateCreated    time.Time
	DateUpdated    time.Time
}

// NewProduct is what we require from clients when adding a Product.
type NewProduct struct {
	UserID          uuid.UUID
	SKU             string
	Name            name.Name
	Description     string
	Category        category.Category
	Subcategory     subcategory.Subcategory
	UPC             string
	Brand           string
	Manufacturer    string
	Status          productstatus.ProductStatus
	TaxCategory     taxcategory.TaxCategory
	UnitOfMeasure   uom.UnitOfMeasure
	Weight          float64
	Length          float64
	Width           float64
	Height          float64
	MSRP            money.Money
	Cost            money.Money
	MinimumPrice    money.Money
	Quantity        quantity.Quantity
	IsDigital       bool
	HasSerialNumber bool
	HasLotNumber    bool
	Attributes      JSONMap
	ImageURLs       StringArray
}

// NewProductVariant is what we require from clients when adding a ProductVariant.
type NewProductVariant struct {
	ProductID      uuid.UUID
	SKU            string
	VariantOptions StringArray
	Price          money.Money
	Quantity       quantity.Quantity
	IsActive       bool
}

// UpdateProduct defines what information may be provided to modify an
// existing Product. All fields are optional so clients can send just the
// fields they want changed. It uses pointer fields so we can differentiate
// between a field that was not provided and a field that was provided as
// explicitly blank.
type UpdateProduct struct {
	SKU             *string
	Name            *name.Name
	Description     *string
	Category        *category.Category
	Subcategory     *subcategory.Subcategory
	UPC             *string
	Brand           *string
	Manufacturer    *string
	Status          *productstatus.ProductStatus
	TaxCategory     *taxcategory.TaxCategory
	UnitOfMeasure   *uom.UnitOfMeasure
	Weight          *float64
	Length          *float64
	Width           *float64
	Height          *float64
	MSRP            *money.Money
	Cost            *money.Money
	MinimumPrice    *money.Money
	Quantity        *quantity.Quantity
	IsDigital       *bool
	HasSerialNumber *bool
	HasLotNumber    *bool
	Attributes      *JSONMap
	ImageURLs       *StringArray
}

// UpdateProductVariant defines what information may be provided to modify an
// existing ProductVariant.
type UpdateProductVariant struct {
	SKU            *string
	VariantOptions *StringArray
	Price          *money.Money
	Quantity       *quantity.Quantity
	IsActive       *bool
}

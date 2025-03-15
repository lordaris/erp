package productbus

import (
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

// QueryFilter holds the available fields a query can be filtered on.
// We are using pointer semantics because the With API mutates the value.
type QueryFilter struct {
	// Core identification
	ID      *uuid.UUID
	UserID  *uuid.UUID
	SKU     *string
	Barcode *string
	UPC     *string
	Name    *name.Name

	// Categorization
	Category      *category.Category
	Subcategory   *subcategory.Subcategory
	Brand         *string
	Manufacturer  *string
	Status        *productstatus.ProductStatus
	TaxCategory   *taxcategory.TaxCategory
	UnitOfMeasure *uom.UnitOfMeasure

	// Description fields
	Description      *string
	ShortDescription *string
	Notes            *string

	// Pricing fields
	CostPrice         *float64
	WholesalePrice    *float64
	RetailPrice       *float64
	MinCostPrice      *float64
	MaxCostPrice      *float64
	MinRetailPrice    *float64
	MaxRetailPrice    *float64
	MinWholesalePrice *float64
	MaxWholesalePrice *float64

	// Inventory
	Quantity    *int
	MinQuantity *int
	MaxQuantity *int

	// Physical attributes
	Weight    *float64
	MinWeight *float64
	MaxWeight *float64
	Length    *float64
	MinLength *float64
	MaxLength *float64
	Width     *float64
	MinWidth  *float64
	MaxWidth  *float64
	Height    *float64
	MinHeight *float64
	MaxHeight *float64

	// Boolean flags
	IsDigital       *bool
	IsWeighted      *bool
	IsTaxable       *bool
	HasSerialNumber *bool
	HasLotNumber    *bool
	HasImages       *bool
	HasVariants     *bool

	// Time-based filtering
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	UpdatedAfter  *time.Time
	UpdatedBefore *time.Time

	// Special search parameters
	ReturnPolicy *string
	SearchTerm   *string
	RelatedTo    *uuid.UUID

	// Variant filtering
	HasVariantWithSKU         *string
	HasVariantWithBarcode     *string
	HasVariantWithMinPrice    *float64
	HasVariantWithMaxPrice    *float64
	HasVariantWithMinQuantity *int
	HasVariantWithMaxQuantity *int
}

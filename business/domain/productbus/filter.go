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
	ID              *uuid.UUID
	UserID          *uuid.UUID
	SKU             *string
	Name            *name.Name
	Category        *category.Category
	Subcategory     *subcategory.Subcategory
	Brand           *string
	Manufacturer    *string
	Status          *productstatus.ProductStatus
	TaxCategory     *taxcategory.TaxCategory
	UnitOfMeasure   *uom.UnitOfMeasure
	Cost            *float64
	MinimumPrice    *float64
	MSRP            *float64
	Quantity        *int
	IsDigital       *bool
	HasSerialNumber *bool
	HasLotNumber    *bool
	MinWeight       *float64
	MaxWeight       *float64
	MinPrice        *float64
	MaxPrice        *float64
	MinMSRP         *float64
	MaxMSRP         *float64
	MinQuantity     *int
	MaxQuantity     *int
	HasImages       *bool
	CreatedAfter    *time.Time
	CreatedBefore   *time.Time
	UpdatedAfter    *time.Time
	UpdatedBefore   *time.Time
	SearchTerm      *string
}

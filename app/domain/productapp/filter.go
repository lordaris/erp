package productapp

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

type queryParams struct {
	// Pagination and ordering
	Page    string
	Rows    string
	OrderBy string

	// Core identification
	ID      string
	UserID  string
	SKU     string
	Barcode string
	UPC     string
	Name    string

	// Categorization
	Category      string
	Subcategory   string
	Brand         string
	Manufacturer  string
	Status        string
	TaxCategory   string
	UnitOfMeasure string

	// Description fields
	Description      string
	ShortDescription string
	Notes            string

	// Pricing fields
	CostPrice         string
	WholesalePrice    string
	RetailPrice       string
	MinCostPrice      string
	MaxCostPrice      string
	MinRetailPrice    string
	MaxRetailPrice    string
	MinWholesalePrice string
	MaxWholesalePrice string

	// Inventory
	Quantity    string
	MinQuantity string
	MaxQuantity string

	// Physical attributes
	Weight    string
	MinWeight string
	MaxWeight string
	Length    string
	MinLength string
	MaxLength string
	Width     string
	MinWidth  string
	MaxWidth  string
	Height    string
	MinHeight string
	MaxHeight string

	// Boolean flags
	IsDigital       string
	IsWeighted      string
	IsTaxable       string
	HasSerialNumber string
	HasLotNumber    string
	HasImages       string
	HasVariants     string

	// Time-based filtering
	CreatedAfter  string
	CreatedBefore string
	UpdatedAfter  string
	UpdatedBefore string

	// Special search parameters
	ReturnPolicy string
	SearchTerm   string
	RelatedTo    string

	// Variant filtering
	HasVariantWithSKU         string
	HasVariantWithBarcode     string
	HasVariantWithMinPrice    string
	HasVariantWithMaxPrice    string
	HasVariantWithMinQuantity string
	HasVariantWithMaxQuantity string
}

func parseQueryParams(r *http.Request) queryParams {
	values := r.URL.Query()

	return queryParams{
		// Pagination and ordering
		Page:    values.Get("page"),
		Rows:    values.Get("rows"),
		OrderBy: values.Get("orderBy"),

		// Core identification
		ID:      values.Get("product_id"),
		UserID:  values.Get("user_id"),
		SKU:     values.Get("sku"),
		Barcode: values.Get("barcode"),
		UPC:     values.Get("upc"),
		Name:    values.Get("name"),

		// Categorization
		Category:      values.Get("category"),
		Subcategory:   values.Get("subcategory"),
		Brand:         values.Get("brand"),
		Manufacturer:  values.Get("manufacturer"),
		Status:        values.Get("status"),
		TaxCategory:   values.Get("tax_category"),
		UnitOfMeasure: values.Get("unit_of_measure"),

		// Description fields
		Description:      values.Get("description"),
		ShortDescription: values.Get("short_description"),
		Notes:            values.Get("notes"),

		// Pricing fields
		CostPrice:         values.Get("cost_price"),
		WholesalePrice:    values.Get("wholesale_price"),
		RetailPrice:       values.Get("retail_price"),
		MinCostPrice:      values.Get("min_cost_price"),
		MaxCostPrice:      values.Get("max_cost_price"),
		MinRetailPrice:    values.Get("min_retail_price"),
		MaxRetailPrice:    values.Get("max_retail_price"),
		MinWholesalePrice: values.Get("min_wholesale_price"),
		MaxWholesalePrice: values.Get("max_wholesale_price"),

		// Inventory
		Quantity:    values.Get("quantity"),
		MinQuantity: values.Get("min_quantity"),
		MaxQuantity: values.Get("max_quantity"),

		// Physical attributes
		Weight:    values.Get("weight"),
		MinWeight: values.Get("min_weight"),
		MaxWeight: values.Get("max_weight"),
		Length:    values.Get("length"),
		MinLength: values.Get("min_length"),
		MaxLength: values.Get("max_length"),
		Width:     values.Get("width"),
		MinWidth:  values.Get("min_width"),
		MaxWidth:  values.Get("max_width"),
		Height:    values.Get("height"),
		MinHeight: values.Get("min_height"),
		MaxHeight: values.Get("max_height"),

		// Boolean flags
		IsDigital:       values.Get("is_digital"),
		IsWeighted:      values.Get("is_weighted"),
		IsTaxable:       values.Get("is_taxable"),
		HasSerialNumber: values.Get("has_serial_number"),
		HasLotNumber:    values.Get("has_lot_number"),
		HasImages:       values.Get("has_images"),
		HasVariants:     values.Get("has_variants"),

		// Time-based filtering
		CreatedAfter:  values.Get("created_after"),
		CreatedBefore: values.Get("created_before"),
		UpdatedAfter:  values.Get("updated_after"),
		UpdatedBefore: values.Get("updated_before"),

		// Special search parameters
		ReturnPolicy: values.Get("return_policy"),
		SearchTerm:   values.Get("search"),
		RelatedTo:    values.Get("related_to"),

		// Variant filtering
		HasVariantWithSKU:         values.Get("variant_sku"),
		HasVariantWithBarcode:     values.Get("variant_barcode"),
		HasVariantWithMinPrice:    values.Get("variant_min_price"),
		HasVariantWithMaxPrice:    values.Get("variant_max_price"),
		HasVariantWithMinQuantity: values.Get("variant_min_quantity"),
		HasVariantWithMaxQuantity: values.Get("variant_max_quantity"),
	}
}

func parseFilter(qp queryParams) (productbus.QueryFilter, error) {
	var fieldErrors errs.FieldErrors
	var filter productbus.QueryFilter

	// Core identification fields
	if qp.ID != "" {
		id, err := uuid.Parse(qp.ID)
		switch err {
		case nil:
			filter.ID = &id
		default:
			fieldErrors.Add("product_id", err)
		}
	}

	if qp.UserID != "" {
		id, err := uuid.Parse(qp.UserID)
		switch err {
		case nil:
			filter.UserID = &id
		default:
			fieldErrors.Add("user_id", err)
		}
	}

	if qp.SKU != "" {
		filter.SKU = &qp.SKU
	}

	if qp.Barcode != "" {
		filter.Barcode = &qp.Barcode
	}

	if qp.UPC != "" {
		filter.UPC = &qp.UPC
	}

	if qp.Name != "" {
		name, err := name.Parse(qp.Name)
		switch err {
		case nil:
			filter.Name = &name
		default:
			fieldErrors.Add("name", err)
		}
	}

	// Categorization fields
	if qp.Category != "" {
		cat, err := category.Parse(qp.Category)
		switch err {
		case nil:
			filter.Category = &cat
		default:
			fieldErrors.Add("category", err)
		}
	}

	if qp.Subcategory != "" {
		subcat, err := subcategory.Parse(qp.Subcategory)
		switch err {
		case nil:
			filter.Subcategory = &subcat
		default:
			fieldErrors.Add("subcategory", err)
		}
	}

	if qp.Brand != "" {
		filter.Brand = &qp.Brand
	}

	if qp.Manufacturer != "" {
		filter.Manufacturer = &qp.Manufacturer
	}

	if qp.Status != "" {
		status, err := productstatus.Parse(qp.Status)
		switch err {
		case nil:
			filter.Status = &status
		default:
			fieldErrors.Add("status", err)
		}
	}

	if qp.TaxCategory != "" {
		taxcat, err := taxcategory.Parse(qp.TaxCategory)
		switch err {
		case nil:
			filter.TaxCategory = &taxcat
		default:
			fieldErrors.Add("tax_category", err)
		}
	}

	if qp.UnitOfMeasure != "" {
		unitOfMeasure, err := uom.Parse(qp.UnitOfMeasure)
		switch err {
		case nil:
			filter.UnitOfMeasure = &unitOfMeasure
		default:
			fieldErrors.Add("unit_of_measure", err)
		}
	}

	// Description fields
	if qp.Description != "" {
		filter.Description = &qp.Description
	}

	if qp.ShortDescription != "" {
		filter.ShortDescription = &qp.ShortDescription
	}

	if qp.Notes != "" {
		filter.Notes = &qp.Notes
	}

	// Pricing fields
	if qp.CostPrice != "" {
		cost, err := strconv.ParseFloat(qp.CostPrice, 64)
		switch err {
		case nil:
			filter.CostPrice = &cost
		default:
			fieldErrors.Add("cost_price", err)
		}
	}

	if qp.WholesalePrice != "" {
		wholesale, err := strconv.ParseFloat(qp.WholesalePrice, 64)
		switch err {
		case nil:
			filter.WholesalePrice = &wholesale
		default:
			fieldErrors.Add("wholesale_price", err)
		}
	}

	if qp.RetailPrice != "" {
		retail, err := strconv.ParseFloat(qp.RetailPrice, 64)
		switch err {
		case nil:
			filter.RetailPrice = &retail
		default:
			fieldErrors.Add("retail_price", err)
		}
	}

	if qp.MinCostPrice != "" {
		minCost, err := strconv.ParseFloat(qp.MinCostPrice, 64)
		switch err {
		case nil:
			filter.MinCostPrice = &minCost
		default:
			fieldErrors.Add("min_cost_price", err)
		}
	}

	if qp.MaxCostPrice != "" {
		maxCost, err := strconv.ParseFloat(qp.MaxCostPrice, 64)
		switch err {
		case nil:
			filter.MaxCostPrice = &maxCost
		default:
			fieldErrors.Add("max_cost_price", err)
		}
	}

	if qp.MinRetailPrice != "" {
		minRetail, err := strconv.ParseFloat(qp.MinRetailPrice, 64)
		switch err {
		case nil:
			filter.MinRetailPrice = &minRetail
		default:
			fieldErrors.Add("min_retail_price", err)
		}
	}

	if qp.MaxRetailPrice != "" {
		maxRetail, err := strconv.ParseFloat(qp.MaxRetailPrice, 64)
		switch err {
		case nil:
			filter.MaxRetailPrice = &maxRetail
		default:
			fieldErrors.Add("max_retail_price", err)
		}
	}

	if qp.MinWholesalePrice != "" {
		minWholesale, err := strconv.ParseFloat(qp.MinWholesalePrice, 64)
		switch err {
		case nil:
			filter.MinWholesalePrice = &minWholesale
		default:
			fieldErrors.Add("min_wholesale_price", err)
		}
	}

	if qp.MaxWholesalePrice != "" {
		maxWholesale, err := strconv.ParseFloat(qp.MaxWholesalePrice, 64)
		switch err {
		case nil:
			filter.MaxWholesalePrice = &maxWholesale
		default:
			fieldErrors.Add("max_wholesale_price", err)
		}
	}

	// Inventory
	if qp.Quantity != "" {
		qty, err := strconv.ParseInt(qp.Quantity, 10, 64)
		switch err {
		case nil:
			q := int(qty)
			filter.Quantity = &q
		default:
			fieldErrors.Add("quantity", err)
		}
	}

	if qp.MinQuantity != "" {
		minQty, err := strconv.ParseInt(qp.MinQuantity, 10, 64)
		switch err {
		case nil:
			q := int(minQty)
			filter.MinQuantity = &q
		default:
			fieldErrors.Add("min_quantity", err)
		}
	}

	if qp.MaxQuantity != "" {
		maxQty, err := strconv.ParseInt(qp.MaxQuantity, 10, 64)
		switch err {
		case nil:
			q := int(maxQty)
			filter.MaxQuantity = &q
		default:
			fieldErrors.Add("max_quantity", err)
		}
	}

	// Physical attributes
	if qp.Weight != "" {
		weight, err := strconv.ParseFloat(qp.Weight, 64)
		switch err {
		case nil:
			filter.Weight = &weight
		default:
			fieldErrors.Add("weight", err)
		}
	}

	if qp.MinWeight != "" {
		minWeight, err := strconv.ParseFloat(qp.MinWeight, 64)
		switch err {
		case nil:
			filter.MinWeight = &minWeight
		default:
			fieldErrors.Add("min_weight", err)
		}
	}

	if qp.MaxWeight != "" {
		maxWeight, err := strconv.ParseFloat(qp.MaxWeight, 64)
		switch err {
		case nil:
			filter.MaxWeight = &maxWeight
		default:
			fieldErrors.Add("max_weight", err)
		}
	}

	if qp.Length != "" {
		length, err := strconv.ParseFloat(qp.Length, 64)
		switch err {
		case nil:
			filter.Length = &length
		default:
			fieldErrors.Add("length", err)
		}
	}

	if qp.MinLength != "" {
		minLength, err := strconv.ParseFloat(qp.MinLength, 64)
		switch err {
		case nil:
			filter.MinLength = &minLength
		default:
			fieldErrors.Add("min_length", err)
		}
	}

	if qp.MaxLength != "" {
		maxLength, err := strconv.ParseFloat(qp.MaxLength, 64)
		switch err {
		case nil:
			filter.MaxLength = &maxLength
		default:
			fieldErrors.Add("max_length", err)
		}
	}

	if qp.Width != "" {
		width, err := strconv.ParseFloat(qp.Width, 64)
		switch err {
		case nil:
			filter.Width = &width
		default:
			fieldErrors.Add("width", err)
		}
	}

	if qp.MinWidth != "" {
		minWidth, err := strconv.ParseFloat(qp.MinWidth, 64)
		switch err {
		case nil:
			filter.MinWidth = &minWidth
		default:
			fieldErrors.Add("min_width", err)
		}
	}

	if qp.MaxWidth != "" {
		maxWidth, err := strconv.ParseFloat(qp.MaxWidth, 64)
		switch err {
		case nil:
			filter.MaxWidth = &maxWidth
		default:
			fieldErrors.Add("max_width", err)
		}
	}

	if qp.Height != "" {
		height, err := strconv.ParseFloat(qp.Height, 64)
		switch err {
		case nil:
			filter.Height = &height
		default:
			fieldErrors.Add("height", err)
		}
	}

	if qp.MinHeight != "" {
		minHeight, err := strconv.ParseFloat(qp.MinHeight, 64)
		switch err {
		case nil:
			filter.MinHeight = &minHeight
		default:
			fieldErrors.Add("min_height", err)
		}
	}

	if qp.MaxHeight != "" {
		maxHeight, err := strconv.ParseFloat(qp.MaxHeight, 64)
		switch err {
		case nil:
			filter.MaxHeight = &maxHeight
		default:
			fieldErrors.Add("max_height", err)
		}
	}

	// Boolean flags
	if qp.IsDigital != "" {
		isDigital, err := strconv.ParseBool(qp.IsDigital)
		switch err {
		case nil:
			filter.IsDigital = &isDigital
		default:
			fieldErrors.Add("is_digital", err)
		}
	}

	if qp.IsWeighted != "" {
		isWeighted, err := strconv.ParseBool(qp.IsWeighted)
		switch err {
		case nil:
			filter.IsWeighted = &isWeighted
		default:
			fieldErrors.Add("is_weighted", err)
		}
	}

	if qp.IsTaxable != "" {
		isTaxable, err := strconv.ParseBool(qp.IsTaxable)
		switch err {
		case nil:
			filter.IsTaxable = &isTaxable
		default:
			fieldErrors.Add("is_taxable", err)
		}
	}

	if qp.HasSerialNumber != "" {
		hasSerialNumber, err := strconv.ParseBool(qp.HasSerialNumber)
		switch err {
		case nil:
			filter.HasSerialNumber = &hasSerialNumber
		default:
			fieldErrors.Add("has_serial_number", err)
		}
	}

	if qp.HasLotNumber != "" {
		hasLotNumber, err := strconv.ParseBool(qp.HasLotNumber)
		switch err {
		case nil:
			filter.HasLotNumber = &hasLotNumber
		default:
			fieldErrors.Add("has_lot_number", err)
		}
	}

	if qp.HasImages != "" {
		hasImages, err := strconv.ParseBool(qp.HasImages)
		switch err {
		case nil:
			filter.HasImages = &hasImages
		default:
			fieldErrors.Add("has_images", err)
		}
	}

	if qp.HasVariants != "" {
		hasVariants, err := strconv.ParseBool(qp.HasVariants)
		switch err {
		case nil:
			filter.HasVariants = &hasVariants
		default:
			fieldErrors.Add("has_variants", err)
		}
	}

	// Time-based filtering
	if qp.CreatedAfter != "" {
		createdAfter, err := time.Parse(time.RFC3339, qp.CreatedAfter)
		switch err {
		case nil:
			filter.CreatedAfter = &createdAfter
		default:
			fieldErrors.Add("created_after", err)
		}
	}

	if qp.CreatedBefore != "" {
		createdBefore, err := time.Parse(time.RFC3339, qp.CreatedBefore)
		switch err {
		case nil:
			filter.CreatedBefore = &createdBefore
		default:
			fieldErrors.Add("created_before", err)
		}
	}

	if qp.UpdatedAfter != "" {
		updatedAfter, err := time.Parse(time.RFC3339, qp.UpdatedAfter)
		switch err {
		case nil:
			filter.UpdatedAfter = &updatedAfter
		default:
			fieldErrors.Add("updated_after", err)
		}
	}

	if qp.UpdatedBefore != "" {
		updatedBefore, err := time.Parse(time.RFC3339, qp.UpdatedBefore)
		switch err {
		case nil:
			filter.UpdatedBefore = &updatedBefore
		default:
			fieldErrors.Add("updated_before", err)
		}
	}

	// Special search parameters
	if qp.ReturnPolicy != "" {
		filter.ReturnPolicy = &qp.ReturnPolicy
	}

	if qp.SearchTerm != "" {
		filter.SearchTerm = &qp.SearchTerm
	}

	if qp.RelatedTo != "" {
		relatedTo, err := uuid.Parse(qp.RelatedTo)
		switch err {
		case nil:
			filter.RelatedTo = &relatedTo
		default:
			fieldErrors.Add("related_to", err)
		}
	}

	// Variant filtering
	if qp.HasVariantWithSKU != "" {
		filter.HasVariantWithSKU = &qp.HasVariantWithSKU
	}

	if qp.HasVariantWithBarcode != "" {
		filter.HasVariantWithBarcode = &qp.HasVariantWithBarcode
	}

	if qp.HasVariantWithMinPrice != "" {
		minPrice, err := strconv.ParseFloat(qp.HasVariantWithMinPrice, 64)
		switch err {
		case nil:
			filter.HasVariantWithMinPrice = &minPrice
		default:
			fieldErrors.Add("variant_min_price", err)
		}
	}

	if qp.HasVariantWithMaxPrice != "" {
		maxPrice, err := strconv.ParseFloat(qp.HasVariantWithMaxPrice, 64)
		switch err {
		case nil:
			filter.HasVariantWithMaxPrice = &maxPrice
		default:
			fieldErrors.Add("variant_max_price", err)
		}
	}

	if qp.HasVariantWithMinQuantity != "" {
		minQty, err := strconv.ParseInt(qp.HasVariantWithMinQuantity, 10, 64)
		switch err {
		case nil:
			q := int(minQty)
			filter.HasVariantWithMinQuantity = &q
		default:
			fieldErrors.Add("variant_min_quantity", err)
		}
	}

	if qp.HasVariantWithMaxQuantity != "" {
		maxQty, err := strconv.ParseInt(qp.HasVariantWithMaxQuantity, 10, 64)
		switch err {
		case nil:
			q := int(maxQty)
			filter.HasVariantWithMaxQuantity = &q
		default:
			fieldErrors.Add("variant_max_quantity", err)
		}
	}

	if fieldErrors != nil {
		return productbus.QueryFilter{}, fieldErrors.ToError()
	}

	return filter, nil
}

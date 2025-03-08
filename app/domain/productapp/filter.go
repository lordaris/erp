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
	Page            string
	Rows            string
	OrderBy         string
	ID              string
	UserID          string
	SKU             string
	Name            string
	Category        string
	Subcategory     string
	Brand           string
	Manufacturer    string
	Status          string
	TaxCategory     string
	UnitOfMeasure   string
	Cost            string
	MinimumPrice    string
	MSRP            string
	Quantity        string
	IsDigital       string
	HasSerialNumber string
	HasLotNumber    string
	MinWeight       string
	MaxWeight       string
	MinPrice        string
	MaxPrice        string
	MinMSRP         string
	MaxMSRP         string
	MinQuantity     string
	MaxQuantity     string
	HasImages       string
	CreatedAfter    string
	CreatedBefore   string
	UpdatedAfter    string
	UpdatedBefore   string
	SearchTerm      string
}

func parseQueryParams(r *http.Request) queryParams {
	values := r.URL.Query()

	filter := queryParams{
		Page:            values.Get("page"),
		Rows:            values.Get("rows"),
		OrderBy:         values.Get("orderBy"),
		ID:              values.Get("product_id"),
		UserID:          values.Get("user_id"),
		SKU:             values.Get("sku"),
		Name:            values.Get("name"),
		Category:        values.Get("category"),
		Subcategory:     values.Get("subcategory"),
		Brand:           values.Get("brand"),
		Manufacturer:    values.Get("manufacturer"),
		Status:          values.Get("status"),
		TaxCategory:     values.Get("tax_category"),
		UnitOfMeasure:   values.Get("unit_of_measure"),
		Cost:            values.Get("cost"),
		MinimumPrice:    values.Get("minimum_price"),
		MSRP:            values.Get("msrp"),
		Quantity:        values.Get("quantity"),
		IsDigital:       values.Get("is_digital"),
		HasSerialNumber: values.Get("has_serial_number"),
		HasLotNumber:    values.Get("has_lot_number"),
		MinWeight:       values.Get("min_weight"),
		MaxWeight:       values.Get("max_weight"),
		MinPrice:        values.Get("min_price"),
		MaxPrice:        values.Get("max_price"),
		MinMSRP:         values.Get("min_msrp"),
		MaxMSRP:         values.Get("max_msrp"),
		MinQuantity:     values.Get("min_quantity"),
		MaxQuantity:     values.Get("max_quantity"),
		HasImages:       values.Get("has_images"),
		CreatedAfter:    values.Get("created_after"),
		CreatedBefore:   values.Get("created_before"),
		UpdatedAfter:    values.Get("updated_after"),
		UpdatedBefore:   values.Get("updated_before"),
		SearchTerm:      values.Get("search"),
	}

	return filter
}

func parseFilter(qp queryParams) (productbus.QueryFilter, error) {
	var fieldErrors errs.FieldErrors
	var filter productbus.QueryFilter

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

	if qp.Name != "" {
		name, err := name.Parse(qp.Name)
		switch err {
		case nil:
			filter.Name = &name
		default:
			fieldErrors.Add("name", err)
		}
	}

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

	if qp.Cost != "" {
		cost, err := strconv.ParseFloat(qp.Cost, 64)
		switch err {
		case nil:
			filter.Cost = &cost
		default:
			fieldErrors.Add("cost", err)
		}
	}

	if qp.MinimumPrice != "" {
		minPrice, err := strconv.ParseFloat(qp.MinimumPrice, 64)
		switch err {
		case nil:
			filter.MinimumPrice = &minPrice
		default:
			fieldErrors.Add("minimum_price", err)
		}
	}

	if qp.MSRP != "" {
		msrp, err := strconv.ParseFloat(qp.MSRP, 64)
		switch err {
		case nil:
			filter.MSRP = &msrp
		default:
			fieldErrors.Add("msrp", err)
		}
	}

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

	if qp.IsDigital != "" {
		isDigital, err := strconv.ParseBool(qp.IsDigital)
		switch err {
		case nil:
			filter.IsDigital = &isDigital
		default:
			fieldErrors.Add("is_digital", err)
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

	if qp.MinPrice != "" {
		minPrice, err := strconv.ParseFloat(qp.MinPrice, 64)
		switch err {
		case nil:
			filter.MinPrice = &minPrice
		default:
			fieldErrors.Add("min_price", err)
		}
	}

	if qp.MaxPrice != "" {
		maxPrice, err := strconv.ParseFloat(qp.MaxPrice, 64)
		switch err {
		case nil:
			filter.MaxPrice = &maxPrice
		default:
			fieldErrors.Add("max_price", err)
		}
	}

	if qp.MinMSRP != "" {
		minMSRP, err := strconv.ParseFloat(qp.MinMSRP, 64)
		switch err {
		case nil:
			filter.MinMSRP = &minMSRP
		default:
			fieldErrors.Add("min_msrp", err)
		}
	}

	if qp.MaxMSRP != "" {
		maxMSRP, err := strconv.ParseFloat(qp.MaxMSRP, 64)
		switch err {
		case nil:
			filter.MaxMSRP = &maxMSRP
		default:
			fieldErrors.Add("max_msrp", err)
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

	// Handle image boolean
	if qp.HasImages != "" {
		hasImages, err := strconv.ParseBool(qp.HasImages)
		switch err {
		case nil:
			filter.HasImages = &hasImages
		default:
			fieldErrors.Add("has_images", err)
		}
	}

	// Handle date ranges
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

	if qp.SearchTerm != "" {
		filter.SearchTerm = &qp.SearchTerm
	}

	if fieldErrors != nil {
		return productbus.QueryFilter{}, fieldErrors.ToError()
	}

	return filter, nil
}

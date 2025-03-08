package inventoryapp

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
)

type queryParams struct {
	Page      string
	Rows      string
	OrderBy   string
	ID        string
	ProductID string
	Location  string
	Name      string
	Quantity  string
}

func parseQueryParams(r *http.Request) queryParams {
	values := r.URL.Query()

	filter := queryParams{
		Page:      values.Get("page"),
		Rows:      values.Get("rows"),
		OrderBy:   values.Get("orderBy"),
		ID:        values.Get("inventory_id"),
		ProductID: values.Get("product_id"),
		Location:  values.Get("location"),
		Name:      values.Get("name"),
		Quantity:  values.Get("quantity"),
	}

	return filter
}

func parseFilter(qp queryParams) (inventorybus.QueryFilter, error) {
	var fieldErrors errs.FieldErrors
	var filter inventorybus.QueryFilter

	if qp.ID != "" {
		id, err := uuid.Parse(qp.ID)
		switch err {
		case nil:
			filter.ID = &id
		default:
			fieldErrors.Add("inventory_id", err)
		}
	}

	if qp.ProductID != "" {
		id, err := uuid.Parse(qp.ProductID)
		switch err {
		case nil:
			filter.ProductID = &id
		default:
			fieldErrors.Add("product_id", err)
		}
	}

	if qp.Name != "" {
		n, err := name.Parse(qp.Name)
		switch err {
		case nil:
			filter.Name = &n
		default:
			fieldErrors.Add("name", err)
		}
	}

	if qp.Location != "" {
		loc, err := location.Parse(qp.Location)
		switch err {
		case nil:
			filter.Location = &loc
		default:
			fieldErrors.Add("location", err)
		}
	}

	if qp.Quantity != "" {
		var q int
		_, err := fmt.Sscanf(qp.Quantity, "%d", &q)
		switch err {
		case nil:
			filter.Quantity = &q
		default:
			fieldErrors.Add("quantity", err)
		}
	}

	if fieldErrors != nil {
		return inventorybus.QueryFilter{}, fieldErrors.ToError()
	}

	return filter, nil
}

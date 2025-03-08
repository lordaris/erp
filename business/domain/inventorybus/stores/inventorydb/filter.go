package inventorydb

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/lordaris/erp/business/domain/inventorybus"
)

func (s *Store) applyFilter(filter inventorybus.QueryFilter, data map[string]any, buf *bytes.Buffer) {
	var wc []string

	if filter.ID != nil {
		data["inventory_id"] = *filter.ID
		wc = append(wc, "inventory_id = :inventory_id")
	}

	if filter.ProductID != nil {
		data["product_id"] = *filter.ProductID
		wc = append(wc, "product_id = :product_id")
	}

	if filter.Name != nil {
		data["name"] = fmt.Sprintf("%%%s%%", *filter.Name)
		wc = append(wc, "name LIKE :name")
	}

	if filter.Location != nil {
		data["location"] = (*filter.Location).String()
		wc = append(wc, "location = :location")
	}

	if filter.Quantity != nil {
		data["quantity"] = *filter.Quantity
		wc = append(wc, "quantity = :quantity")
	}

	if len(wc) > 0 {
		buf.WriteString(" WHERE ")
		buf.WriteString(strings.Join(wc, " AND "))
	}
}

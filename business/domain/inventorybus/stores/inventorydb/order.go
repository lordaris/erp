package inventorydb

import (
	"fmt"

	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/sdk/order"
)

var orderByFields = map[string]string{
	inventorybus.OrderByID:        "inventory_id",
	inventorybus.OrderByProductID: "product_id",
	inventorybus.OrderByLocation:  "location",
	inventorybus.OrderByName:      "name",
	inventorybus.OrderByQuantity:  "quantity",
}

func orderByClause(orderBy order.By) (string, error) {
	by, exists := orderByFields[orderBy.Field]
	if !exists {
		return "", fmt.Errorf("field %q does not exist", orderBy.Field)
	}

	return " ORDER BY " + by + " " + orderBy.Direction, nil
}

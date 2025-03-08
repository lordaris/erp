package inventorybus

import "github.com/lordaris/erp/business/sdk/order"

// DefaultOrderBy represents the default way we sort.
var DefaultOrderBy = order.NewBy(OrderByID, order.ASC)

// Set of fields that the results can be ordered by.
const (
	OrderByID        = "inventory_id"
	OrderByProductID = "product_id"
	OrderByLocation  = "location"
	OrderByName      = "name"
	OrderByQuantity  = "quantity"
)

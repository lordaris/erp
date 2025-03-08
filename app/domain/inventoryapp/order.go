package inventoryapp

import "github.com/lordaris/erp/business/domain/inventorybus"

var orderByFields = map[string]string{
	"inventory_id": inventorybus.OrderByID,
	"product_id":   inventorybus.OrderByProductID,
	"location":     inventorybus.OrderByLocation,
	"name":         inventorybus.OrderByName,
	"quantity":     inventorybus.OrderByQuantity,
}

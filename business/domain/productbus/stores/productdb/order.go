package productdb

import (
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/order"
)

var orderByFields = map[string]string{
	productbus.OrderByProductID:       "product_id",
	productbus.OrderByUserID:          "user_id",
	productbus.OrderBySKU:             "sku",
	productbus.OrderByName:            "name",
	productbus.OrderByCategory:        "category",
	productbus.OrderBySubcategory:     "subcategory",
	productbus.OrderByBrand:           "brand",
	productbus.OrderByManufacturer:    "manufacturer",
	productbus.OrderByStatus:          "status",
	productbus.OrderByTaxCategory:     "tax_category",
	productbus.OrderByUOM:             "unit_of_measure",
	productbus.OrderByCost:            "cost",
	productbus.OrderByMSRP:            "msrp",
	productbus.OrderByMinimumPrice:    "minimum_price",
	productbus.OrderByQuantity:        "quantity",
	productbus.OrderByWeight:          "weight",
	productbus.OrderByHeight:          "height",
	productbus.OrderByWidth:           "width",
	productbus.OrderByLength:          "length",
	productbus.OrderByIsDigital:       "is_digital",
	productbus.OrderByHasSerialNumber: "has_serial_number",
	productbus.OrderByHasLotNumber:    "has_lot_number",
	productbus.OrderByDateCreated:     "date_created",
	productbus.OrderByDateUpdated:     "date_updated",
	productbus.OrderByVariantCount:    "(SELECT COUNT(*) FROM product_variants WHERE product_variants.product_id = products.product_id)",
	productbus.OrderByTotalInventory:  "(products.quantity + COALESCE((SELECT SUM(quantity) FROM product_variants WHERE product_variants.product_id = products.product_id), 0))",
}

func orderByClause(orderBy order.By) (string, error) {
	by, exists := orderByFields[orderBy.Field]
	if !exists {
		// Return default ordering if the field doesn't exist
		defaultField := orderByFields[productbus.OrderByProductID]
		return " ORDER BY " + defaultField + " " + order.ASC, nil
	}

	return " ORDER BY " + by + " " + orderBy.Direction, nil
}

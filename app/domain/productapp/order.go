package productapp

import (
	"github.com/lordaris/erp/business/domain/productbus"
)

var orderByFields = map[string]string{
	"product_id":      productbus.OrderByProductID,
	"user_id":         productbus.OrderByUserID,
	"sku":             productbus.OrderBySKU,
	"name":            productbus.OrderByName,
	"category":        productbus.OrderByCategory,
	"subcategory":     productbus.OrderBySubcategory,
	"brand":           productbus.OrderByBrand,
	"manufacturer":    productbus.OrderByManufacturer,
	"status":          productbus.OrderByStatus,
	"tax_category":    productbus.OrderByTaxCategory,
	"unit_of_measure": productbus.OrderByUOM,
	"cost":            productbus.OrderByCost,
	"msrp":            productbus.OrderByMSRP,
	"minimum_price":   productbus.OrderByMinimumPrice,
	"quantity":        productbus.OrderByQuantity,
	"weight":          productbus.OrderByWeight,
	"height":          productbus.OrderByHeight,
	"width":           productbus.OrderByWidth,
	"length":          productbus.OrderByLength,
}

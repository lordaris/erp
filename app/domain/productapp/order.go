package productapp

import (
	"github.com/lordaris/erp/business/domain/productbus"
)

var orderByFields = map[string]string{
	// Core identification fields
	"product_id": productbus.OrderByProductID,
	"user_id":    productbus.OrderByUserID,
	"sku":        productbus.OrderBySKU,
	"barcode":    productbus.OrderByBarcode,
	"name":       productbus.OrderByName,

	// Categorization fields
	"category":        productbus.OrderByCategory,
	"subcategory":     productbus.OrderBySubcategory,
	"brand":           productbus.OrderByBrand,
	"manufacturer":    productbus.OrderByManufacturer,
	"status":          productbus.OrderByStatus,
	"tax_category":    productbus.OrderByTaxCategory,
	"unit_of_measure": productbus.OrderByUOM,

	// Description fields
	"description":       productbus.OrderByDescription,
	"short_description": productbus.OrderByShortDescription,
	"return_policy":     productbus.OrderByReturnPolicy,
	"notes":             productbus.OrderByNotes,

	// Pricing fields
	"cost_price":      productbus.OrderByCostPrice,
	"wholesale_price": productbus.OrderByWholesalePrice,
	"retail_price":    productbus.OrderByRetailPrice,

	// Physical attributes
	"weight": productbus.OrderByWeight,
	"height": productbus.OrderByHeight,
	"width":  productbus.OrderByWidth,
	"length": productbus.OrderByLength,

	// Boolean flags
	"is_digital":        productbus.OrderByIsDigital,
	"is_weighted":       productbus.OrderByIsWeighted,
	"is_taxable":        productbus.OrderByIsTaxable,
	"has_serial_number": productbus.OrderByHasSerialNumber,
	"has_lot_number":    productbus.OrderByHasLotNumber,

	// Time fields
	"created_at": productbus.OrderByCreatedAt,
	"updated_at": productbus.OrderByUpdatedAt,

	// Calculated fields
	"variant_count":   productbus.OrderByVariantCount,
	"total_inventory": productbus.OrderByTotalInventory,
	"image_count":     productbus.OrderByImageCount,
	"attribute_count": productbus.OrderByAttributeCount,
}

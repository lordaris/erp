package productdb

import (
	"fmt"

	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/order"
)

var orderByFields = map[string]string{
	// Core identification fields
	productbus.OrderByProductID: "product_id",
	productbus.OrderByUserID:    "user_id",
	productbus.OrderBySKU:       "sku",
	productbus.OrderByBarcode:   "barcode",
	productbus.OrderByName:      "name",

	// Categorization fields
	productbus.OrderByCategory:     "category",
	productbus.OrderBySubcategory:  "subcategory",
	productbus.OrderByBrand:        "brand",
	productbus.OrderByManufacturer: "manufacturer",
	productbus.OrderByStatus:       "status",
	productbus.OrderByTaxCategory:  "tax_category",
	productbus.OrderByUOM:          "unit_of_measure",

	// Description fields
	productbus.OrderByDescription:      "description",
	productbus.OrderByShortDescription: "short_description",
	productbus.OrderByReturnPolicy:     "return_policy",
	productbus.OrderByNotes:            "notes",

	// Pricing fields
	productbus.OrderByCostPrice:      "cost_price",
	productbus.OrderByWholesalePrice: "wholesale_price",
	productbus.OrderByRetailPrice:    "retail_price",

	// Physical attributes
	productbus.OrderByWeight: "weight",
	productbus.OrderByHeight: "height",
	productbus.OrderByWidth:  "width",
	productbus.OrderByLength: "length",

	// Boolean flags
	productbus.OrderByIsDigital:       "is_digital",
	productbus.OrderByIsWeighted:      "is_weighted",
	productbus.OrderByIsTaxable:       "is_taxable",
	productbus.OrderByHasSerialNumber: "has_serial_number",
	productbus.OrderByHasLotNumber:    "has_lot_number",

	// Time fields
	productbus.OrderByCreatedAt: "created_at",
	productbus.OrderByUpdatedAt: "updated_at",

	// Calculated/Aggregated fields
	productbus.OrderByVariantCount:   "(SELECT COUNT(*) FROM product_variants WHERE product_variants.product_id = products.product_id)",
	productbus.OrderByTotalInventory: "(products.quantity + COALESCE((SELECT SUM(quantity) FROM product_variants WHERE product_variants.product_id = products.product_id), 0))",
	productbus.OrderByImageCount:     "jsonb_array_length(image_urls)",
	productbus.OrderByAttributeCount: "jsonb_object_keys(attributes)",
}

func orderByClause(orderBy order.By) (string, error) {
	by, exists := orderByFields[orderBy.Field]
	if !exists {
		return "", fmt.Errorf("field %q does not exist", orderBy.Field)
	}

	return " ORDER BY " + by + " " + orderBy.Direction, nil
}

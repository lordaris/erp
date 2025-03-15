package productbus

import "github.com/lordaris/erp/business/sdk/order"

// DefaultOrderBy represents the default way we sort.
var DefaultOrderBy = order.NewBy(OrderByProductID, order.ASC)

// Set of fields that the results can be ordered by.
const (
	// Core identification fields
	OrderByProductID = "product_id"
	OrderByUserID    = "user_id"
	OrderBySKU       = "sku"
	OrderByBarcode   = "barcode"
	OrderByName      = "name"

	// Categorization fields
	OrderByCategory     = "category"
	OrderBySubcategory  = "subcategory"
	OrderByBrand        = "brand"
	OrderByManufacturer = "manufacturer"
	OrderByStatus       = "status"
	OrderByTaxCategory  = "tax_category"
	OrderByUOM          = "unit_of_measure"

	// Description fields
	OrderByDescription      = "description"
	OrderByShortDescription = "short_description"
	OrderByReturnPolicy     = "return_policy"
	OrderByNotes            = "notes"

	// Pricing fields
	OrderByCostPrice      = "cost_price"
	OrderByWholesalePrice = "wholesale_price"
	OrderByRetailPrice    = "retail_price"

	// Physical attributes
	OrderByWeight = "weight"
	OrderByHeight = "height"
	OrderByWidth  = "width"
	OrderByLength = "length"

	// Boolean flags
	OrderByIsDigital       = "is_digital"
	OrderByIsWeighted      = "is_weighted"
	OrderByIsTaxable       = "is_taxable"
	OrderByHasSerialNumber = "has_serial_number"
	OrderByHasLotNumber    = "has_lot_number"

	// Time fields
	OrderByCreatedAt = "created_at"
	OrderByUpdatedAt = "updated_at"

	// Calculated/Aggregated fields
	OrderByVariantCount   = "(SELECT COUNT(*) FROM product_variants WHERE product_variants.product_id = products.product_id)"
	OrderByTotalInventory = "(products.quantity + COALESCE((SELECT SUM(quantity) FROM product_variants WHERE product_variants.product_id = products.product_id), 0))"
	OrderByImageCount     = "jsonb_array_length(image_urls)"
	OrderByAttributeCount = "jsonb_object_keys(attributes)"
)

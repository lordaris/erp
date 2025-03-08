package productbus

import "github.com/lordaris/erp/business/sdk/order"

// DefaultOrderBy represents the default way we sort.
var DefaultOrderBy = order.NewBy(OrderByProductID, order.ASC)

// Set of fields that the results can be ordered by.
const (
	OrderByProductID       = "product_id"
	OrderByUserID          = "user_id"
	OrderBySKU             = "sku"
	OrderByName            = "name"
	OrderByCategory        = "category"
	OrderBySubcategory     = "subcategory"
	OrderByBrand           = "brand"
	OrderByManufacturer    = "manufacturer"
	OrderByStatus          = "status"
	OrderByTaxCategory     = "tax_category"
	OrderByUOM             = "unit_of_measure"
	OrderByCost            = "cost"
	OrderByMSRP            = "msrp"
	OrderByMinimumPrice    = "minimum_price"
	OrderByQuantity        = "quantity"
	OrderByWeight          = "weight"
	OrderByHeight          = "height"
	OrderByWidth           = "width"
	OrderByLength          = "length"
	OrderByIsDigital       = "is_digital"
	OrderByHasSerialNumber = "has_serial_number"
	OrderByHasLotNumber    = "has_lot_number"
	OrderByDateCreated     = "date_created"
	OrderByDateUpdated     = "date_updated"
	OrderByVariantCount    = "variant_count"
	OrderByTotalInventory  = "total_inventory"
)

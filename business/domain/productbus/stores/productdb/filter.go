package productdb

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/lordaris/erp/business/domain/productbus"
)

func (s *Store) applyFilter(filter productbus.QueryFilter, data map[string]any, buf *bytes.Buffer) {
	var wc []string

	// Core identification fields
	if filter.ID != nil {
		data["product_id"] = *filter.ID
		wc = append(wc, "product_id = :product_id")
	}

	if filter.UserID != nil {
		data["user_id"] = *filter.UserID
		wc = append(wc, "user_id = :user_id")
	}

	if filter.SKU != nil {
		data["sku"] = *filter.SKU
		wc = append(wc, "sku = :sku")
	}

	if filter.Barcode != nil {
		data["barcode"] = *filter.Barcode
		wc = append(wc, "barcode = :barcode")
	}

	if filter.UPC != nil {
		data["upc"] = *filter.UPC
		wc = append(wc, "upc = :upc")
	}

	if filter.Name != nil {
		data["name"] = fmt.Sprintf("%%%s%%", *filter.Name)
		wc = append(wc, "name LIKE :name")
	}

	// Categorization fields
	if filter.Category != nil {
		data["category"] = (*filter.Category).String()
		wc = append(wc, "category = :category")
	}

	if filter.Subcategory != nil {
		data["subcategory"] = (*filter.Subcategory).String()
		wc = append(wc, "subcategory = :subcategory")
	}

	if filter.Brand != nil {
		data["brand"] = fmt.Sprintf("%%%s%%", *filter.Brand)
		wc = append(wc, "brand LIKE :brand")
	}

	if filter.Manufacturer != nil {
		data["manufacturer"] = fmt.Sprintf("%%%s%%", *filter.Manufacturer)
		wc = append(wc, "manufacturer LIKE :manufacturer")
	}

	if filter.Status != nil {
		data["status"] = (*filter.Status).String()
		wc = append(wc, "status = :status")
	}

	if filter.TaxCategory != nil {
		data["tax_category"] = (*filter.TaxCategory).String()
		wc = append(wc, "tax_category = :tax_category")
	}

	if filter.UnitOfMeasure != nil {
		data["unit_of_measure"] = (*filter.UnitOfMeasure).String()
		wc = append(wc, "unit_of_measure = :unit_of_measure")
	}

	// Description fields
	if filter.Description != nil {
		data["description"] = fmt.Sprintf("%%%s%%", *filter.Description)
		wc = append(wc, "description LIKE :description")
	}

	if filter.ShortDescription != nil {
		data["short_description"] = fmt.Sprintf("%%%s%%", *filter.ShortDescription)
		wc = append(wc, "short_description LIKE :short_description")
	}

	if filter.Notes != nil {
		data["notes"] = fmt.Sprintf("%%%s%%", *filter.Notes)
		wc = append(wc, "notes LIKE :notes")
	}

	// Pricing fields
	if filter.CostPrice != nil {
		data["cost_price"] = *filter.CostPrice
		wc = append(wc, "cost_price = :cost_price")
	}

	if filter.WholesalePrice != nil {
		data["wholesale_price"] = *filter.WholesalePrice
		wc = append(wc, "wholesale_price = :wholesale_price")
	}

	if filter.RetailPrice != nil {
		data["retail_price"] = *filter.RetailPrice
		wc = append(wc, "retail_price = :retail_price")
	}

	if filter.MinCostPrice != nil {
		data["min_cost_price"] = *filter.MinCostPrice
		wc = append(wc, "cost_price >= :min_cost_price")
	}

	if filter.MaxCostPrice != nil {
		data["max_cost_price"] = *filter.MaxCostPrice
		wc = append(wc, "cost_price <= :max_cost_price")
	}

	if filter.MinRetailPrice != nil {
		data["min_retail_price"] = *filter.MinRetailPrice
		wc = append(wc, "retail_price >= :min_retail_price")
	}

	if filter.MaxRetailPrice != nil {
		data["max_retail_price"] = *filter.MaxRetailPrice
		wc = append(wc, "retail_price <= :max_retail_price")
	}

	if filter.MinWholesalePrice != nil {
		data["min_wholesale_price"] = *filter.MinWholesalePrice
		wc = append(wc, "wholesale_price >= :min_wholesale_price")
	}

	if filter.MaxWholesalePrice != nil {
		data["max_wholesale_price"] = *filter.MaxWholesalePrice
		wc = append(wc, "wholesale_price <= :max_wholesale_price")
	}

	// Inventory
	if filter.Quantity != nil {
		data["quantity"] = *filter.Quantity
		wc = append(wc, "quantity = :quantity")
	}

	if filter.MinQuantity != nil {
		data["min_quantity"] = *filter.MinQuantity
		wc = append(wc, "quantity >= :min_quantity")
	}

	if filter.MaxQuantity != nil {
		data["max_quantity"] = *filter.MaxQuantity
		wc = append(wc, "quantity <= :max_quantity")
	}

	// Physical attributes
	if filter.Weight != nil {
		data["weight"] = *filter.Weight
		wc = append(wc, "weight = :weight")
	}

	if filter.MinWeight != nil {
		data["min_weight"] = *filter.MinWeight
		wc = append(wc, "weight >= :min_weight")
	}

	if filter.MaxWeight != nil {
		data["max_weight"] = *filter.MaxWeight
		wc = append(wc, "weight <= :max_weight")
	}

	if filter.Length != nil {
		data["length"] = *filter.Length
		wc = append(wc, "length = :length")
	}

	if filter.MinLength != nil {
		data["min_length"] = *filter.MinLength
		wc = append(wc, "length >= :min_length")
	}

	if filter.MaxLength != nil {
		data["max_length"] = *filter.MaxLength
		wc = append(wc, "length <= :max_length")
	}

	if filter.Width != nil {
		data["width"] = *filter.Width
		wc = append(wc, "width = :width")
	}

	if filter.MinWidth != nil {
		data["min_width"] = *filter.MinWidth
		wc = append(wc, "width >= :min_width")
	}

	if filter.MaxWidth != nil {
		data["max_width"] = *filter.MaxWidth
		wc = append(wc, "width <= :max_width")
	}

	if filter.Height != nil {
		data["height"] = *filter.Height
		wc = append(wc, "height = :height")
	}

	if filter.MinHeight != nil {
		data["min_height"] = *filter.MinHeight
		wc = append(wc, "height >= :min_height")
	}

	if filter.MaxHeight != nil {
		data["max_height"] = *filter.MaxHeight
		wc = append(wc, "height <= :max_height")
	}

	// Boolean flags
	if filter.IsDigital != nil {
		data["is_digital"] = *filter.IsDigital
		wc = append(wc, "is_digital = :is_digital")
	}

	if filter.IsWeighted != nil {
		data["is_weighted"] = *filter.IsWeighted
		wc = append(wc, "is_weighted = :is_weighted")
	}

	if filter.IsTaxable != nil {
		data["is_taxable"] = *filter.IsTaxable
		wc = append(wc, "is_taxable = :is_taxable")
	}

	if filter.HasSerialNumber != nil {
		data["has_serial_number"] = *filter.HasSerialNumber
		wc = append(wc, "has_serial_number = :has_serial_number")
	}

	if filter.HasLotNumber != nil {
		data["has_lot_number"] = *filter.HasLotNumber
		wc = append(wc, "has_lot_number = :has_lot_number")
	}

	if filter.HasImages != nil {
		if *filter.HasImages {
			wc = append(wc, "jsonb_array_length(image_urls) > 0")
		} else {
			wc = append(wc, "(image_urls IS NULL OR jsonb_array_length(image_urls) = 0)")
		}
	}

	if filter.HasVariants != nil {
		if *filter.HasVariants {
			wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id)")
		} else {
			wc = append(wc, "NOT EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id)")
		}
	}

	// Time-based filtering
	if filter.CreatedAfter != nil {
		data["created_after"] = *filter.CreatedAfter
		wc = append(wc, "created_at >= :created_after")
	}

	if filter.CreatedBefore != nil {
		data["created_before"] = *filter.CreatedBefore
		wc = append(wc, "created_at <= :created_before")
	}

	if filter.UpdatedAfter != nil {
		data["updated_after"] = *filter.UpdatedAfter
		wc = append(wc, "updated_at >= :updated_after")
	}

	if filter.UpdatedBefore != nil {
		data["updated_before"] = *filter.UpdatedBefore
		wc = append(wc, "updated_at <= :updated_before")
	}

	// Special search parameters
	if filter.ReturnPolicy != nil {
		data["return_policy"] = fmt.Sprintf("%%%s%%", *filter.ReturnPolicy)
		wc = append(wc, "return_policy LIKE :return_policy")
	}

	if filter.SearchTerm != nil {
		data["search_term"] = fmt.Sprintf("%%%s%%", *filter.SearchTerm)
		wc = append(wc, "(name LIKE :search_term OR description LIKE :search_term OR short_description LIKE :search_term OR sku LIKE :search_term OR brand LIKE :search_term OR manufacturer LIKE :search_term)")
	}

	if filter.RelatedTo != nil {
		data["related_to"] = *filter.RelatedTo
		wc = append(wc, "related_products = :related_to")
	}

	// Variant filtering
	if filter.HasVariantWithSKU != nil {
		data["variant_sku"] = *filter.HasVariantWithSKU
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.sku = :variant_sku)")
	}

	if filter.HasVariantWithBarcode != nil {
		data["variant_barcode"] = *filter.HasVariantWithBarcode
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.barcode = :variant_barcode)")
	}

	if filter.HasVariantWithMinPrice != nil {
		data["variant_min_price"] = *filter.HasVariantWithMinPrice
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.price >= :variant_min_price)")
	}

	if filter.HasVariantWithMaxPrice != nil {
		data["variant_max_price"] = *filter.HasVariantWithMaxPrice
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.price <= :variant_max_price)")
	}

	if filter.HasVariantWithMinQuantity != nil {
		data["variant_min_quantity"] = *filter.HasVariantWithMinQuantity
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.quantity >= :variant_min_quantity)")
	}

	if filter.HasVariantWithMaxQuantity != nil {
		data["variant_max_quantity"] = *filter.HasVariantWithMaxQuantity
		wc = append(wc, "EXISTS (SELECT 1 FROM product_variants WHERE product_variants.product_id = products.product_id AND product_variants.quantity <= :variant_max_quantity)")
	}

	if len(wc) > 0 {
		buf.WriteString(" WHERE ")
		buf.WriteString(strings.Join(wc, " AND "))
	}
}

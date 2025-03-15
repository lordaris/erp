package productbus

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/types/category"
	"github.com/lordaris/erp/business/types/money"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/productstatus"
	"github.com/lordaris/erp/business/types/subcategory"
	"github.com/lordaris/erp/business/types/taxcategory"
	"github.com/lordaris/erp/business/types/uom"
)

// TestGenerateNewProducts is a helper method for testing.
func TestGenerateNewProducts(n int, userID uuid.UUID) []NewProduct {
	newPrds := make([]NewProduct, n)

	idx := rand.Intn(10000)
	for i := 0; i < n; i++ {
		idx++

		// Generate a random price between 10 and 500
		price := rand.Float64()*490 + 10

		// Create consistent test data with all required fields and sensible defaults
		np := NewProduct{
			UserID:          userID,
			SKU:             fmt.Sprintf("SKU-%d", idx),
			Barcode:         fmt.Sprintf("BAR-%d", idx),
			Name:            name.MustParse(fmt.Sprintf("Product %d", idx)),
			Description:     fmt.Sprintf("Description for product %d", idx),
			Category:        category.MustParse("Electronics"),
			Subcategory:     subcategory.MustParse("Computers"),
			Status:          productstatus.MustParse(productstatus.Active),
			TaxCategory:     taxcategory.MustParse(taxcategory.Standard),
			UnitOfMeasure:   uom.MustParse(uom.Each),
			CostPrice:       money.MustParse(price),
			RetailPrice:     money.MustParse(price * 2),
			WholesalePrice:  money.MustParse(price * 1.5),
			IsTaxable:       true,
			HasSerialNumber: false,
			HasLotNumber:    false,
			Attributes:      make(JSONMap),
			ImageURLs:       StringArray{},
		}

		newPrds[i] = np
	}

	return newPrds
}

// TestGenerateSeedProducts is a helper method for testing.
func TestGenerateSeedProducts(ctx context.Context, n int, api *Business, userID uuid.UUID) ([]Product, error) {
	newPrds := TestGenerateNewProducts(n, userID)

	prds := make([]Product, len(newPrds))
	for i, np := range newPrds {
		prd, err := api.Create(ctx, np)
		if err != nil {
			return nil, fmt.Errorf("seeding product: idx: %d : %w", i, err)
		}

		prds[i] = prd
	}

	return prds, nil
}

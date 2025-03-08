package inventorybus_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/sdk/dbtest"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/unitest"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/quantity"
	"github.com/lordaris/erp/business/types/role"
)

func Test_Inventory(t *testing.T) {
	t.Parallel()

	db := dbtest.New(t, "Test_Inventory")

	// Skip the test if the required table doesn't exist (likely not migrated yet)
	if err := checkTableExists(db); err != nil {
		t.Skip("inventory tests skipped: ", err)
	}

	sd, err := insertSeedData(db.BusDomain)
	if err != nil {
		t.Fatalf("Seeding error: %s", err)
	}

	// -------------------------------------------------------------------------

	unitest.Run(t, query(db.BusDomain, sd), "query")
	unitest.Run(t, create(db.BusDomain, sd), "create")
	unitest.Run(t, update(db.BusDomain, sd), "update")
	unitest.Run(t, delete(db.BusDomain, sd), "delete")
}

// checkTableExists verifies the inventories table exists or returns an error
func checkTableExists(db *dbtest.Database) error {
	var exists bool
	query := `SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = 'inventories')`
	err := db.DB.QueryRow(query).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("inventories table does not exist")
	}
	return nil
}

// =============================================================================

// TestGenerateNewInventories is a helper method for testing.
func TestGenerateNewInventories(n int, productID uuid.UUID) []inventorybus.NewInventory {
	newInvs := make([]inventorybus.NewInventory, n)

	for i := 0; i < n; i++ {
		locationCode := fmt.Sprintf("A-%d-%d", i+1, i+10)

		ni := inventorybus.NewInventory{
			ProductID: productID,
			Location:  location.MustParse(locationCode),
			Name:      name.MustParse(fmt.Sprintf("Inventory Item %d", i+1)),
			Quantity:  quantity.MustParse(i + 10),
		}

		newInvs[i] = ni
	}

	return newInvs
}

// TestGenerateSeedInventories is a helper method for testing.
func TestGenerateSeedInventories(ctx context.Context, n int, api *inventorybus.Business, productID uuid.UUID) ([]inventorybus.Inventory, error) {
	newInvs := TestGenerateNewInventories(n, productID)

	invs := make([]inventorybus.Inventory, len(newInvs))
	for i, ni := range newInvs {
		inv, err := api.Create(ctx, ni)
		if err != nil {
			return nil, fmt.Errorf("seeding inventory: idx: %d : %w", i, err)
		}

		invs[i] = inv
	}

	return invs, nil
}

// =============================================================================

func insertSeedData(busDomain dbtest.BusDomain) (unitest.SeedData, error) {
	ctx := context.Background()

	usrs, err := userbus.TestSeedUsers(ctx, 1, role.User, busDomain.User)
	if err != nil {
		return unitest.SeedData{}, fmt.Errorf("seeding users : %w", err)
	}

	prds, err := productbus.TestGenerateSeedProducts(ctx, 2, busDomain.Product, usrs[0].ID)
	if err != nil {
		return unitest.SeedData{}, fmt.Errorf("seeding products : %w", err)
	}

	invs, err := TestGenerateSeedInventories(ctx, 2, busDomain.Inventory, prds[0].ID)
	if err != nil {
		return unitest.SeedData{}, fmt.Errorf("seeding inventories : %w", err)
	}

	tu1 := unitest.User{
		User:     usrs[0],
		Products: prds,
	}

	sd := unitest.SeedData{
		Users: []unitest.User{tu1},
		Extras: map[string]interface{}{
			"inventories": invs,
		},
	}

	return sd, nil
}

// =============================================================================

func query(busDomain dbtest.BusDomain, sd unitest.SeedData) []unitest.Table {
	invs := sd.Extras["inventories"].([]inventorybus.Inventory)

	table := []unitest.Table{
		{
			Name:    "all",
			ExpResp: invs,
			ExcFunc: func(ctx context.Context) any {
				resp, err := busDomain.Inventory.Query(ctx, inventorybus.QueryFilter{}, inventorybus.DefaultOrderBy, page.MustParse("1", "10"))
				if err != nil {
					return err
				}

				// Sort to match expected order
				sort.Slice(resp, func(i, j int) bool {
					return resp[i].ID.String() <= resp[j].ID.String()
				})

				return resp
			},
			CmpFunc: func(got any, exp any) string {
				gotResp, exists := got.([]inventorybus.Inventory)
				if !exists {
					return "error occurred"
				}

				expResp := exp.([]inventorybus.Inventory)

				for i := range gotResp {
					if gotResp[i].DateCreated.Format(time.RFC3339) == expResp[i].DateCreated.Format(time.RFC3339) {
						expResp[i].DateCreated = gotResp[i].DateCreated
					}

					if gotResp[i].DateUpdated.Format(time.RFC3339) == expResp[i].DateUpdated.Format(time.RFC3339) {
						expResp[i].DateUpdated = gotResp[i].DateUpdated
					}
				}

				return cmp.Diff(gotResp, expResp)
			},
		},
		{
			Name:    "byid",
			ExpResp: invs[0],
			ExcFunc: func(ctx context.Context) any {
				resp, err := busDomain.Inventory.QueryByID(ctx, invs[0].ID)
				if err != nil {
					return err
				}

				return resp
			},
			CmpFunc: func(got any, exp any) string {
				gotResp, exists := got.(inventorybus.Inventory)
				if !exists {
					return "error occurred"
				}

				expResp := exp.(inventorybus.Inventory)

				if gotResp.DateCreated.Format(time.RFC3339) == expResp.DateCreated.Format(time.RFC3339) {
					expResp.DateCreated = gotResp.DateCreated
				}

				if gotResp.DateUpdated.Format(time.RFC3339) == expResp.DateUpdated.Format(time.RFC3339) {
					expResp.DateUpdated = gotResp.DateUpdated
				}

				return cmp.Diff(gotResp, expResp)
			},
		},
	}

	return table
}

func create(busDomain dbtest.BusDomain, sd unitest.SeedData) []unitest.Table {
	tu := sd.Users[0]
	productID := tu.Products[0].ID

	table := []unitest.Table{
		{
			Name: "basic",
			ExpResp: inventorybus.Inventory{
				ProductID: productID,
				Location:  location.MustParse("A-1-1"),
				Name:      name.MustParse("New Inventory"),
				Quantity:  quantity.MustParse(25),
			},
			ExcFunc: func(ctx context.Context) any {
				ni := inventorybus.NewInventory{
					ProductID: productID,
					Location:  location.MustParse("A-1-1"),
					Name:      name.MustParse("New Inventory"),
					Quantity:  quantity.MustParse(25),
				}

				resp, err := busDomain.Inventory.Create(ctx, ni)
				if err != nil {
					return err
				}

				return resp
			},
			CmpFunc: func(got any, exp any) string {
				gotResp, exists := got.(inventorybus.Inventory)
				if !exists {
					return "error occurred"
				}

				expResp := exp.(inventorybus.Inventory)

				expResp.ID = gotResp.ID
				expResp.DateCreated = gotResp.DateCreated
				expResp.DateUpdated = gotResp.DateUpdated

				return cmp.Diff(gotResp, expResp)
			},
		},
	}

	return table
}

func update(busDomain dbtest.BusDomain, sd unitest.SeedData) []unitest.Table {
	invs := sd.Extras["inventories"].([]inventorybus.Inventory)

	newLoc := location.MustParse("B-2-2")
	newName := name.MustParse("Updated Inventory")
	newQty := quantity.MustParse(50)

	table := []unitest.Table{
		{
			Name: "basic",
			ExpResp: inventorybus.Inventory{
				ID:          invs[0].ID,
				ProductID:   invs[0].ProductID,
				Location:    newLoc,
				Name:        newName,
				Quantity:    newQty,
				DateCreated: invs[0].DateCreated,
				DateUpdated: invs[0].DateUpdated,
			},
			ExcFunc: func(ctx context.Context) any {
				ui := inventorybus.UpdateInventory{
					Location: &newLoc,
					Name:     &newName,
					Quantity: &newQty,
				}

				resp, err := busDomain.Inventory.Update(ctx, invs[0], ui)
				if err != nil {
					return err
				}

				return resp
			},
			CmpFunc: func(got any, exp any) string {
				gotResp, exists := got.(inventorybus.Inventory)
				if !exists {
					return "error occurred"
				}

				expResp := exp.(inventorybus.Inventory)

				expResp.DateUpdated = gotResp.DateUpdated

				return cmp.Diff(gotResp, expResp)
			},
		},
	}

	return table
}

func delete(busDomain dbtest.BusDomain, sd unitest.SeedData) []unitest.Table {
	invs := sd.Extras["inventories"].([]inventorybus.Inventory)

	table := []unitest.Table{
		{
			Name:    "basic",
			ExpResp: nil,
			ExcFunc: func(ctx context.Context) any {
				if err := busDomain.Inventory.Delete(ctx, invs[1]); err != nil {
					return err
				}

				return nil
			},
			CmpFunc: func(got any, exp any) string {
				return cmp.Diff(got, exp)
			},
		},
	}

	return table
}

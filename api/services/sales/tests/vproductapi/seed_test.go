package vproduct_test

import (
	"context"
	"fmt"

	"github.com/lordaris/erp/app/sdk/apitest"
	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/sdk/dbtest"
	"github.com/lordaris/erp/business/types/role"
)

func insertSeedData(db *dbtest.Database, ath *auth.Auth) (apitest.SeedData, error) {
	ctx := context.Background()
	busDomain := db.BusDomain

	usrs, err := userbus.TestSeedUsers(ctx, 1, role.User, busDomain.User)
	if err != nil {
		return apitest.SeedData{}, fmt.Errorf("seeding users : %w", err)
	}

	prds, err := productbus.TestGenerateSeedProducts(ctx, 2, busDomain.Product, usrs[0].ID)
	if err != nil {
		return apitest.SeedData{}, fmt.Errorf("seeding products : %w", err)
	}

	tu1 := apitest.User{
		User:     usrs[0],
		Products: prds,
		Token:    apitest.Token(db.BusDomain.User, ath, usrs[0].Email.Address),
	}

	// -------------------------------------------------------------------------

	usrs, err = userbus.TestSeedUsers(ctx, 1, role.Admin, busDomain.User)
	if err != nil {
		return apitest.SeedData{}, fmt.Errorf("seeding users : %w", err)
	}

	prds, err = productbus.TestGenerateSeedProducts(ctx, 2, busDomain.Product, usrs[0].ID)
	if err != nil {
		return apitest.SeedData{}, fmt.Errorf("seeding products : %w", err)
	}

	tu2 := apitest.User{
		User:     usrs[0],
		Products: prds,
		Token:    apitest.Token(db.BusDomain.User, ath, usrs[0].Email.Address),
	}

	// -------------------------------------------------------------------------

	sd := apitest.SeedData{
		Admins: []apitest.User{tu2},
		Users:  []apitest.User{tu1},
	}

	return sd, nil
}

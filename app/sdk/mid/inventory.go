package mid

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/app/sdk/authclient"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/foundation/web"
)

// AuthorizeInventory executes the specified role and extracts the specified
// inventory from the DB if an inventory id is specified in the call.
func AuthorizeInventory(client *authclient.Client, inventoryBus *inventorybus.Business) web.MidFunc {
	m := func(next web.HandlerFunc) web.HandlerFunc {
		h := func(ctx context.Context, r *http.Request) web.Encoder {
			id := web.Param(r, "inventory_id")

			var userID uuid.UUID

			if id != "" {
				var err error
				inventoryID, err := uuid.Parse(id)
				if err != nil {
					return errs.New(errs.Unauthenticated, ErrInvalidID)
				}

				inv, err := inventoryBus.QueryByID(ctx, inventoryID)
				if err != nil {
					switch {
					case errors.Is(err, inventorybus.ErrNotFound):
						return errs.New(errs.Unauthenticated, err)
					default:
						return errs.Newf(errs.Unauthenticated, "querybyid: inventoryID[%s]: %s", inventoryID, err)
					}
				}

				// For inventory, we'll use the claim's user ID
				// since inventory might not have a direct user association
				userID, err = GetUserID(ctx)
				if err != nil {
					return errs.New(errs.Unauthenticated, err)
				}

				ctx = setInventory(ctx, inv)
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			auth := authclient.Authorize{
				UserID: userID,
				Claims: GetClaims(ctx),
				Rule:   auth.RuleAny,
			}

			if err := client.Authorize(ctx, auth); err != nil {
				return errs.New(errs.Unauthenticated, err)
			}

			return next(ctx, r)
		}

		return h
	}

	return m
}

// GetInventory returns the inventory from the context.
func GetInventory(ctx context.Context) (inventorybus.Inventory, error) {
	v, ok := ctx.Value(inventoryKey).(inventorybus.Inventory)
	if !ok {
		return inventorybus.Inventory{}, errors.New("inventory not found in context")
	}

	return v, nil
}

// setInventory sets the inventory value into the context.
func setInventory(ctx context.Context, inv inventorybus.Inventory) context.Context {
	return context.WithValue(ctx, inventoryKey, inv)
}

// Package mid provides app level middleware support.
package mid

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/auth"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/foundation/web"
)

// isError tests if the Encoder has an error inside of it.
func isError(e web.Encoder) error {
	err, isError := e.(error)
	if isError {
		return err
	}
	return nil
}

// =============================================================================

type ctxKey int

const (
	claimKey ctxKey = iota + 1
	userIDKey
	userKey
	productKey
	homeKey
	trKey
)

func setClaims(ctx context.Context, claims auth.Claims) context.Context {
	return context.WithValue(ctx, claimKey, claims)
}

// GetClaims returns the claims from the context.
func GetClaims(ctx context.Context) auth.Claims {
	v, ok := ctx.Value(claimKey).(auth.Claims)
	if !ok {
		return auth.Claims{}
	}
	return v
}

func setUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUserID returns the user id from the context.
func GetUserID(ctx context.Context) (uuid.UUID, error) {
	v, ok := ctx.Value(userIDKey).(uuid.UUID)
	if !ok {
		return uuid.UUID{}, errors.New("user id not found in context")
	}

	return v, nil
}

func setUser(ctx context.Context, usr userbus.User) context.Context {
	return context.WithValue(ctx, userKey, usr)
}

// GetUser returns the user from the context.
func GetUser(ctx context.Context) (userbus.User, error) {
	v, ok := ctx.Value(userKey).(userbus.User)
	if !ok {
		return userbus.User{}, errors.New("user not found in context")
	}

	return v, nil
}

func setProduct(ctx context.Context, prd productbus.Product) context.Context {
	return context.WithValue(ctx, productKey, prd)
}

// GetProduct returns the product from the context.
func GetProduct(ctx context.Context) (productbus.Product, error) {
	v, ok := ctx.Value(productKey).(productbus.Product)
	if !ok {
		return productbus.Product{}, errors.New("product not found in context")
	}

	return v, nil
}

func setTran(ctx context.Context, tx sqldb.CommitRollbacker) context.Context {
	return context.WithValue(ctx, trKey, tx)
}

// GetTran retrieves the value that can manage a transaction.
func GetTran(ctx context.Context) (sqldb.CommitRollbacker, error) {
	v, ok := ctx.Value(trKey).(sqldb.CommitRollbacker)
	if !ok {
		return nil, errors.New("transaction not found in context")
	}

	return v, nil
}

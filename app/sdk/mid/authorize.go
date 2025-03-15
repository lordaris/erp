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
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/foundation/web"
)

// ErrInvalidID represents a condition where the id is not a uuid.
var ErrInvalidID = errors.New("ID is not in its proper form")

// Authorize validates authorization via the auth service.
func Authorize(client *authclient.Client, rule string) web.MidFunc {
	m := func(next web.HandlerFunc) web.HandlerFunc {
		h := func(ctx context.Context, r *http.Request) web.Encoder {
			userID, err := GetUserID(ctx)
			if err != nil {
				return errs.New(errs.Unauthenticated, err)
			}

			auth := authclient.Authorize{
				Claims: GetClaims(ctx),
				UserID: userID,
				Rule:   rule,
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := client.Authorize(ctx, auth); err != nil {
				return errs.New(errs.Unauthenticated, err)
			}

			return next(ctx, r)
		}

		return h
	}

	return m
}

// AuthorizeUser executes the specified role and extracts the specified
// user from the DB if a user id is specified in the call. Depending on the rule
// specified, the userid from the claims may be compared with the specified
// user id.
func AuthorizeUser(client *authclient.Client, userBus *userbus.Business, rule string) web.MidFunc {
	m := func(next web.HandlerFunc) web.HandlerFunc {
		h := func(ctx context.Context, r *http.Request) web.Encoder {
			id := web.Param(r, "user_id")

			var userID uuid.UUID

			if id != "" {
				var err error
				userID, err = uuid.Parse(id)
				if err != nil {
					return errs.New(errs.Unauthenticated, ErrInvalidID)
				}

				usr, err := userBus.QueryByID(ctx, userID)
				if err != nil {
					switch {
					case errors.Is(err, userbus.ErrNotFound):
						return errs.New(errs.Unauthenticated, err)
					default:
						return errs.Newf(errs.Unauthenticated, "querybyid: userID[%s]: %s", userID, err)
					}
				}

				ctx = setUser(ctx, usr)
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			auth := authclient.Authorize{
				Claims: GetClaims(ctx),
				UserID: userID,
				Rule:   rule,
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

// AuthorizeProduct executes the specified role and extracts the specified
// product from the DB if a product id is specified in the call. Depending on
// the rule specified, the userid from the claims may be compared with the
// specified user id from the product.
func AuthorizeProduct(client *authclient.Client, productBus *productbus.Business) web.MidFunc {
	m := func(next web.HandlerFunc) web.HandlerFunc {
		h := func(ctx context.Context, r *http.Request) web.Encoder {
			id := web.Param(r, "product_id")

			var userID uuid.UUID

			if id != "" {
				var err error
				productID, err := uuid.Parse(id)
				if err != nil {
					return errs.New(errs.Unauthenticated, ErrInvalidID)
				}

				prd, err := productBus.QueryByID(ctx, productID)
				if err != nil {
					switch {
					case errors.Is(err, productbus.ErrNotFound):
						return errs.New(errs.Unauthenticated, err)
					default:
						return errs.Newf(errs.Internal, "querybyid: productID[%s]: %s", productID, err)
					}
				}

				userID = prd.UserID
				ctx = setProduct(ctx, prd)
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			auth := authclient.Authorize{
				UserID: userID,
				Claims: GetClaims(ctx),
				Rule:   auth.RuleAdminOrSubject,
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

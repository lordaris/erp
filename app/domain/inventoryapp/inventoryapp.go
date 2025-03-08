// Package inventoryapp maintains the app layer api for the inventory domain.
package inventoryapp

import (
	"context"
	"net/http"

	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/app/sdk/mid"
	"github.com/lordaris/erp/app/sdk/query"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/foundation/web"
)

type app struct {
	inventoryBus *inventorybus.Business
}

func newApp(inventoryBus *inventorybus.Business) *app {
	return &app{
		inventoryBus: inventoryBus,
	}
}

func (a *app) create(ctx context.Context, r *http.Request) web.Encoder {
	var app NewInventory
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	ni, err := toBusNewInventory(ctx, app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	inv, err := a.inventoryBus.Create(ctx, ni)
	if err != nil {
		return errs.Newf(errs.Internal, "create: inv[%+v]: %s", app, err)
	}

	return toAppInventory(inv)
}

func (a *app) update(ctx context.Context, r *http.Request) web.Encoder {
	var app UpdateInventory
	if err := web.Decode(r, &app); err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	ui, err := toBusUpdateInventory(app)
	if err != nil {
		return errs.New(errs.InvalidArgument, err)
	}

	inv, err := mid.GetInventory(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "inventory missing in context: %s", err)
	}

	updInv, err := a.inventoryBus.Update(ctx, inv, ui)
	if err != nil {
		return errs.Newf(errs.Internal, "update: inventoryID[%s] ui[%+v]: %s", inv.ID, app, err)
	}

	return toAppInventory(updInv)
}

func (a *app) delete(ctx context.Context, _ *http.Request) web.Encoder {
	inv, err := mid.GetInventory(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "inventoryID missing in context: %s", err)
	}

	if err := a.inventoryBus.Delete(ctx, inv); err != nil {
		return errs.Newf(errs.Internal, "delete: inventoryID[%s]: %s", inv.ID, err)
	}

	return nil
}

func (a *app) query(ctx context.Context, r *http.Request) web.Encoder {
	qp := parseQueryParams(r)

	page, err := page.Parse(qp.Page, qp.Rows)
	if err != nil {
		return errs.NewFieldErrors("page", err)
	}

	filter, err := parseFilter(qp)
	if err != nil {
		return err.(*errs.Error)
	}

	orderBy, err := order.Parse(orderByFields, qp.OrderBy, inventorybus.DefaultOrderBy)
	if err != nil {
		return errs.NewFieldErrors("order", err)
	}

	invs, err := a.inventoryBus.Query(ctx, filter, orderBy, page)
	if err != nil {
		return errs.Newf(errs.Internal, "query: %s", err)
	}

	total, err := a.inventoryBus.Count(ctx, filter)
	if err != nil {
		return errs.Newf(errs.Internal, "count: %s", err)
	}

	return query.NewResult(toAppInventories(invs), total, page)
}

func (a *app) queryByID(ctx context.Context, _ *http.Request) web.Encoder {
	inv, err := mid.GetInventory(ctx)
	if err != nil {
		return errs.Newf(errs.Internal, "querybyid: %s", err)
	}

	return toAppInventory(inv)
}

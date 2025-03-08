// Package inventorybus provides business access to inventory domain.
package inventorybus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/delegate"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/foundation/logger"
	"github.com/lordaris/erp/foundation/otel"
)

// Set of error variables for CRUD operations.
var (
	ErrNotFound        = errors.New("inventory not found")
	ErrProductNotFound = errors.New("product not found")
	ErrInvalidQuantity = errors.New("quantity not valid")
)

// Storer interface declares the behavior this package needs to persist and
// retrieve data.
type Storer interface {
	NewWithTx(tx sqldb.CommitRollbacker) (Storer, error)
	Create(ctx context.Context, inv Inventory) error
	Update(ctx context.Context, inv Inventory) error
	Delete(ctx context.Context, inv Inventory) error
	Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Inventory, error)
	Count(ctx context.Context, filter QueryFilter) (int, error)
	QueryByID(ctx context.Context, inventoryID uuid.UUID) (Inventory, error)
	QueryByProductID(ctx context.Context, productID uuid.UUID) ([]Inventory, error)
}

// Business manages the set of APIs for inventory access.
type Business struct {
	log        *logger.Logger
	productBus *productbus.Business
	delegate   *delegate.Delegate
	storer     Storer
}

// NewBusiness constructs an inventory business API for use.
func NewBusiness(log *logger.Logger, productBus *productbus.Business, delegate *delegate.Delegate, storer Storer) *Business {
	b := Business{
		log:        log,
		productBus: productBus,
		delegate:   delegate,
		storer:     storer,
	}

	return &b
}

// NewWithTx constructs a new business value that will use the
// specified transaction in any store related calls.
func (b *Business) NewWithTx(tx sqldb.CommitRollbacker) (*Business, error) {
	storer, err := b.storer.NewWithTx(tx)
	if err != nil {
		return nil, err
	}

	productBus, err := b.productBus.NewWithTx(tx)
	if err != nil {
		return nil, err
	}

	bus := Business{
		log:        b.log,
		productBus: productBus,
		delegate:   b.delegate,
		storer:     storer,
	}

	return &bus, nil
}

// Create adds a new inventory to the system.
func (b *Business) Create(ctx context.Context, ni NewInventory) (Inventory, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.create")
	defer span.End()

	now := time.Now()

	inv := Inventory{
		ID:          uuid.New(),
		ProductID:   ni.ProductID,
		Location:    ni.Location,
		Name:        ni.Name,
		Quantity:    ni.Quantity,
		DateCreated: now,
		DateUpdated: now,
	}

	if err := b.storer.Create(ctx, inv); err != nil {
		return Inventory{}, fmt.Errorf("create: %w", err)
	}

	return inv, nil
}

// Update modifies information about an inventory.
func (b *Business) Update(ctx context.Context, inv Inventory, ui UpdateInventory) (Inventory, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.update")
	defer span.End()

	if ui.ProductID != nil {
		// Validate the product ID exists
		if _, err := b.productBus.QueryByID(ctx, *ui.ProductID); err != nil {
			return Inventory{}, fmt.Errorf("product.querybyid: %s: %w", *ui.ProductID, err)
		}
		inv.ProductID = *ui.ProductID
	}

	if ui.Location != nil {
		inv.Location = *ui.Location
	}

	if ui.Name != nil {
		inv.Name = *ui.Name
	}

	if ui.Quantity != nil {
		inv.Quantity = *ui.Quantity
	}

	inv.DateUpdated = time.Now()

	if err := b.storer.Update(ctx, inv); err != nil {
		return Inventory{}, fmt.Errorf("update: %w", err)
	}

	return inv, nil
}

// Delete removes the specified inventory.
func (b *Business) Delete(ctx context.Context, inv Inventory) error {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.delete")
	defer span.End()

	if err := b.storer.Delete(ctx, inv); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	return nil
}

// Query retrieves a list of existing inventories.
func (b *Business) Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Inventory, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.query")
	defer span.End()

	invs, err := b.storer.Query(ctx, filter, orderBy, page)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	return invs, nil
}

// Count returns the total number of inventories.
func (b *Business) Count(ctx context.Context, filter QueryFilter) (int, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.count")
	defer span.End()

	return b.storer.Count(ctx, filter)
}

// QueryByID finds the inventory by the specified ID.
func (b *Business) QueryByID(ctx context.Context, inventoryID uuid.UUID) (Inventory, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.querybyid")
	defer span.End()

	inv, err := b.storer.QueryByID(ctx, inventoryID)
	if err != nil {
		return Inventory{}, fmt.Errorf("query: inventoryID[%s]: %w", inventoryID, err)
	}

	return inv, nil
}

// QueryByProductID finds the inventories by a specified Product ID.
func (b *Business) QueryByProductID(ctx context.Context, productID uuid.UUID) ([]Inventory, error) {
	ctx, span := otel.AddSpan(ctx, "business.inventorybus.querybyproductid")
	defer span.End()

	invs, err := b.storer.QueryByProductID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	return invs, nil
}

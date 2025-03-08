// Package inventorydb contains inventory related CRUD functionality.
package inventorydb

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/foundation/logger"
)

// Store manages the set of APIs for inventory database access.
type Store struct {
	log *logger.Logger
	db  sqlx.ExtContext
}

// NewStore constructs the api for data access.
func NewStore(log *logger.Logger, db *sqlx.DB) *Store {
	return &Store{
		log: log,
		db:  db,
	}
}

// NewWithTx constructs a new Store value replacing the sqlx DB
// value with a sqlx DB value that is currently inside a transaction.
func (s *Store) NewWithTx(tx sqldb.CommitRollbacker) (inventorybus.Storer, error) {
	ec, err := sqldb.GetExtContext(tx)
	if err != nil {
		return nil, err
	}

	store := Store{
		log: s.log,
		db:  ec,
	}

	return &store, nil
}

// Create adds an Inventory to the sqldb. It returns the created Inventory with
// fields like ID and DateCreated populated.
func (s *Store) Create(ctx context.Context, inv inventorybus.Inventory) error {
	const q = `
	INSERT INTO inventories
		(inventory_id, product_id, location, name, quantity, date_created, date_updated)
	VALUES
		(:inventory_id, :product_id, :location, :name, :quantity, :date_created, :date_updated)`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBInventory(inv)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// Update modifies data about an inventory. It will error if the specified ID is
// invalid or does not reference an existing inventory.
func (s *Store) Update(ctx context.Context, inv inventorybus.Inventory) error {
	const q = `
	UPDATE
		inventories
	SET
		"product_id" = :product_id,
		"location" = :location,
		"name" = :name,
		"quantity" = :quantity,
		"date_updated" = :date_updated
	WHERE
		inventory_id = :inventory_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBInventory(inv)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// Delete removes the inventory identified by a given ID.
func (s *Store) Delete(ctx context.Context, inv inventorybus.Inventory) error {
	data := struct {
		ID string `db:"inventory_id"`
	}{
		ID: inv.ID.String(),
	}

	const q = `
	DELETE FROM
		inventories
	WHERE
		inventory_id = :inventory_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, data); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// Query gets all Inventories from the database.
func (s *Store) Query(ctx context.Context, filter inventorybus.QueryFilter, orderBy order.By, page page.Page) ([]inventorybus.Inventory, error) {
	data := map[string]any{
		"offset":        (page.Number() - 1) * page.RowsPerPage(),
		"rows_per_page": page.RowsPerPage(),
	}

	const q = `
	SELECT
	    inventory_id, product_id, location, name, quantity, date_created, date_updated
	FROM
		inventories`

	buf := bytes.NewBufferString(q)
	s.applyFilter(filter, data, buf)

	orderByClause, err := orderByClause(orderBy)
	if err != nil {
		return nil, err
	}

	buf.WriteString(orderByClause)
	buf.WriteString(" OFFSET :offset ROWS FETCH NEXT :rows_per_page ROWS ONLY")

	var dbInvs []inventory
	if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, buf.String(), data, &dbInvs); err != nil {
		return nil, fmt.Errorf("namedqueryslice: %w", err)
	}

	return toBusInventories(dbInvs)
}

// Count returns the total number of users in the DB.
func (s *Store) Count(ctx context.Context, filter inventorybus.QueryFilter) (int, error) {
	data := map[string]any{}

	const q = `
	SELECT
		count(1)
	FROM
		inventories`

	buf := bytes.NewBufferString(q)
	s.applyFilter(filter, data, buf)

	var count struct {
		Count int `db:"count"`
	}
	if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, buf.String(), data, &count); err != nil {
		return 0, fmt.Errorf("db: %w", err)
	}

	return count.Count, nil
}

// QueryByID finds the inventory identified by a given ID.
func (s *Store) QueryByID(ctx context.Context, inventoryID uuid.UUID) (inventorybus.Inventory, error) {
	data := struct {
		ID string `db:"inventory_id"`
	}{
		ID: inventoryID.String(),
	}

	const q = `
	SELECT
	    inventory_id, product_id, location, name, quantity, date_created, date_updated
	FROM
		inventories
	WHERE
		inventory_id = :inventory_id`

	var dbInv inventory
	if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, q, data, &dbInv); err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			return inventorybus.Inventory{}, fmt.Errorf("db: %w", inventorybus.ErrNotFound)
		}
		return inventorybus.Inventory{}, fmt.Errorf("db: %w", err)
	}

	return toBusInventory(dbInv)
}

// QueryByProductID finds inventories by a given Product ID.
func (s *Store) QueryByProductID(ctx context.Context, productID uuid.UUID) ([]inventorybus.Inventory, error) {
	data := struct {
		ID string `db:"product_id"`
	}{
		ID: productID.String(),
	}

	const q = `
	SELECT
	    inventory_id, product_id, location, name, quantity, date_created, date_updated
	FROM
		inventories
	WHERE
		product_id = :product_id`

	var dbInvs []inventory
	if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, q, data, &dbInvs); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}

	return toBusInventories(dbInvs)
}

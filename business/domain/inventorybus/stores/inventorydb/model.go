package inventorydb

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/quantity"
)

type inventory struct {
	ID          uuid.UUID `db:"inventory_id"`
	ProductID   uuid.UUID `db:"product_id"`
	Location    string    `db:"location"`
	Name        string    `db:"name"`
	Quantity    int       `db:"quantity"`
	DateCreated time.Time `db:"date_created"`
	DateUpdated time.Time `db:"date_updated"`
}

func toDBInventory(bus inventorybus.Inventory) inventory {
	db := inventory{
		ID:          bus.ID,
		ProductID:   bus.ProductID,
		Location:    bus.Location.String(),
		Name:        bus.Name.String(),
		Quantity:    bus.Quantity.Value(),
		DateCreated: bus.DateCreated.UTC(),
		DateUpdated: bus.DateUpdated.UTC(),
	}

	return db
}

func toBusInventory(db inventory) (inventorybus.Inventory, error) {
	loc, err := location.Parse(db.Location)
	if err != nil {
		return inventorybus.Inventory{}, fmt.Errorf("parse location: %w", err)
	}

	name, err := name.Parse(db.Name)
	if err != nil {
		return inventorybus.Inventory{}, fmt.Errorf("parse name: %w", err)
	}

	quantity, err := quantity.Parse(db.Quantity)
	if err != nil {
		return inventorybus.Inventory{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := inventorybus.Inventory{
		ID:          db.ID,
		ProductID:   db.ProductID,
		Location:    loc,
		Name:        name,
		Quantity:    quantity,
		DateCreated: db.DateCreated.In(time.Local),
		DateUpdated: db.DateUpdated.In(time.Local),
	}

	return bus, nil
}

func toBusInventories(dbs []inventory) ([]inventorybus.Inventory, error) {
	bus := make([]inventorybus.Inventory, len(dbs))

	for i, db := range dbs {
		var err error
		bus[i], err = toBusInventory(db)
		if err != nil {
			return nil, err
		}
	}

	return bus, nil
}

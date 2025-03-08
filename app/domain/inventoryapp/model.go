package inventoryapp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/app/sdk/errs"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/quantity"
)

// Inventory represents information about an individual inventory item.
type Inventory struct {
	ID          string `json:"id"`
	ProductID   string `json:"productID"`
	Location    string `json:"location"`
	Name        string `json:"name"`
	Quantity    int    `json:"quantity"`
	DateCreated string `json:"dateCreated"`
	DateUpdated string `json:"dateUpdated"`
}

// Encode implements the encoder interface.
func (app Inventory) Encode() ([]byte, string, error) {
	data, err := json.Marshal(app)
	return data, "application/json", err
}

func toAppInventory(inv inventorybus.Inventory) Inventory {
	return Inventory{
		ID:          inv.ID.String(),
		ProductID:   inv.ProductID.String(),
		Location:    inv.Location.String(),
		Name:        inv.Name.String(),
		Quantity:    inv.Quantity.Value(),
		DateCreated: inv.DateCreated.Format(time.RFC3339),
		DateUpdated: inv.DateUpdated.Format(time.RFC3339),
	}
}

func toAppInventories(invs []inventorybus.Inventory) []Inventory {
	app := make([]Inventory, len(invs))
	for i, inv := range invs {
		app[i] = toAppInventory(inv)
	}

	return app
}

// =============================================================================

// NewInventory defines the data needed to add a new inventory item.
type NewInventory struct {
	ProductID string `json:"productID" validate:"required,uuid"`
	Location  string `json:"location" validate:"required"`
	Name      string `json:"name" validate:"required"`
	Quantity  int    `json:"quantity" validate:"required,gte=0"`
}

// Decode implements the decoder interface.
func (app *NewInventory) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app NewInventory) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

func toBusNewInventory(ctx context.Context, app NewInventory) (inventorybus.NewInventory, error) {
	productID, err := uuid.Parse(app.ProductID)
	if err != nil {
		return inventorybus.NewInventory{}, fmt.Errorf("parse productID: %w", err)
	}

	loc, err := location.Parse(app.Location)
	if err != nil {
		return inventorybus.NewInventory{}, fmt.Errorf("parse location: %w", err)
	}

	n, err := name.Parse(app.Name)
	if err != nil {
		return inventorybus.NewInventory{}, fmt.Errorf("parse name: %w", err)
	}

	q, err := quantity.Parse(app.Quantity)
	if err != nil {
		return inventorybus.NewInventory{}, fmt.Errorf("parse quantity: %w", err)
	}

	bus := inventorybus.NewInventory{
		ProductID: productID,
		Location:  loc,
		Name:      n,
		Quantity:  q,
	}

	return bus, nil
}

// =============================================================================

// UpdateInventory defines the data needed to update an inventory item.
type UpdateInventory struct {
	ProductID *string `json:"productID,omitempty" validate:"omitempty,uuid"`
	Location  *string `json:"location,omitempty"`
	Name      *string `json:"name,omitempty"`
	Quantity  *int    `json:"quantity,omitempty" validate:"omitempty,gte=0"`
}

// Decode implements the decoder interface.
func (app *UpdateInventory) Decode(data []byte) error {
	return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app UpdateInventory) Validate() error {
	if err := errs.Check(app); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}

func toBusUpdateInventory(app UpdateInventory) (inventorybus.UpdateInventory, error) {
	var productID *uuid.UUID
	if app.ProductID != nil {
		id, err := uuid.Parse(*app.ProductID)
		if err != nil {
			return inventorybus.UpdateInventory{}, fmt.Errorf("parse: %w", err)
		}
		productID = &id
	}

	var loc *location.Location
	if app.Location != nil {
		l, err := location.Parse(*app.Location)
		if err != nil {
			return inventorybus.UpdateInventory{}, fmt.Errorf("parse: %w", err)
		}
		loc = &l
	}

	var n *name.Name
	if app.Name != nil {
		nm, err := name.Parse(*app.Name)
		if err != nil {
			return inventorybus.UpdateInventory{}, fmt.Errorf("parse: %w", err)
		}
		n = &nm
	}

	var q *quantity.Quantity
	if app.Quantity != nil {
		qty, err := quantity.Parse(*app.Quantity)
		if err != nil {
			return inventorybus.UpdateInventory{}, fmt.Errorf("parse: %w", err)
		}
		q = &qty
	}

	bus := inventorybus.UpdateInventory{
		ProductID: productID,
		Location:  loc,
		Name:      n,
		Quantity:  q,
	}

	return bus, nil
}

// Package inventorybus provides business access to inventory domain.
package inventorybus

import (
	"time"

	"github.com/google/uuid"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
	"github.com/lordaris/erp/business/types/quantity"
)

// Inventory represents an individual inventory item.
type Inventory struct {
	ID          uuid.UUID
	ProductID   uuid.UUID
	Location    location.Location
	Name        name.Name
	Quantity    quantity.Quantity
	DateCreated time.Time
	DateUpdated time.Time
}

// NewInventory is what we require from clients when adding an Inventory.
type NewInventory struct {
	ProductID uuid.UUID
	Location  location.Location
	Name      name.Name
	Quantity  quantity.Quantity
}

// UpdateInventory defines what information may be provided to modify an
// existing Inventory. All fields are optional so clients can send just the
// fields they want changed. It uses pointer fields so we can differentiate
// between a field that was not provided and a field that was provided as
// explicitly blank. Normally we do not want to use pointers to basic types but
// we make exceptions around marshalling/unmarshalling.
type UpdateInventory struct {
	ProductID *uuid.UUID
	Location  *location.Location
	Name      *name.Name
	Quantity  *quantity.Quantity
}

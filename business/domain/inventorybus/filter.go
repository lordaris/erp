package inventorybus

import (
	"github.com/google/uuid"
	"github.com/lordaris/erp/business/types/location"
	"github.com/lordaris/erp/business/types/name"
)

// QueryFilter holds the available fields a query can be filtered on.
// We are using pointer semantics because the With API mutates the value.
type QueryFilter struct {
	ID        *uuid.UUID
	ProductID *uuid.UUID
	Location  *location.Location
	Name      *name.Name
	Quantity  *int
}

# Service Architecture Quick Reference Manual

This manual provides a quick reference for creating new applications within the service architecture.

## Core Architecture

The service follows a layered architecture:

1. **Business Layer**: Core domain logic and models
2. **Store Layer**: Database access
3. **Application Layer**: API and interface with external systems
4. **Foundation Layer**: Common utilities and infrastructure

## Creating New Business Domains

### Domain Model Structure

1. Create a new package under `business/domain/{domainname}bus/` containing:

```
business/domain/{domainname}bus/
├── model.go         # Core domain models and types
├── {domainname}bus.go  # Business logic implementation
├── filter.go        # Query filtering
├── order.go         # Sorting definitions
├── event.go         # Event handling for cross-domain communication
└── testutil.go      # Test utilities
```

### Creating a Domain Model (model.go)

Define your core domain entities with proper types and validation:

```go
// model.go
package {domainname}bus

type Entity struct {
    ID          uuid.UUID
    Name        name.Name    // Use strong types for validation
    // Add other fields
    DateCreated time.Time
    DateUpdated time.Time
}

// NewEntity defines data required to create a new entity
type NewEntity struct {
    Name        name.Name
    // Other fields needed for creation
}

// UpdateEntity defines mutable fields for updates
type UpdateEntity struct {
    Name        *name.Name  // Use pointers for optional update fields
    // Other updatable fields
}
```

### Implementing Business Logic ({domainname}bus.go)

Business logic wraps the store with domain-specific operations:

```go
// {domainname}bus.go
package {domainname}bus

type Business struct {
    log      *logger.Logger
    delegate *delegate.Delegate
    storer   Storer
}

// Storer interface defines required DB operations
type Storer interface {
    NewWithTx(tx sqldb.CommitRollbacker) (Storer, error)
    Create(ctx context.Context, entity Entity) error
    Update(ctx context.Context, entity Entity) error
    Delete(ctx context.Context, entity Entity) error
    Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Entity, error)
    Count(ctx context.Context, filter QueryFilter) (int, error)
    QueryByID(ctx context.Context, id uuid.UUID) (Entity, error)
}

// Create adds a new entity
func (b *Business) Create(ctx context.Context, ne NewEntity) (Entity, error) {
    // Convert NewEntity to Entity, add validation, generate IDs
    // Call storer.Create
}

// Update modifies an existing entity
func (b *Business) Update(ctx context.Context, entity Entity, ue UpdateEntity) (Entity, error) {
    // Apply changes, validate, and save
}

// Other business operations...
```

### Define Filtering (filter.go)

```go
// filter.go
package {domainname}bus

type QueryFilter struct {
    ID               *uuid.UUID
    Name             *name.Name
    // Other filter fields
    StartCreatedDate *time.Time
    EndCreatedDate   *time.Time
}
```

### Define Ordering (order.go)

```go
// order.go
package {domainname}bus

import "github.com/ardanlabs/service/business/sdk/order"

// DefaultOrderBy represents the default way we sort.
var DefaultOrderBy = order.NewBy(OrderByID, order.ASC)

// Set of fields that the results can be ordered by.
const (
    OrderByID      = "id"
    OrderByName    = "name"
    // Other orderable fields
)
```

### Event Handling (event.go)

For cross-domain communication:

```go
// event.go
package {domainname}bus

import (
    "encoding/json"
    "github.com/ardanlabs/service/business/sdk/delegate"
)

// DomainName represents the name of this domain.
const DomainName = "{domainname}"

// Set of delegate actions.
const (
    ActionUpdated = "updated"
    // Other actions
)

// ActionUpdatedParms represents the parameters for the updated action.
type ActionUpdatedParms struct {
    EntityID uuid.UUID
    // Other parameters
}

// ActionUpdatedData constructs the data for the updated action.
func ActionUpdatedData(params UpdateEntity, entityID uuid.UUID) delegate.Data {
    // Create and return delegate data
}
```

## Creating Store Layer

Create store implementation under `business/domain/{domainname}bus/stores/{domainname}db/`:

```
business/domain/{domainname}bus/stores/{domainname}db/
├── {domainname}db.go  # Store implementation
├── model.go         # DB model <-> Domain model conversion
├── filter.go        # Filter implementation
└── order.go         # Order implementation
```

### Store Implementation ({domainname}db.go)

```go
// {domainname}db.go
package {domainname}db

type Store struct {
    log *logger.Logger
    db  sqlx.ExtContext
}

// Implement Storer interface methods to interact with the database
```

### Model Conversion (model.go)

```go
// model.go
package {domainname}db

// DB entity representation
type entity struct {
    ID          uuid.UUID `db:"entity_id"`
    Name        string    `db:"name"`
    // Other DB fields
    DateCreated time.Time `db:"date_created"`
    DateUpdated time.Time `db:"date_updated"`
}

// toDBEntity converts domain entity to DB entity
func toDBEntity(bus {domainname}bus.Entity) entity {
    // Conversion logic
}

// toBusEntity converts DB entity to domain entity
func toBusEntity(db entity) ({domainname}bus.Entity, error) {
    // Conversion logic with validation
}
```

### Filter Implementation (filter.go)

```go
// filter.go
package {domainname}db

func (s *Store) applyFilter(filter {domainname}bus.QueryFilter, data map[string]any, buf *bytes.Buffer) {
    // Build WHERE clauses based on filter
}
```

### Order Implementation (order.go)

```go
// order.go
package {domainname}db

var orderByFields = map[string]string{
    {domainname}bus.OrderByID: "entity_id",
    {domainname}bus.OrderByName: "name",
    // Other field mappings
}

func orderByClause(orderBy order.By) (string, error) {
    // Build ORDER BY clause
}
```

## Creating Application Layer

Create app layer under `app/domain/{domainname}app/`:

```
app/domain/{domainname}app/
├── {domainname}app.go  # App layer implementation
├── model.go         # API models and conversion
├── route.go         # Route definitions
├── filter.go        # API filter parsing
└── order.go         # API order mapping
```

### App Implementation ({domainname}app.go)

```go
// {domainname}app.go
package {domainname}app

type app struct {
    {domainname}Bus *{domainname}bus.Business
}

// Implement HTTP handlers for CRUD operations
```

### API Models (model.go)

```go
// model.go
package {domainname}app

type Entity struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    // Other API fields
    DateCreated string    `json:"dateCreated"`
    DateUpdated string    `json:"dateUpdated"`
}

// Define API request/response models with validation and conversion functions
```

### Routes (route.go)

```go
// route.go
package {domainname}app

func Routes(app *web.App, cfg Config) {
    const version = "v1"

    authen := mid.Authenticate(cfg.AuthClient)
    ruleAny := mid.Authorize(cfg.AuthClient, auth.RuleAny)

    api := newApp(cfg.{DomainName}Bus)

    app.HandlerFunc(http.MethodGet, version, "/{domainname}s", api.query, authen, ruleAny)
    app.HandlerFunc(http.MethodGet, version, "/{domainname}s/{id}", api.queryByID, authen, ruleAuth)
    app.HandlerFunc(http.MethodPost, version, "/{domainname}s", api.create, authen, ruleAuth)
    app.HandlerFunc(http.MethodPut, version, "/{domainname}s/{id}", api.update, authen, ruleAuth)
    app.HandlerFunc(http.MethodDelete, version, "/{domainname}s/{id}", api.delete, authen, ruleAuth)
}
```

## Wiring Up the New Domain

1. **Add to Business Domain Layer**:

   - Register in `business/sdk/dbtest/business.go`

2. **Add to API Routes**:

   - Register in `api/services/sales/build/all/all.go`
   - Or in specific builds like `crud` or `reporting`

3. **Add Tests**:
   - Create unit tests in `business/domain/{domainname}bus/{domainname}bus_test.go`
   - Create API tests in `api/services/sales/tests/{domainname}api/`

## Database Schema

Add schema definition in `business/sdk/migrate/sql/migrate.sql` with proper versioning.

## Integration with Other Domains

Use the delegate pattern for cross-domain communication:

1. **Register event handlers**:

   - Add to the `registerDelegateFunctions()` method in your domain's business layer
   - Define proper actions and parameters in `event.go`

2. **Fire events**:
   - Use `b.delegate.Call()` to notify other domains of changes

## General Best Practices

1. Use strong types for business domains (`name.Name`, `money.Money`, etc.)
2. Follow the error handling patterns (wrap errors with context)
3. Use the established middleware for authentication and authorization
4. Add proper tracing with `otel.AddSpan`
5. Validate all inputs at the application layer
6. Use pointers for optional fields in update structures

This quick reference provides the skeleton for creating new applications. Refer to existing implementations like `userbus`, `productbus`, or `homebus` for complete examples.

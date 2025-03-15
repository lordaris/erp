## 2. Setting Up a New Service

Creating a new service in our architectural framework requires careful planning and adherence to established patterns. This chapter will guide you through the process of setting up a new service from scratch, explaining each step and component in detail.

### 2.1 Planning Your Service

Before writing any code, it's important to clearly define what your service will do and how it fits into the overall system. Consider the following questions:

1. What domain concept does your service represent? (e.g., products, orders, inventory)
2. What operations will it support? (e.g., create, update, delete, query)
3. What relationships does it have with other domains?
4. What data will it need to store and retrieve?
5. What business rules must it enforce?

Taking time to answer these questions will help ensure that your service has clear boundaries and responsibilities, following the principles of Domain-Driven Design.

### 2.2 Creating the Directory Structure

Once you've defined your service's purpose, you need to create the appropriate directory structure. Assuming we're creating a service for managing "widgets," you would create these directories and files:

```
api/
  services/
    widget/
      main.go                  # Service entry point
      build/                   # Build artifacts
      tests/                   # Integration tests
app/
  domain/
    widgetapp/
      widgetapp.go             # HTTP handlers
      model.go                 # API models
      route.go                 # Route definitions
      filter.go                # Query filter parsing
      order.go                 # Sort order mapping
business/
  domain/
    widgetbus/
      widgetbus.go             # Business logic
      model.go                 # Domain models
      filter.go                # Query filter definitions
      order.go                 # Sort order definitions
      widgetbus_test.go        # Business logic tests
      stores/
        widgetdb/
          widgetdb.go          # Database operations
          model.go             # Database models
          filter.go            # SQL filter construction
          order.go             # SQL order construction
```

This structure ensures that your service follows the same pattern as existing services, making it easier for other developers to understand and maintain.

### 2.3 Implementing Domain Models

The first step in implementing your service is defining your domain models in `business/domain/widgetbus/model.go`. These models represent the core concepts of your domain and should be independent of any infrastructure concerns.

Here's an example of how you might define widget domain models:

```go
package widgetbus

import (
    "time"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/business/types/name"
    "github.com/yourorg/yourapp/business/types/category"
)

// Widget represents an individual widget in the system.
type Widget struct {
    ID          uuid.UUID
    UserID      uuid.UUID
    Name        name.Name
    Category    category.Category
    Description string
    IsActive    bool
    CreatedAt time.Time
    UpdatedAt time.Time
}

// NewWidget is what we require from clients when adding a Widget.
type NewWidget struct {
    UserID      uuid.UUID
    Name        name.Name
    Category    category.Category
    Description string
    IsActive    bool
}

// UpdateWidget defines what information may be provided to modify an
// existing Widget. All fields are optional so clients can send just the
// fields they want changed. It uses pointer fields so we can differentiate
// between a field that was not provided and a field that was provided as
// explicitly blank.
type UpdateWidget struct {
    Name        *name.Name
    Category    *category.Category
    Description *string
    IsActive    *bool
}
```

Notice several important patterns here:

1. **Core Entity**: The `Widget` struct represents the complete entity with all its attributes.
2. **Creation Model**: The `NewWidget` struct defines what's required to create a new widget, omitting system-managed fields like ID and timestamps.
3. **Update Model**: The `UpdateWidget` struct uses pointer fields to allow partial updates.
4. **Value Types**: We use domain-specific types like `name.Name` instead of primitive types for better validation and semantic clarity.

### 2.4 Defining Query Filters

Next, implement your query filters in `business/domain/widgetbus/filter.go`. Filters define the criteria that can be used to search for widgets:

```go
package widgetbus

import (
    "time"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/business/types/name"
    "github.com/yourorg/yourapp/business/types/category"
)

// QueryFilter holds the available fields a query can be filtered on.
// We use pointer semantics to distinguish between a field being empty vs. not provided.
type QueryFilter struct {
    ID           *uuid.UUID
    UserID       *uuid.UUID
    Name         *name.Name
    Category     *category.Category
    IsActive     *bool
    CreatedAfter *time.Time
    CreatedBefore *time.Time
}
```

These filters will later be translated into database queries by the store implementation.

### 2.5 Defining Sort Orders

Define the possible sort orderings in `business/domain/widgetbus/order.go`:

```go
package widgetbus

import "github.com/yourorg/yourapp/business/sdk/order"

// DefaultOrderBy represents the default way we sort.
var DefaultOrderBy = order.NewBy(OrderByID, order.ASC)

// Set of fields that the results can be ordered by.
const (
    OrderByID        = "widget_id"
    OrderByUserID    = "user_id"
    OrderByName      = "name"
    OrderByCategory  = "category"
    OrderByCreatedAt = "date_created"
    OrderByUpdatedAt = "date_updated"
)
```

These constants define the valid fields that can be used for sorting results.

### 2.6 Implementing the Store Interface

Now, define the store interface in `business/domain/widgetbus/widgetbus.go`:

```go
package widgetbus

import (
    "context"
    "errors"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/business/sdk/order"
    "github.com/yourorg/yourapp/business/sdk/page"
    "github.com/yourorg/yourapp/business/sdk/sqldb"
)

// Set of error variables for CRUD operations.
var (
    ErrNotFound     = errors.New("widget not found")
    ErrUserDisabled = errors.New("user disabled")
    ErrInvalidInput = errors.New("input not valid")
)

// Storer interface declares the behavior this package needs to persist and
// retrieve data.
type Storer interface {
    NewWithTx(tx sqldb.CommitRollbacker) (Storer, error)
    Create(ctx context.Context, widget Widget) error
    Update(ctx context.Context, widget Widget) error
    Delete(ctx context.Context, widget Widget) error
    Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Widget, error)
    Count(ctx context.Context, filter QueryFilter) (int, error)
    QueryByID(ctx context.Context, widgetID uuid.UUID) (Widget, error)
    QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Widget, error)
}
```

This interface defines the data access operations that your business logic will require. The actual implementation will be provided by the database layer.

### 2.7 Implementing Business Logic

Next, implement the business logic for your widgets in the same `widgetbus.go` file:

```go
// Business manages the set of APIs for widget access.
type Business struct {
    log      *logger.Logger
    userBus  *userbus.Business
    delegate *delegate.Delegate
    storer   Storer
}

// NewBusiness constructs a widget business API for use.
func NewBusiness(log *logger.Logger, userBus *userbus.Business, delegate *delegate.Delegate, storer Storer) *Business {
    b := Business{
        log:      log,
        userBus:  userBus,
        delegate: delegate,
        storer:   storer,
    }

    return &b
}

// Create adds a new widget to the system.
func (b *Business) Create(ctx context.Context, nw NewWidget) (Widget, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.create")
    defer span.End()

    // Validate that the user exists and is enabled
    usr, err := b.userBus.QueryByID(ctx, nw.UserID)
    if err != nil {
        return Widget{}, fmt.Errorf("user.querybyid: %s: %w", nw.UserID, err)
    }

    if !usr.Enabled {
        return Widget{}, ErrUserDisabled
    }

    now := time.Now()

    widget := Widget{
        ID:          uuid.New(),
        UserID:      nw.UserID,
        Name:        nw.Name,
        Category:    nw.Category,
        Description: nw.Description,
        IsActive:    nw.IsActive,
        CreatedAt: now,
        UpdatedAt: now,
    }

    if err := b.storer.Create(ctx, widget); err != nil {
        return Widget{}, fmt.Errorf("create: %w", err)
    }

    return widget, nil
}

// Update modifies information about a widget.
func (b *Business) Update(ctx context.Context, widget Widget, uw UpdateWidget) (Widget, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.update")
    defer span.End()

    // Apply updates to the widget
    if uw.Name != nil {
        widget.Name = *uw.Name
    }

    if uw.Category != nil {
        widget.Category = *uw.Category
    }

    if uw.Description != nil {
        widget.Description = *uw.Description
    }

    if uw.IsActive != nil {
        widget.IsActive = *uw.IsActive
    }

    widget.UpdatedAt = time.Now()

    if err := b.storer.Update(ctx, widget); err != nil {
        return Widget{}, fmt.Errorf("update: %w", err)
    }

    return widget, nil
}

// Delete removes the specified widget.
func (b *Business) Delete(ctx context.Context, widget Widget) error {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.delete")
    defer span.End()

    if err := b.storer.Delete(ctx, widget); err != nil {
        return fmt.Errorf("delete: %w", err)
    }

    return nil
}

// Query retrieves a list of existing widgets.
func (b *Business) Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Widget, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.query")
    defer span.End()

    widgets, err := b.storer.Query(ctx, filter, orderBy, page)
    if err != nil {
        return nil, fmt.Errorf("query: %w", err)
    }

    return widgets, nil
}

// Count returns the total number of widgets.
func (b *Business) Count(ctx context.Context, filter QueryFilter) (int, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.count")
    defer span.End()

    return b.storer.Count(ctx, filter)
}

// QueryByID finds the widget by the specified ID.
func (b *Business) QueryByID(ctx context.Context, widgetID uuid.UUID) (Widget, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.querybyid")
    defer span.End()

    widget, err := b.storer.QueryByID(ctx, widgetID)
    if err != nil {
        return Widget{}, fmt.Errorf("query: widgetID[%s]: %w", widgetID, err)
    }

    return widget, nil
}

// QueryByUserID finds the widgets by a specified User ID.
func (b *Business) QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Widget, error) {
    ctx, span := otel.AddSpan(ctx, "business.widgetbus.querybyuserid")
    defer span.End()

    widgets, err := b.storer.QueryByUserID(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("query: %w", err)
    }

    return widgets, nil
}
```

Note the important patterns here:

1. **Constructor Injection**: Dependencies are passed via the constructor, making them explicit and testable.
2. **Error Wrapping**: Errors are wrapped with context at each layer boundary.
3. **Tracing**: OpenTelemetry spans are added to track operation performance.
4. **Business Rules**: Domain rules (like checking if a user is enabled) are enforced here.
5. **Transaction Boundaries**: The business layer determines transaction boundaries but delegates actual persistence to the store.

### 2.8 Implementing Database Models

Next, implement your database models in `business/domain/widgetbus/stores/widgetdb/model.go`:

```go
package widgetdb

import (
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/types/name"
    "github.com/yourorg/yourapp/business/types/category"
)

// widget represents a widget in the database.
type widget struct {
    ID          uuid.UUID `db:"widget_id"`
    UserID      uuid.UUID `db:"user_id"`
    Name        string    `db:"name"`
    Category    string    `db:"category"`
    Description string    `db:"description"`
    IsActive    bool      `db:"is_active"`
    CreatedAt time.Time `db:"date_created"`
    UpdatedAt time.Time `db:"date_updated"`
}

// toDBWidget converts a business Widget to a database widget.
func toDBWidget(bus widgetbus.Widget) widget {
    db := widget{
        ID:          bus.ID,
        UserID:      bus.UserID,
        Name:        bus.Name.String(),
        Category:    bus.Category.String(),
        Description: bus.Description,
        IsActive:    bus.IsActive,
        CreatedAt: bus.CreatedAt.UTC(),
        UpdatedAt: bus.UpdatedAt.UTC(),
    }

    return db
}

// toBusWidget converts a database widget to a business Widget.
func toBusWidget(db widget) (widgetbus.Widget, error) {
    n, err := name.Parse(db.Name)
    if err != nil {
        return widgetbus.Widget{}, fmt.Errorf("parse name: %w", err)
    }

    cat, err := category.Parse(db.Category)
    if err != nil {
        return widgetbus.Widget{}, fmt.Errorf("parse category: %w", err)
    }

    bus := widgetbus.Widget{
        ID:          db.ID,
        UserID:      db.UserID,
        Name:        n,
        Category:    cat,
        Description: db.Description,
        IsActive:    db.IsActive,
        CreatedAt: db.CreatedAt.In(time.Local),
        UpdatedAt: db.UpdatedAt.In(time.Local),
    }

    return bus, nil
}

// toBusWidgets converts a slice of database widgets to business Widgets.
func toBusWidgets(dbs []widget) ([]widgetbus.Widget, error) {
    widgets := make([]widgetbus.Widget, len(dbs))

    for i, db := range dbs {
        var err error
        widgets[i], err = toBusWidget(db)
        if err != nil {
            return nil, fmt.Errorf("converting widget at index %d: %w", i, err)
        }
    }

    return widgets, nil
}
```

These functions handle the mapping between domain models and database models. Note how validation happens during the conversion from database to domain models, ensuring that invalid data cannot enter the domain layer.

### 2.9 Implementing Database Operations

Now, implement the database operations in `business/domain/widgetbus/stores/widgetdb/widgetdb.go`:

```go
package widgetdb

import (
    "bytes"
    "context"
    "errors"
    "fmt"

    "github.com/google/uuid"
    "github.com/jmoiron/sqlx"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/sdk/order"
    "github.com/yourorg/yourapp/business/sdk/page"
    "github.com/yourorg/yourapp/business/sdk/sqldb"
    "github.com/yourorg/yourapp/foundation/logger"
)

// Store manages the set of APIs for widget database access.
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
func (s *Store) NewWithTx(tx sqldb.CommitRollbacker) (widgetbus.Storer, error) {
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

// Create adds a Widget to the sqldb. It returns the created Widget with
// fields like ID and CreatedAt populated.
func (s *Store) Create(ctx context.Context, widget widgetbus.Widget) error {
    const q = `
    INSERT INTO widgets
        (widget_id, user_id, name, category, description, is_active, date_created, date_updated)
    VALUES
        (:widget_id, :user_id, :name, :category, :description, :is_active, :date_created, :date_updated)`

    if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBWidget(widget)); err != nil {
        return fmt.Errorf("namedexeccontext: %w", err)
    }

    return nil
}

// Update modifies data about a widget. It will error if the specified ID is
// invalid or does not reference an existing widget.
func (s *Store) Update(ctx context.Context, widget widgetbus.Widget) error {
    const q = `
    UPDATE
        widgets
    SET
        "name" = :name,
        "category" = :category,
        "description" = :description,
        "is_active" = :is_active,
        "date_updated" = :date_updated
    WHERE
        widget_id = :widget_id`

    if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBWidget(widget)); err != nil {
        return fmt.Errorf("namedexeccontext: %w", err)
    }

    return nil
}

// Delete removes the widget identified by a given ID.
func (s *Store) Delete(ctx context.Context, widget widgetbus.Widget) error {
    data := struct {
        ID string `db:"widget_id"`
    }{
        ID: widget.ID.String(),
    }

    const q = `
    DELETE FROM
        widgets
    WHERE
        widget_id = :widget_id`

    if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, data); err != nil {
        return fmt.Errorf("namedexeccontext: %w", err)
    }

    return nil
}

// Query gets all Widgets from the database.
func (s *Store) Query(ctx context.Context, filter widgetbus.QueryFilter, orderBy order.By, page page.Page) ([]widgetbus.Widget, error) {
    data := map[string]any{
        "offset":        (page.Number() - 1) * page.RowsPerPage(),
        "rows_per_page": page.RowsPerPage(),
    }

    const q = `
    SELECT
        widget_id, user_id, name, category, description, is_active, date_created, date_updated
    FROM
        widgets`

    buf := bytes.NewBufferString(q)
    s.applyFilter(filter, data, buf)

    orderByClause, err := orderByClause(orderBy)
    if err != nil {
        return nil, err
    }

    buf.WriteString(orderByClause)
    buf.WriteString(" OFFSET :offset ROWS FETCH NEXT :rows_per_page ROWS ONLY")

    var dbWidgets []widget
    if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, buf.String(), data, &dbWidgets); err != nil {
        return nil, fmt.Errorf("namedqueryslice: %w", err)
    }

    return toBusWidgets(dbWidgets)
}

// Count returns the total number of widgets in the DB.
func (s *Store) Count(ctx context.Context, filter widgetbus.QueryFilter) (int, error) {
    data := map[string]any{}

    const q = `
    SELECT
        count(1)
    FROM
        widgets`

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

// QueryByID finds the widget identified by a given ID.
func (s *Store) QueryByID(ctx context.Context, widgetID uuid.UUID) (widgetbus.Widget, error) {
    data := struct {
        ID string `db:"widget_id"`
    }{
        ID: widgetID.String(),
    }

    const q = `
    SELECT
        widget_id, user_id, name, category, description, is_active, date_created, date_updated
    FROM
        widgets
    WHERE
        widget_id = :widget_id`

    var dbWidget widget
    if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, q, data, &dbWidget); err != nil {
        if errors.Is(err, sqldb.ErrDBNotFound) {
            return widgetbus.Widget{}, fmt.Errorf("db: %w", widgetbus.ErrNotFound)
        }
        return widgetbus.Widget{}, fmt.Errorf("db: %w", err)
    }

    return toBusWidget(dbWidget)
}

// QueryByUserID finds the widgets identified by a given User ID.
func (s *Store) QueryByUserID(ctx context.Context, userID uuid.UUID) ([]widgetbus.Widget, error) {
    data := struct {
        ID string `db:"user_id"`
    }{
        ID: userID.String(),
    }

    const q = `
    SELECT
        widget_id, user_id, name, category, description, is_active, date_created, date_updated
    FROM
        widgets
    WHERE
        user_id = :user_id`

    var dbWidgets []widget
    if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, q, data, &dbWidgets); err != nil {
        return nil, fmt.Errorf("db: %w", err)
    }

    return toBusWidgets(dbWidgets)
}
```

This implementation provides the actual database operations, using the `sqldb` package to handle SQL execution. Note how it translates between domain models and database models using the functions we defined earlier.

### 2.10 Implementing Filter and Order

Now, implement the database filter in `business/domain/widgetbus/stores/widgetdb/filter.go`:

```go
package widgetdb

import (
    "bytes"
    "fmt"
    "strings"

    "github.com/yourorg/yourapp/business/domain/widgetbus"
)

func (s *Store) applyFilter(filter widgetbus.QueryFilter, data map[string]any, buf *bytes.Buffer) {
    var wc []string

    if filter.ID != nil {
        data["widget_id"] = *filter.ID
        wc = append(wc, "widget_id = :widget_id")
    }

    if filter.UserID != nil {
        data["user_id"] = *filter.UserID
        wc = append(wc, "user_id = :user_id")
    }

    if filter.Name != nil {
        data["name"] = fmt.Sprintf("%%%s%%", *filter.Name)
        wc = append(wc, "name LIKE :name")
    }

    if filter.Category != nil {
        data["category"] = (*filter.Category).String()
        wc = append(wc, "category = :category")
    }

    if filter.IsActive != nil {
        data["is_active"] = *filter.IsActive
        wc = append(wc, "is_active = :is_active")
    }

    if filter.CreatedAfter != nil {
        data["created_after"] = *filter.CreatedAfter
        wc = append(wc, "date_created >= :created_after")
    }

    if filter.CreatedBefore != nil {
        data["created_before"] = *filter.CreatedBefore
        wc = append(wc, "date_created <= :created_before")
    }

    if len(wc) > 0 {
        buf.WriteString(" WHERE ")
        buf.WriteString(strings.Join(wc, " AND "))
    }
}
```

And implement the order by clause in `business/domain/widgetbus/stores/widgetdb/order.go`:

```go
package widgetdb

import (
    "fmt"

    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/sdk/order"
)

var orderByFields = map[string]string{
    widgetbus.OrderByID:           "widget_id",
    widgetbus.OrderByUserID:       "user_id",
    widgetbus.OrderByName:         "name",
    widgetbus.OrderByCategory:     "category",
    widgetbus.OrderByCreatedAt:  "date_created",
    widgetbus.OrderByUpdatedAt:  "date_updated",
}

func orderByClause(orderBy order.By) (string, error) {
    by, exists := orderByFields[orderBy.Field]
    if !exists {
        return "", fmt.Errorf("field %q does not exist", orderBy.Field)
    }

    return " ORDER BY " + by + " " + orderBy.Direction, nil
}
```

These implementations translate domain filters and sort orders into SQL clauses.

### 2.11 Adding Database Migration Scripts

Now, add a migration script to create your widgets table. Add the following to `business/sdk/migrate/sql/migrate.sql`:

```sql
-- Version: X.XX
-- Description: Create table widgets
CREATE TABLE widgets (
    widget_id      UUID        PRIMARY KEY,
    user_id        UUID        NOT NULL,
    name           VARCHAR(100) NOT NULL,
    category       VARCHAR(100) NOT NULL,
    description    TEXT,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    date_created   TIMESTAMP   NOT NULL,
    date_updated   TIMESTAMP   NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX widgets_name_idx ON widgets(name);
CREATE INDEX widgets_category_idx ON widgets(category);
CREATE INDEX widgets_user_id_idx ON widgets(user_id);
```

This script creates the database table and necessary indexes for your widget domain.

### 2.12 Implementing API Models

Now that we have our business layer implemented, let's create the API layer. First, define your API models in `app/domain/widgetapp/model.go`:

```go
package widgetapp

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/app/sdk/errs"
    "github.com/yourorg/yourapp/app/sdk/mid"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/types/name"
    "github.com/yourorg/yourapp/business/types/category"
)

// Widget represents information about an individual widget.
type Widget struct {
    ID          string `json:"id"`
    UserID      string `json:"userID"`
    Name        string `json:"name"`
    Category    string `json:"category"`
    Description string `json:"description"`
    IsActive    bool   `json:"isActive"`
    CreatedAt string `json:"CreatedAt"`
    UpdatedAt string `json:"UpdatedAt"`
}

// Encode implements the encoder interface.
func (app Widget) Encode() ([]byte, string, error) {
    data, err := json.Marshal(app)
    return data, "application/json", err
}

func toAppWidget(widget widgetbus.Widget) Widget {
    return Widget{
        ID:          widget.ID.String(),
        UserID:      widget.UserID.String(),
        Name:        widget.Name.String(),
        Category:    widget.Category.String(),
        Description: widget.Description,
        IsActive:    widget.IsActive,
        CreatedAt: widget.CreatedAt.Format(time.RFC3339),
        UpdatedAt: widget.UpdatedAt.Format(time.RFC3339),
    }
}

func toAppWidgets(widgets []widgetbus.Widget) []Widget {
    app := make([]Widget, len(widgets))
    for i, widget := range widgets {
        app[i] = toAppWidget(widget)
    }

    return app
}

// =============================================================================

// NewWidget defines the data needed to add a new widget.
type NewWidget struct {
    Name        string `json:"name" validate:"required"`
    Category    string `json:"category" validate:"required"`
    Description string `json:"description"`
    IsActive    bool   `json:"isActive"`
}

// Decode implements the decoder interface.
func (app *NewWidget) Decode(data []byte) error {
    return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app NewWidget) Validate() error {
    if err := errs.Check(app); err != nil {
        return fmt.Errorf("validate: %w", err)
    }

    return nil
}

func toBusNewWidget(ctx context.Context, app NewWidget) (widgetbus.NewWidget, error) {
    userID, err := mid.GetUserID(ctx)
    if err != nil {
        return widgetbus.NewWidget{}, fmt.Errorf("getuserid: %w", err)
    }

    n, err := name.Parse(app.Name)
    if err != nil {
        return widgetbus.NewWidget{}, fmt.Errorf("parse name: %w", err)
    }

    cat, err := category.Parse(app.Category)
    if err != nil {
        return widgetbus.NewWidget{}, fmt.Errorf("parse category: %w", err)
    }

    bus := widgetbus.NewWidget{
        UserID:      userID,
        Name:        n,
        Category:    cat,
        Description: app.Description,
        IsActive:    app.IsActive,
    }

    return bus, nil
}

// =============================================================================

// UpdateWidget defines the data needed to update a widget.
type UpdateWidget struct {
    Name        *string `json:"name"`
    Category    *string `json:"category"`
    Description *string `json:"description"`
    IsActive    *bool   `json:"isActive"`
}

// Decode implements the decoder interface.
func (app *UpdateWidget) Decode(data []byte) error {
    return json.Unmarshal(data, app)
}

// Validate checks the data in the model is considered clean.
func (app UpdateWidget) Validate() error {
    if err := errs.Check(app); err != nil {
        return fmt.Errorf("validate: %w", err)
    }

    return nil
}

func toBusUpdateWidget(app UpdateWidget) (widgetbus.UpdateWidget, error) {
    var n *name.Name
    if app.Name != nil {
        nm, err := name.Parse(*app.Name)
        if err != nil {
            return widgetbus.UpdateWidget{}, fmt.Errorf("parse name: %w", err)
        }
        n = &nm
    }

    var c *category.Category
    if app.Category != nil {
        cat, err := category.Parse(*app.Category)
        if err != nil {
            return widgetbus.UpdateWidget{}, fmt.Errorf("parse category: %w", err)
        }
        c = &cat
    }

    bus := widgetbus.UpdateWidget{
        Name:        n,
        Category:    c,
        Description: app.Description,
        IsActive:    app.IsActive,
    }

    return bus, nil
}
```

These models define the JSON structures that will be used to communicate with API clients. Note how they include validation rules and conversion functions to transform between API and business models.

### 2.13 Implementing API Filter and Order

Now, implement the API filter in `app/domain/widgetapp/filter.go`:

```go
package widgetapp

import (
    "net/http"
    "strconv"
    "time"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/app/sdk/errs"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/types/name"
    "github.com/yourorg/yourapp/business/types/category"
)

type queryParams struct {
    Page          string
    Rows          string
    OrderBy       string
    ID            string
    UserID        string
    Name          string
    Category      string
    IsActive      string
    CreatedAfter  string
    CreatedBefore string
}

func parseQueryParams(r *http.Request) queryParams {
    values := r.URL.Query()

    filter := queryParams{
        Page:          values.Get("page"),
        Rows:          values.Get("rows"),
        OrderBy:       values.Get("orderBy"),
        ID:            values.Get("widget_id"),
        UserID:        values.Get("user_id"),
        Name:          values.Get("name"),
        Category:      values.Get("category"),
        IsActive:      values.Get("is_active"),
        CreatedAfter:  values.Get("created_after"),
        CreatedBefore: values.Get("created_before"),
    }

    return filter
}

func parseFilter(qp queryParams) (widgetbus.QueryFilter, error) {
    var fieldErrors errs.FieldErrors
    var filter widgetbus.QueryFilter

    if qp.ID != "" {
        id, err := uuid.Parse(qp.ID)
        switch err {
        case nil:
            filter.ID = &id
        default:
            fieldErrors.Add("widget_id", err)
        }
    }

    if qp.UserID != "" {
        id, err := uuid.Parse(qp.UserID)
        switch err {
        case nil:
            filter.UserID = &id
        default:
            fieldErrors.Add("user_id", err)
        }
    }

    if qp.Name != "" {
        n, err := name.Parse(qp.Name)
        switch err {
        case nil:
            filter.Name = &n
        default:
            fieldErrors.Add("name", err)
        }
    }

    if qp.Category != "" {
        cat, err := category.Parse(qp.Category)
        switch err {
        case nil:
            filter.Category = &cat
        default:
            fieldErrors.Add("category", err)
        }
    }

    if qp.IsActive != "" {
        active, err := strconv.ParseBool(qp.IsActive)
        switch err {
        case nil:
            filter.IsActive = &active
        default:
            fieldErrors.Add("is_active", err)
        }
    }

    if qp.CreatedAfter != "" {
        createdAfter, err := time.Parse(time.RFC3339, qp.CreatedAfter)
        switch err {
        case nil:
            filter.CreatedAfter = &createdAfter
        default:
            fieldErrors.Add("created_after", err)
        }
    }

    if qp.CreatedBefore != "" {
        createdBefore, err := time.Parse(time.RFC3339, qp.CreatedBefore)
        switch err {
        case nil:
            filter.CreatedBefore = &createdBefore
        default:
            fieldErrors.Add("created_before", err)
        }
    }

    if fieldErrors != nil {
        return widgetbus.QueryFilter{}, fieldErrors.ToError()
    }

    return filter, nil
}
```

And implement the API order mapping in `app/domain/widgetapp/order.go`:

```go
package widgetapp

import (
    "github.com/yourorg/yourapp/business/domain/widgetbus"
)

var orderByFields = map[string]string{
    "widget_id":     widgetbus.OrderByID,
    "user_id":       widgetbus.OrderByUserID,
    "name":          widgetbus.OrderByName,
    "category":      widgetbus.OrderByCategory,
    "date_created":  widgetbus.OrderByCreatedAt,
    "date_updated":  widgetbus.OrderByUpdatedAt,
}
```

These implementations handle the parsing and validation of query parameters for filtering and sorting.

### 2.14 Implementing HTTP Handlers

Next, implement your HTTP handlers in `app/domain/widgetapp/widgetapp.go`:

```go
package widgetapp

import (
    "context"
    "net/http"

    "github.com/yourorg/yourapp/app/sdk/errs"
    "github.com/yourorg/yourapp/app/sdk/mid"
    "github.com/yourorg/yourapp/app/sdk/query"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/sdk/order"
    "github.com/yourorg/yourapp/business/sdk/page"
    "github.com/yourorg/yourapp/foundation/web"
)

type app struct {
    widgetBus *widgetbus.Business
}

func newApp(widgetBus *widgetbus.Business) *app {
    return &app{
        widgetBus: widgetBus,
    }
}

// create adds a new widget to the system.
func (a *app) create(ctx context.Context, r *http.Request) web.Encoder {
    var app NewWidget
    if err := web.Decode(r, &app); err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    nw, err := toBusNewWidget(ctx, app)
    if err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    widget, err := a.widgetBus.Create(ctx, nw)
    if err != nil {
        return errs.Newf(errs.Internal, "create: widget[%+v]: %s", app, err)
    }

    return toAppWidget(widget)
}

// update modifies data about a widget.
func (a *app) update(ctx context.Context, r *http.Request) web.Encoder {
    var app UpdateWidget
    if err := web.Decode(r, &app); err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    uw, err := toBusUpdateWidget(app)
    if err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    widget, err := mid.GetWidget(ctx)
    if err != nil {
        return errs.Newf(errs.Internal, "widget missing in context: %s", err)
    }

    updWidget, err := a.widgetBus.Update(ctx, widget, uw)
    if err != nil {
        return errs.Newf(errs.Internal, "update: widgetID[%s] uw[%+v]: %s", widget.ID, app, err)
    }

    return toAppWidget(updWidget)
}

// delete removes the widget identified by a given ID.
func (a *app) delete(ctx context.Context, _ *http.Request) web.Encoder {
    widget, err := mid.GetWidget(ctx)
    if err != nil {
        return errs.Newf(errs.Internal, "widgetID missing in context: %s", err)
    }

    if err := a.widgetBus.Delete(ctx, widget); err != nil {
        return errs.Newf(errs.Internal, "delete: widgetID[%s]: %s", widget.ID, err)
    }

    return nil
}

// query retrieves a list of existing widgets with filter capabilities.
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

    orderBy, err := order.Parse(orderByFields, qp.OrderBy, widgetbus.DefaultOrderBy)
    if err != nil {
        return errs.NewFieldErrors("order", err)
    }

    widgets, err := a.widgetBus.Query(ctx, filter, orderBy, page)
    if err != nil {
        return errs.Newf(errs.Internal, "query: %s", err)
    }

    total, err := a.widgetBus.Count(ctx, filter)
    if err != nil {
        return errs.Newf(errs.Internal, "count: %s", err)
    }

    return query.NewResult(toAppWidgets(widgets), total, page)
}

// queryByID finds the widget identified by a given ID.
func (a *app) queryByID(ctx context.Context, r *http.Request) web.Encoder {
    widget, err := mid.GetWidget(ctx)
    if err != nil {
        return errs.Newf(errs.Internal, "querybyid: %s", err)
    }

    return toAppWidget(widget)
}
```

These handlers process HTTP requests, validate input, call the appropriate business methods, and format responses. Notice how they delegate most of the actual work to the business layer, focusing primarily on HTTP-specific concerns.

### 2.15 Defining Routes

Finally, define your API routes in `app/domain/widgetapp/route.go`:

```go
package widgetapp

import (
    "net/http"

    "github.com/yourorg/yourapp/app/sdk/auth"
    "github.com/yourorg/yourapp/app/sdk/authclient"
    "github.com/yourorg/yourapp/app/sdk/mid"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/foundation/logger"
    "github.com/yourorg/yourapp/foundation/web"
)

// Config contains all the mandatory systems required by handlers.
type Config struct {
    Log       *logger.Logger
    WidgetBus *widgetbus.Business
    AuthClient *authclient.Client
}

// Routes adds specific routes for this group.
func Routes(app *web.App, cfg Config) {
    const version = "v1"

    authen := mid.Authenticate(cfg.AuthClient)
    ruleAny := mid.Authorize(cfg.AuthClient, auth.RuleAny)
    ruleUserOnly := mid.Authorize(cfg.AuthClient, auth.RuleUserOnly)
    ruleAuthorizeWidget := mid.AuthorizeWidget(cfg.AuthClient, cfg.WidgetBus)

    api := newApp(cfg.WidgetBus)

    app.HandlerFunc(http.MethodGet, version, "/widgets", api.query, authen, ruleAny)
    app.HandlerFunc(http.MethodGet, version, "/widgets/{widget_id}", api.queryByID, authen, ruleAuthorizeWidget)
    app.HandlerFunc(http.MethodPost, version, "/widgets", api.create, authen, ruleUserOnly)
    app.HandlerFunc(http.MethodPut, version, "/widgets/{widget_id}", api.update, authen, ruleAuthorizeWidget)
    app.HandlerFunc(http.MethodDelete, version, "/widgets/{widget_id}", api.delete, authen, ruleAuthorizeWidget)
}
```

This file defines the routes for your widget API, specifying the HTTP method, URL path, handler function, and any middleware requirements.

### 2.16 Implementing Authorization Middleware

You'll need to create a new authorization middleware for widgets. Create a new file `app/sdk/mid/widget.go`:

```go
package mid

import (
    "context"
    "errors"
    "fmt"
    "net/http"

    "github.com/google/uuid"
    "github.com/yourorg/yourapp/app/sdk/auth"
    "github.com/yourorg/yourapp/app/sdk/authclient"
    "github.com/yourorg/yourapp/app/sdk/errs"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/foundation/web"
)

// contextKey represents the type of value for the context key.
type contextKey int

// key is used to store/retrieve a Widget value from a context.
const widgetKey contextKey = 3

// GetWidget returns the widget from the context.
func GetWidget(ctx context.Context) (widgetbus.Widget, error) {
    v, ok := ctx.Value(widgetKey).(widgetbus.Widget)
    if !ok {
        return widgetbus.Widget{}, errors.New("widget value missing from context")
    }
    return v, nil
}

// AuthorizeWidget executes the specified authorization rule against the widget
// in the request.
func AuthorizeWidget(client *authclient.Client, widgetBus *widgetbus.Business) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Extract widget ID from the request.
            widgetID := web.Param(r, "widget_id")
            if widgetID == "" {
                return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument, fmt.Errorf("missing widget_id"))
            }

            id, err := uuid.Parse(widgetID)
            if err != nil {
                return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument, fmt.Errorf("invalid widget_id: %w", err))
            }

            // Retrieve the widget from the database.
            widget, err := widgetBus.QueryByID(ctx, id)
            if err != nil {
                switch {
                case errors.Is(err, widgetbus.ErrNotFound):
                    return errs.NewWithStatus(http.StatusNotFound, errs.NotFound, fmt.Errorf("widget not found: %w", err))
                default:
                    return errs.New(errs.Internal, fmt.Errorf("widget[%s]: %w", id, err))
                }
            }

            // Retrieve the claims from the request context.
            claims, err := auth.GetClaims(ctx)
            if err != nil {
                return err
            }

            // If you are an admin, you are authorized.
            if claims.HasRole(auth.RoleAdmin) {
                ctx = context.WithValue(ctx, widgetKey, widget)
                return handler(ctx, w, r)
            }

            // If you are the owner, you are authorized.
            if widget.UserID.String() == claims.Subject {
                ctx = context.WithValue(ctx, widgetKey, widget)
                return handler(ctx, w, r)
            }

            return errs.NewWithStatus(http.StatusForbidden, errs.PermissionDenied, fmt.Errorf("unauthorized access to widget: %s", id))
        }

        return h
    }

    return m
}
```

This middleware retrieves a widget from the database and checks if the user is authorized to access it, based on their roles and ownership.

### 2.17 Creating the Service Entry Point

Finally, create the service entry point in `api/services/widget/main.go`:

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "syscall"
    "time"

    "github.com/ardanlabs/conf/v3"
    "github.com/jmoiron/sqlx"
    "github.com/yourorg/yourapp/app/domain/checkapp"
    "github.com/yourorg/yourapp/app/domain/widgetapp"
    "github.com/yourorg/yourapp/app/sdk/authclient"
    "github.com/yourorg/yourapp/app/sdk/debug"
    "github.com/yourorg/yourapp/app/sdk/mid"
    "github.com/yourorg/yourapp/business/domain/widgetbus"
    "github.com/yourorg/yourapp/business/domain/widgetbus/stores/widgetdb"
    "github.com/yourorg/yourapp/business/sdk/delegate"
    "github.com/yourorg/yourapp/business/sdk/migrate"
    "github.com/yourorg/yourapp/business/sdk/sqldb"
    "github.com/yourorg/yourapp/foundation/logger"
    "github.com/yourorg/yourapp/foundation/otel"
    "github.com/yourorg/yourapp/foundation/web"
)

// build is the git version of this program. It is set using build flags in the
// makefile.
var build = "develop"

func main() {
    // Construct the application logger.
    log := logger.New()
    defer log.Sync()

    // Perform the startup and shutdown sequence.
    if err := run(log); err != nil {
        log.Errorw("startup", "ERROR", err)
        log.Sync()
        os.Exit(1)
    }
}

func run(log *logger.Logger) error {
    ctx := context.Background()

    // =========================================================================
    // Configuration

    cfg := struct {
        conf.Version
        Web struct {
            ReadTimeout     time.Duration `conf:"default:5s"`
            WriteTimeout    time.Duration `conf:"default:10s"`
            IdleTimeout     time.Duration `conf:"default:120s"`
            ShutdownTimeout time.Duration `conf:"default:20s"`
            APIHost         string        `conf:"default:0.0.0.0:3000"`
            DebugHost       string        `conf:"default:0.0.0.0:4000"`
        }
        Auth struct {
            KeysFolder string `conf:"default:zarf/keys/"`
            ActiveKID  string `conf:"default:54bb2165-71e1-41a6-af3e-7da4a0e1e2c1"`
        }
        DB struct {
            User         string `conf:"default:postgres"`
            Password     string `conf:"default:postgres,mask"`
            Host         string `conf:"default:localhost"`
            Name         string `conf:"default:postgres"`
            MaxIdleConns int    `conf:"default:0"`
            MaxOpenConns int    `conf:"default:0"`
            DisableTLS   bool   `conf:"default:true"`
        }
        Otel struct {
            ExporterEndpoint string        `conf:"default:localhost:4317"`
            ServiceName      string        `conf:"default:widget-api"`
            ServiceVersion   string        `conf:"default:develop"`
            Probability      float64       `conf:"default:0.01"`
            Timeout          time.Duration `conf:"default:30s"`
        }
    }{
        Version: conf.Version{
            Build: build,
            Desc:  "copyright information here",
        },
    }

    const prefix = "WIDGET"
    help, err := conf.Parse(prefix, &cfg)
    if err != nil {
        if errors.Is(err, conf.ErrHelpWanted) {
            fmt.Println(help)
            return nil
        }
        return fmt.Errorf("parsing config: %w", err)
    }

    // =========================================================================
    // App Starting

    log.Infow("starting service", "version", build)
    defer log.Infow("shutdown complete")

    log.Infow("startup", "config", conf.MaskString(conf.String(cfg)))

    // =========================================================================
    // Database Support

    log.Infow("startup", "status", "initializing database support", "host", cfg.DB.Host)

    db, err := sqldb.Open(sqldb.Config{
        User:         cfg.DB.User,
        Password:     cfg.DB.Password,
        Host:         cfg.DB.Host,
        Name:         cfg.DB.Name,
        MaxIdleConns: cfg.DB.MaxIdleConns,
        MaxOpenConns: cfg.DB.MaxOpenConns,
        DisableTLS:   cfg.DB.DisableTLS,
    })
    if err != nil {
        return fmt.Errorf("connecting to db: %w", err)
    }
    defer func() {
        log.Infow("shutdown", "status", "stopping database support", "host", cfg.DB.Host)
        db.Close()
    }()

    // =========================================================================
    // Migrations

    log.Infow("startup", "status", "initializing migrations support", "host", cfg.DB.Host)

    if err := migrate.Migrate(ctx, db); err != nil {
        return fmt.Errorf("migrating db: %w", err)
    }

    // =========================================================================
    // OTel Support

    log.Infow("startup", "status", "initializing OTel support")

    otelSdk, otelExport, err := otel.Init(ctx, otel.Config{
        Exporter:    cfg.Otel.ExporterEndpoint,
        ServiceName: cfg.Otel.ServiceName,
        Version:     cfg.Otel.ServiceVersion,
        Probability: cfg.Otel.Probability,
        Timeout:     cfg.Otel.Timeout,
    })
    if err != nil {
        return fmt.Errorf("starting otel sdk: %w", err)
    }
    defer func() {
        log.Infow("shutdown", "status", "stopping otel sdk", "host", cfg.Otel.ExporterEndpoint)
        if err := otelExport.Shutdown(ctx); err != nil {
            log.Errorw("shutdown", "ERROR", err)
        }
        otelSdk.Shutdown(ctx)
    }()

    // =========================================================================
    // Authentication Support

    log.Infow("startup", "status", "initializing auth support")

    authClient, err := authclient.New(cfg.Auth.KeysFolder, cfg.Auth.ActiveKID)
    if err != nil {
        return fmt.Errorf("constructing auth: %w", err)
    }

    // =========================================================================
    // Business Layer Support

    log.Infow("startup", "status", "initializing business layer support")

    dlg := delegate.New(log)

    widgetStorer := widgetdb.NewStore(log, db)
    widgetBus := widgetbus.NewBusiness(log, nil, dlg, widgetStorer)

    // =========================================================================
    // Start API Service

    log.Infow("startup", "status", "initializing API support")

    // Make a channel to listen for an interrupt or terminate signal from the OS.
    // Use a buffered channel because the signal package requires it.
    shutdown := make(chan os.Signal, 1)
    signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

    // Construct the mux for the API calls.
    mux := web.NewMux(mid.Stealth())

    // Construct a server to service the requests.
    api := http.Server{
        Addr:         cfg.Web.APIHost,
        Handler:      mux,
        ReadTimeout:  cfg.Web.ReadTimeout,
        WriteTimeout: cfg.Web.WriteTimeout,
        IdleTimeout:  cfg.Web.IdleTimeout,
        ErrorLog:     logger.NewStdLogger(log, "SERVER"),
    }

    // Register the handlers to all the routes required for the service.
    checkapp.Routes(mux, checkapp.Config{
        Log: log,
        DB:  db,
    })

    widgetapp.Routes(mux, widgetapp.Config{
        Log:        log,
        WidgetBus:  widgetBus,
        AuthClient: authClient,
    })

    // Start the service listening for api requests.
    go func() {
        log.Infow("startup", "status", "api router started", "host", api.Addr)
        if err := api.ListenAndServe(); err != nil {
            log.Errorw("shutdown", "status", "api router closed", "host", api.Addr, "ERROR", err)
        }
    }()

    // =========================================================================
    // Start Debug Service

    log.Infow("startup", "status", "initializing debug support")

    // Start the service listening for debug requests.
    go func() {
        log.Infow("startup", "status", "debug router started", "host", cfg.Web.DebugHost)

        d := debug.New(log)
        d.GoroutineDump(log)

        if err := http.ListenAndServe(cfg.Web.DebugHost, d.MuxDebug()); err != nil {
            log.Errorw("shutdown", "status", "debug router closed", "host", cfg.Web.DebugHost, "ERROR", err)
        }
    }()

    // =========================================================================
    // Shutdown

    // Block until a signal is received.
    <-shutdown

    // Give outstanding requests a deadline for completion.
    ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
    defer cancel()

    // Asking listener to shut down and shed load.
    log.Infow("shutdown", "status", "shutdown started")
    if err := api.Shutdown(ctx); err != nil {
        log.Errorw("shutdown", "status", "shutdown error", "ERROR", err)
        if err := api.Close(); err != nil {
            log.Errorw("shutdown", "status", "api close error", "ERROR", err)
        }
    }

    log.Infow("shutdown", "status", "shutdown complete")

    return nil
}
```

This file configures and starts the service, connecting all the components we've defined.

### 2.18 Key Considerations and Best Practices

When setting up a new service, keep these best practices in mind:

#### Dependency Management

- Always inject dependencies through constructors
- Keep dependencies unidirectional (outer layers depend on inner layers)
- Use interfaces to define dependencies between layers
- Minimize dependencies between domains

#### Error Handling

- Define domain-specific errors as variables
- Wrap errors with context at layer boundaries
- Return meaningful error messages that include relevant IDs
- Translate domain errors to appropriate HTTP status codes

#### Validation

- Validate input at the API layer
- Use value types to enforce domain rules
- Keep validation logic consistent across the system
- Provide clear, actionable error messages

#### Testing

- Write unit tests for business logic
- Write integration tests for database operations
- Use mock implementations for testing
- Test happy paths and error cases

#### Security

- Use middleware for authentication and authorization
- Validate user permissions before performing operations
- Never trust client input
- Log security-relevant events

#### Performance

- Use database indexes for frequently queried fields
- Paginate large result sets
- Use transactions appropriately
- Add tracing for performance monitoring

### 2.19 Avoiding Common Pitfalls

Here are some common pitfalls to avoid when creating new services:

1. **Circular Dependencies**: Avoid creating circular dependencies between packages. This can lead to import cycles that won't compile.

2. **Leaking Domain Logic**: Keep business logic in the business layer, not in the application layer or database layer.

3. **Inconsistent Naming**: Follow the established naming conventions for files, types, and functions.

4. **Direct Database Access**: Always go through the store interface, never access the database directly from the business layer.

5. **Missing Error Handling**: Always check and handle errors, don't ignore them.

6. **Hardcoded Values**: Use configuration for environment-specific values.

7. **Missing Validation**: Always validate input at the API layer.

8. **Too Many Dependencies**: Keep the number of dependencies manageable by focusing on clean, focused components.

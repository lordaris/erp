## 4. Database Integration

Effective database integration is crucial for building robust, scalable services. This chapter explores how our architectural framework handles database operations, from defining models to executing queries and managing transactions.

### 4.1 Database Architecture Overview

Our system employs a layered approach to database integration that separates concerns and provides clear interfaces between components. This architecture consists of several key layers:

1. **Database Connection Management**: Handles connection pooling, configuration, and lifecycle
2. **Store Implementation**: Translates business operations into SQL queries
3. **Model Mapping**: Converts between database and business models
4. **Transaction Management**: Provides a consistent approach to handling transactions
5. **Migration Support**: Manages database schema changes

This layered approach offers several benefits:

- **Separation of Concerns**: Business logic remains independent of database details
- **Testability**: Each layer can be tested independently
- **Flexibility**: Database implementations can be changed without affecting business logic
- **Consistency**: Common database patterns are standardized across the system

Let's explore each of these components in detail.

### 4.2 Database Connection Management

Database connections are managed at the application level and provided to business components through dependency injection. The core of this management is in the `sqldb` package.

Here's how database connections are established:

```go
// sqldb.Open opens a connection to the database.
func Open(cfg Config) (*sqlx.DB, error) {
    sslMode := "require"
    if cfg.DisableTLS {
        sslMode = "disable"
    }

    q := make(url.Values)
    q.Set("sslmode", sslMode)
    q.Set("timezone", "utc")

    u := url.URL{
        Scheme:   "postgres",
        User:     url.UserPassword(cfg.User, cfg.Password),
        Host:     cfg.Host,
        Path:     cfg.Name,
        RawQuery: q.Encode(),
    }

    db, err := sqlx.Open("postgres", u.String())
    if err != nil {
        return nil, err
    }

    db.SetMaxIdleConns(cfg.MaxIdleConns)
    db.SetMaxOpenConns(cfg.MaxOpenConns)

    return db, nil
}
```

This function sets up a connection pool with the specified configuration, including SSL settings, connection limits, and timezone.

Connection health is monitored through a status check function:

```go
// StatusCheck returns nil if it can successfully talk to the database.
func StatusCheck(ctx context.Context, db *sqlx.DB) error {
    const q = `SELECT true`

    var tmp bool
    return db.QueryRowContext(ctx, q).Scan(&tmp)
}
```

These connections are typically established during service startup and provided to business components:

```go
// From a service's main function
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

// Create store implementations
widgetStorer := widgetdb.NewStore(log, db)

// Create business components with store implementations
widgetBus := widgetbus.NewBusiness(log, userBus, delegate, widgetStorer)
```

This approach ensures that database connections are properly managed and that business components have access to the database through clean interfaces.

### 4.3 Store Implementation

The store layer is responsible for translating business operations into database queries. Each domain has its own store implementation that implements the `Storer` interface defined in the business layer.

Here's a typical store implementation for a domain:

```go
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

// Create adds a Widget to the sqldb.
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
```

Notice several important patterns here:

1. **SQL Queries as Constants**: SQL queries are defined as constants, making them easy to review and update
2. **Named Parameters**: Queries use named parameters (`:widget_id`) for clarity and safety
3. **Context Propagation**: The context is passed to all database operations for cancellation and tracing
4. **Error Wrapping**: Errors are wrapped with context for better debugging
5. **Model Conversion**: Database models are converted to/from business models using helper functions

### 4.4 Query Execution Utilities

Our framework provides utility functions for common database operations to ensure consistency and proper error handling. These functions are in the `sqldb` package:

```go
// NamedExecContext is a helper function for executing named queries.
func NamedExecContext(ctx context.Context, log *logger.Logger, db namedExecer, query string, data any) error {
    q := queryString(query, data)

    ctx, span := otel.AddSpan(ctx, "database.NamedExecContext")
    span.SetAttributes(
        attribute.String("query", q),
    )
    defer span.End()

    if _, err := db.NamedExecContext(ctx, query, data); err != nil {
        return err
    }

    return nil
}

// NamedQueryStruct is a helper function for executing a named query and loading a single struct.
func NamedQueryStruct(ctx context.Context, log *logger.Logger, db namedQuerier, query string, data any, dest any) error {
    q := queryString(query, data)

    ctx, span := otel.AddSpan(ctx, "database.NamedQueryStruct")
    span.SetAttributes(
        attribute.String("query", q),
    )
    defer span.End()

    rows, err := db.NamedQueryContext(ctx, query, data)
    if err != nil {
        return err
    }
    defer rows.Close()

    if !rows.Next() {
        return ErrDBNotFound
    }

    if err := rows.StructScan(dest); err != nil {
        return err
    }

    return nil
}

// NamedQuerySlice is a helper function for executing a named query and loading a slice of structs.
func NamedQuerySlice(ctx context.Context, log *logger.Logger, db namedQuerier, query string, data any, dest any) error {
    q := queryString(query, data)

    ctx, span := otel.AddSpan(ctx, "database.NamedQuerySlice")
    span.SetAttributes(
        attribute.String("query", q),
    )
    defer span.End()

    val := reflect.ValueOf(dest)
    if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Slice {
        return errors.New("destination must be a pointer to a slice")
    }

    rows, err := db.NamedQueryContext(ctx, query, data)
    if err != nil {
        return err
    }
    defer rows.Close()

    slice := val.Elem()
    for rows.Next() {
        v := reflect.New(slice.Type().Elem()).Interface()
        if err := rows.StructScan(v); err != nil {
            return err
        }
        slice.Set(reflect.Append(slice, reflect.ValueOf(v).Elem()))
    }

    return nil
}
```

These utilities provide several benefits:

1. **Consistent Error Handling**: Errors are handled consistently across all database operations
2. **Tracing Integration**: Database operations are automatically traced for performance monitoring
3. **Type Safety**: Functions use reflection to ensure type compatibility
4. **Resource Management**: Resources like database rows are properly closed

### 4.5 Model Mapping

Database models are distinct from business models, requiring mapping functions to convert between them. This separation allows each layer to define types that meet its specific needs.

Here's an example of the model mapping functions:

```go
// Database model
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

// Business to database model conversion
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

// Database to business model conversion
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
```

Notice several important patterns in these functions:

1. **Value Type Validation**: Database to business conversion validates values through `Parse` functions
2. **Error Handling**: Validation errors are returned with context
3. **Timezone Handling**: Times are stored in UTC but returned in the local timezone
4. **Distinct Types**: Database models use primitive types, while business models use domain-specific types

These conversions ensure that data remains consistent and valid as it moves between layers.

### 4.6 Dynamic Query Construction

For more complex queries, our system builds SQL queries dynamically based on filter criteria. This approach allows for flexible and efficient querying while maintaining safety and readability.

Here's an example of dynamic query construction:

```go
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

This function builds a WHERE clause dynamically based on the filter criteria provided. It adds each condition to a slice and then joins them with AND operators. The function also adds the parameter values to a map that will be used for binding parameters.

The constructed query is then executed:

```go
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
```

This approach has several advantages:

1. **Flexibility**: Queries can adapt to different filter combinations
2. **Safety**: Parameters are bound safely to prevent SQL injection
3. **Readability**: The query structure remains clear despite the dynamic nature
4. **Maintainability**: Filter logic is centralized and consistent

### 4.7 Transaction Management

Transactions are crucial for maintaining data consistency across multiple operations. Our framework provides a consistent approach to transaction management:

```go
// At the business layer
func (b *Business) ComplexOperation(ctx context.Context, param1, param2 string) error {
    // Start a transaction
    tx, err := b.db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("begin transaction: %w", err)
    }

    // Use a defer to ensure the transaction is rolled back if an error occurs
    defer func() {
        if errTx := tx.Rollback(); errTx != nil {
            if errors.Is(errTx, sql.ErrTxDone) {
                return
            }
            err = fmt.Errorf("rollback: %w", errTx)
        }
    }()

    // Create store implementations with the transaction
    widgetStore, err := b.widgetStorer.NewWithTx(tx)
    if err != nil {
        return fmt.Errorf("new widget store with tx: %w", err)
    }

    // Perform operations within the transaction
    if err := widgetStore.Create(ctx, widget); err != nil {
        return fmt.Errorf("create widget: %w", err)
    }

    if err := widgetStore.Update(ctx, anotherWidget); err != nil {
        return fmt.Errorf("update another widget: %w", err)
    }

    // Commit the transaction
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("commit: %w", err)
    }

    return nil
}
```

Each store implementation supports transactions through the `NewWithTx` method:

```go
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
```

This approach allows business operations to span multiple store operations within a single transaction, ensuring data consistency.

### 4.8 Database Schema and Migrations

Database schema changes are managed through migrations, which are defined in SQL files and applied during service startup.

Migrations are stored in the `business/sdk/migrate/sql` directory:

```sql
-- Version: 1.01
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

Migrations are applied during service startup using the `migrate` package:

```go
// From a service's main function
log.Infow("startup", "status", "initializing migrations support", "host", cfg.DB.Host)

if err := migrate.Migrate(ctx, db); err != nil {
    return fmt.Errorf("migrating db: %w", err)
}
```

The `migrate` package uses the Darwin library to track applied migrations and apply new ones:

```go
// Migrate attempts to bring the database up to date with the migrations
// defined in this package.
func Migrate(ctx context.Context, db *sqlx.DB) error {
    if err := sqldb.StatusCheck(ctx, db); err != nil {
        return fmt.Errorf("status check database: %w", err)
    }

    driver, err := generic.New(db.DB, postgres.Dialect{})
    if err != nil {
        return fmt.Errorf("construct darwin driver: %w", err)
    }

    d := darwin.New(driver, darwin.ParseMigrations(migrateDoc))
    return d.Migrate()
}
```

This approach ensures that schema changes are applied consistently and safely across environments.

### 4.9 Seeding Data

For testing and development, our framework provides a way to seed the database with initial data:

```go
// Seed runs the seed document defined in this package against db. The queries
// are run in a transaction and rolled back if any fail.
func Seed(ctx context.Context, db *sqlx.DB) (err error) {
    if err := sqldb.StatusCheck(ctx, db); err != nil {
        return fmt.Errorf("status check database: %w", err)
    }

    tx, err := db.Begin()
    if err != nil {
        return err
    }

    defer func() {
        if errTx := tx.Rollback(); errTx != nil {
            if errors.Is(errTx, sql.ErrTxDone) {
                return
            }

            err = fmt.Errorf("rollback: %w", errTx)
            return
        }
    }()

    if _, err := tx.Exec(seedDoc); err != nil {
        return fmt.Errorf("exec: %w", err)
    }

    if err := tx.Commit(); err != nil {
        return fmt.Errorf("commit: %w", err)
    }

    return nil
}
```

The seed data is defined in a SQL file:

```sql
INSERT INTO users (user_id, name, email, roles, password_hash, department, enabled, date_created, date_updated) VALUES
    ('5cf37266-3473-4006-984f-9325122678b7', 'Admin Gopher', 'admin@example.com', '{ADMIN}', '$2a$10$1ggfMVZV6Js0ybvJufLRUOWHS5f6KneuP0XwwHpJ8L8ipdry9f2/a', NULL, true, '2019-03-24 00:00:00', '2019-03-24 00:00:00'),
    ('45b5fbd3-755f-4379-8f07-a58d4a30fa2f', 'User Gopher', 'user@example.com', '{USER}', '$2a$10$9/XASPKBbJKVfCAZKDH.UuhsuALDr5vVm6VrYA9VFR8rccK86C1hW', NULL, true, '2019-03-24 00:00:00', '2019-03-24 00:00:00')
ON CONFLICT DO NOTHING;
```

This approach ensures that test data is consistent across environments and that it can be easily reset for testing.

### 4.10 Working with JSON and Arrays

PostgreSQL has excellent support for JSON and array data types, which our framework leverages for complex data structures.

For JSON data, we define custom types that implement the `driver.Valuer` and `sql.Scanner` interfaces:

```go
// JSONMap is a custom type for storing JSON data in PostgreSQL
type JSONMap map[string]interface{}

// Value implements the driver.Valuer interface for JSONMap
func (m JSONMap) Value() (driver.Value, error) {
    if m == nil {
        return nil, nil
    }
    return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for JSONMap
func (m *JSONMap) Scan(value interface{}) error {
    if value == nil {
        *m = make(JSONMap)
        return nil
    }

    var data []byte
    switch v := value.(type) {
    case []byte:
        data = v
    case string:
        data = []byte(v)
    default:
        return fmt.Errorf("unsupported type: %T", value)
    }

    return json.Unmarshal(data, m)
}
```

Similarly, for arrays:

```go
// StringArray is a custom type for storing arrays in PostgreSQL
type StringArray []string

// Value implements the driver.Valuer interface for StringArray
func (a StringArray) Value() (driver.Value, error) {
    return json.Marshal(a)
}

// Scan implements the sql.Scanner interface for StringArray
func (a *StringArray) Scan(value interface{}) error {
    if value == nil {
        *a = StringArray{}
        return nil
    }

    var data []byte
    switch v := value.(type) {
    case []byte:
        data = v
    case string:
        data = []byte(v)
    default:
        return fmt.Errorf("unsupported type: %T", value)
    }

    return json.Unmarshal(data, a)
}
```

These types allow for seamless conversion between Go data structures and database JSON/array data.

### 4.11 Complex Query Patterns

For more complex query patterns, our framework provides several approaches:

#### Subqueries

Subqueries can be used to incorporate data from related tables:

```sql
SELECT
    w.widget_id, w.user_id, w.name, w.category, w.description, w.is_active,
    w.date_created, w.date_updated,
    (SELECT COUNT(*) FROM parts p WHERE p.widget_id = w.widget_id) AS part_count
FROM
    widgets w
WHERE
    w.user_id = :user_id
```

#### Window Functions

Window functions can be used for analytics and ranking:

```sql
SELECT
    w.widget_id, w.user_id, w.name, w.category, w.description, w.is_active,
    w.date_created, w.date_updated,
    ROW_NUMBER() OVER (PARTITION BY w.category ORDER BY w.date_created) AS category_rank
FROM
    widgets w
WHERE
    w.user_id = :user_id
```

#### Common Table Expressions (CTEs)

CTEs can be used for more complex, multi-step queries:

```sql
WITH user_widgets AS (
    SELECT
        widget_id, name, category
    FROM
        widgets
    WHERE
        user_id = :user_id
),
widget_counts AS (
    SELECT
        category,
        COUNT(*) AS widget_count
    FROM
        user_widgets
    GROUP BY
        category
)
SELECT
    w.widget_id, w.name, w.category, c.widget_count
FROM
    user_widgets w
JOIN
    widget_counts c ON w.category = c.category
ORDER BY
    c.widget_count DESC, w.name
```

These patterns allow for powerful and efficient querying while maintaining the separation of concerns in our architecture.

### 4.12 Performance Considerations

Database performance is crucial for service scalability. Here are some key considerations:

#### Indexing

Proper indexing is essential for query performance. Indexes should be created for:

1. Primary keys
2. Foreign keys
3. Fields used in WHERE clauses
4. Fields used in ORDER BY clauses
5. Fields used in GROUP BY clauses

Here's an example of index creation:

```sql
CREATE INDEX widgets_name_idx ON widgets(name);
CREATE INDEX widgets_category_idx ON widgets(category);
CREATE INDEX widgets_user_id_idx ON widgets(user_id);
```

#### Connection Pooling

Connection pooling is managed through the `sqlx` library:

```go
db.SetMaxIdleConns(cfg.MaxIdleConns)
db.SetMaxOpenConns(cfg.MaxOpenConns)
```

Proper pool sizing depends on your application requirements and database server capacity. As a rule of thumb:

- `MaxIdleConns`: Set to a value that can handle your normal load
- `MaxOpenConns`: Set to a value that won't overwhelm your database server

#### Query Optimization

Query optimization is essential for performance. Some techniques include:

1. **Selecting Only Needed Columns**: Avoid `SELECT *` for large tables
2. **Using Prepared Statements**: Reuse query plans for similar queries
3. **Limiting Result Sets**: Always use pagination for large results
4. **Using Appropriate Indexes**: Ensure queries can use indexes
5. **Monitoring Query Performance**: Use tools like `EXPLAIN` to understand query execution

### 4.13 Testing Database Code

Testing database code requires special consideration due to the external dependency. Our framework provides utilities for integration testing with a real database:

```go
// New creates a database for testing.
func New(t *testing.T, testName string) *Database {
    t.Helper()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Connect to the database
    db, err := sqldb.Open(sqldb.Config{
        User:       "postgres",
        Password:   "postgres",
        Host:       "database-service",
        Name:       "postgres",
        DisableTLS: true,
    })
    if err != nil {
        t.Fatalf("Opening database connection: %v", err)
    }

    t.Cleanup(func() {
        db.Close()
    })

    // Create a unique test database based on the test name
    dbName := fmt.Sprintf("%s_%d", strings.ToLower(testName), time.Now().UnixNano())
    if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", dbName)); err != nil {
        t.Fatalf("Creating database %s: %v", dbName, err)
    }

    t.Cleanup(func() {
        // Force terminate all connections to the test database
        terminateConn := fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s';", dbName)
        if _, err := db.ExecContext(ctx, terminateConn); err != nil {
            t.Logf("Terminating connections to database %s: %v", dbName, err)
        }

        // Drop the test database
        if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE %s", dbName)); err != nil {
            t.Logf("Dropping database %s: %v", dbName, err)
        }
    })

    // Connect to the test database
    testDB, err := sqldb.Open(sqldb.Config{
        User:       "postgres",
        Password:   "postgres",
        Host:       "database-service",
        Name:       dbName,
        DisableTLS: true,
    })
    if err != nil {
        t.Fatalf("Opening test database connection: %v", err)
    }

    t.Cleanup(func() {
        testDB.Close()
    })

    // Apply migrations
    if err := migrate.Migrate(ctx, testDB); err != nil {
        t.Fatalf("Migrating test database: %v", err)
    }

    // Apply seed data
    if err := migrate.Seed(ctx, testDB); err != nil {
        t.Fatalf("Seeding test database: %v", err)
    }

    return &Database{
        DB: testDB,
        BusDomain: BusDomain{
            Widget: widgetbus.NewBusiness(
                logger.New(),
                nil,
                nil,
                widgetdb.NewStore(logger.New(), testDB),
            ),
            // Other business domains...
        },
    }
}
```

This utility creates a unique test database for each test, applies migrations and seed data, and provides business components for testing. It also cleans up the database after the test is complete.

With this utility, you can write integration tests that exercise the entire stack:

```go
func TestWidgetCreate(t *testing.T) {
    db := dbtest.New(t, "TestWidgetCreate")
    ctx := context.Background()

    // Create a new widget
    widget, err := db.BusDomain.Widget.Create(ctx, widgetbus.NewWidget{
        UserID:      uuid.MustParse("45b5fbd3-755f-4379-8f07-a58d4a30fa2f"), // From seed data
        Name:        name.MustParse("Test Widget"),
        Category:    category.MustParse("Test Category"),
        Description: "Test Description",
        IsActive:    true,
    })
    require.NoError(t, err)

    // Query the widget by ID
    found, err := db.BusDomain.Widget.QueryByID(ctx, widget.ID)
    require.NoError(t, err)

    // Validate the widget
    assert.Equal(t, widget.ID, found.ID)
    assert.Equal(t, widget.UserID, found.UserID)
    assert.Equal(t, widget.Name, found.Name)
    assert.Equal(t, widget.Category, found.Category)
    assert.Equal(t, widget.Description, found.Description)
    assert.Equal(t, widget.IsActive, found.IsActive)
}
```

This approach ensures that your database code is tested thoroughly in an environment that closely matches production.

### 4.14 Handling Database Errors

Database errors can be complex and varied. Our framework provides a structured approach to handling these errors:

```go
// ErrDBNotFound is returned when a record is not found.
var ErrDBNotFound = errors.New("not found")

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
```

Note the following patterns:

1. **Domain-Specific Errors**: Database errors are mapped to domain-specific errors (e.g., `sqldb.ErrDBNotFound` → `widgetbus.ErrNotFound`)
2. **Error Wrapping**: Original errors are wrapped with context
3. **Error Checking**: Specific errors are checked and handled differently
4. **Context Addition**: Errors include relevant IDs and other context

This approach ensures that errors are meaningful and actionable at each layer of the application.

### 4.15 Advanced PostgreSQL Features

PostgreSQL offers many advanced features that our framework leverages for specific use cases:

#### Full-Text Search

Full-text search is implemented using PostgreSQL's `tsvector` and `tsquery` types:

```sql
-- Create a GIN index for full-text search
CREATE INDEX widgets_fts_idx ON widgets USING gin(to_tsvector('english', name || ' ' || description));

-- Perform a full-text search
SELECT
    widget_id, user_id, name, category, description, is_active, date_created, date_updated
FROM
    widgets
WHERE
    to_tsvector('english', name || ' ' || description) @@ to_tsquery('english', :search)
ORDER BY
    ts_rank(to_tsvector('english', name || ' ' || description), to_tsquery('english', :search)) DESC
```

#### JSON Querying

JSON data can be queried using PostgreSQL's JSON operators:

```sql
-- Query based on a JSON field
SELECT
    widget_id, user_id, name, category, description, is_active, date_created, date_updated
FROM
    widgets
WHERE
    attributes ->> 'color' = :color
```

#### Array Operations

Arrays can be manipulated and queried using PostgreSQL's array operators:

```sql
-- Query based on array containment
SELECT
    widget_id, user_id, name, category, description, is_active, date_created, date_updated
FROM
    widgets
WHERE
    :tag = ANY(tags)
```

These advanced features allow for powerful and efficient queries without sacrificing the clean architecture of our system.

### 4.16 Database Security

Database security is a critical concern for any application. Our framework implements several security best practices:

#### Connection Encryption

Database connections are encrypted by default unless explicitly disabled:

```go
sslMode := "require"
if cfg.DisableTLS {
    sslMode = "disable"
}

q := make(url.Values)
q.Set("sslmode", sslMode)
```

#### Parameterized Queries

All queries use parameterized statements to prevent SQL injection:

```go
const q = `
SELECT
    widget_id, user_id, name, category, description, is_active, date_created, date_updated
FROM
    widgets
WHERE
    widget_id = :widget_id`

if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, q, data, &dbWidget); err != nil {
    // Error handling
}
```

#### Minimum Privilege Principle

Database users should be granted only the privileges they need:

```sql
-- Create a read-only user
CREATE USER readonlyuser WITH PASSWORD 'password';
GRANT CONNECT ON DATABASE mydatabase TO readonlyuser;
GRANT USAGE ON SCHEMA public TO readonlyuser;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonlyuser;
```

#### Sensitive Data Handling

Sensitive data should be encrypted or hashed before storage:

```go
// Hash a password before storage
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
    return fmt.Errorf("generating password hash: %w", err)
}

user.PasswordHash = string(hashedPassword)
```

These practices ensure that your database is secure against common threats.

### 4.17 Database Observability

Observability is essential for understanding database performance and behavior. Our framework implements several observability features:

#### Query Logging

All queries are logged for debugging and monitoring:

```go
// NamedExecContext logs queries before execution
func NamedExecContext(ctx context.Context, log *logger.Logger, db namedExecer, query string, data any) error {
    q := queryString(query, data)

    log.Debugw("database.NamedExecContext", "query", q)

    // Execute the query
    if _, err := db.NamedExecContext(ctx, query, data); err != nil {
        return err
    }

    return nil
}
```

#### Tracing

Database operations are traced for performance monitoring:

```go
// NamedExecContext adds tracing spans
func NamedExecContext(ctx context.Context, log *logger.Logger, db namedExecer, query string, data any) error {
    q := queryString(query, data)

    ctx, span := otel.AddSpan(ctx, "database.NamedExecContext")
    span.SetAttributes(
        attribute.String("query", q),
    )
    defer span.End()

    // Execute the query
    if _, err := db.NamedExecContext(ctx, query, data); err != nil {
        return err
    }

    return nil
}
```

#### Metrics

Database metrics can be collected for monitoring:

```go
// StatusCheck collects metrics about the database
func StatusCheck(ctx context.Context, db *sqlx.DB) error {
    const q = `SELECT true`

    ctx, span := otel.AddSpan(ctx, "database.StatusCheck")
    defer span.End()

    start := time.Now()
    var tmp bool
    err := db.QueryRowContext(ctx, q).Scan(&tmp)
    duration := time.Since(start)

    // Record metrics
    metrics.DatabaseQueryDuration.Observe(duration.Seconds())
    metrics.DatabaseQueryCount.Inc()

    if err != nil {
        metrics.DatabaseErrorCount.Inc()
        return err
    }

    return nil
}
```

These observability features enable you to understand and optimize your database usage.

### 4.18 Best Practices for Database Integration

When working with databases in our framework, follow these best practices:

1. **Use The Store Interface**: Always access the database through the store interface, never directly.
2. **Keep SQL in the Store Layer**: SQL should be confined to the store layer, not the business layer.
3. **Use Named Parameters**: Always use named parameters for clarity and safety.
4. **Handle Transactions Explicitly**: Be explicit about transaction boundaries.
5. **Map Domain Errors**: Map database errors to domain-specific errors.
6. **Create Appropriate Indexes**: Ensure that queries can use indexes for performance.
7. **Use Pagination**: Always use pagination for collection endpoints.
8. **Test Database Code**: Write integration tests for database code.
9. **Monitor Database Performance**: Use observability tools to understand and optimize database usage.
10. **Secure Database Connections**: Use encryption and parameterized queries.

### 4.19 Common Pitfalls to Avoid

When working with databases, avoid these common pitfalls:

1. **N+1 Query Problem**: Executing many queries when one would suffice.
2. **Over-Indexing**: Creating too many indexes can slow down writes.
3. **Under-Indexing**: Not having the right indexes can slow down reads.
4. **Connection Leaks**: Not properly closing database resources.
5. **SQL Injection**: Using string concatenation instead of parameterized queries.
6. **Transaction Deadlocks**: Not ordering database operations consistently.
7. **Large Transactions**: Keeping transactions open for too long.
8. **Not Handling Errors**: Ignoring database errors or handling them incorrectly.
9. **Assuming Database Availability**: Not handling database connection failures.
10. **Not Testing Database Code**: Relying on manual testing instead of automated tests.

### 4.20 Summary

In this chapter, we've covered:

1. **Database Architecture Overview**: The layered approach to database integration.
2. **Database Connection Management**: How connections are established and managed.
3. **Store Implementation**: How business operations are translated into database queries.
4. **Query Execution Utilities**: Utilities for consistent and safe query execution.
5. **Model Mapping**: Converting between database and business models.
6. **Dynamic Query Construction**: Building SQL queries dynamically based on filter criteria.
7. **Transaction Management**: Handling transactions consistently across the system.
8. **Database Schema and Migrations**: Managing schema changes through migrations.
9. **Seeding Data**: Providing initial data for testing and development.
10. **Working with JSON and Arrays**: Using PostgreSQL's advanced data types.
11. **Complex Query Patterns**: Implementing subqueries, window functions, and CTEs.
12. **Performance Considerations**: Optimizing database performance.
13. **Testing Database Code**: Writing integration tests for database code.
14. **Handling Database Errors**: Mapping database errors to domain-specific errors.
15. **Advanced PostgreSQL Features**: Leveraging full-text search, JSON querying, and array operations.
16. **Database Security**: Implementing security best practices.
17. **Database Observability**: Monitoring database performance and behavior.
18. **Best Practices**: Guidelines for database integration.
19. **Common Pitfalls**: Issues to avoid in database integration.

By following these patterns and best practices, you can integrate databases into your services in a way that is maintainable, performant, and secure.

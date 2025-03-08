# Systems Architecture and Implementation Guide

## 1. Introduction to System Architecture

Welcome to our comprehensive guide on creating new services and applications within our modular system. This document will help you understand the architecture, components, and best practices for extending our platform with new functionality.

### 1.1 System Overview

Our system follows a clean, modular architecture that emphasizes separation of concerns and clear boundaries between components. At its core, the design implements a Domain-Driven Design (DDD) approach with distinct layers:

1. **Application Layer** (`app/`) - Handles HTTP requests, input validation, and response formatting
2. **Business Layer** (`business/`) - Contains core business logic and domain rules
3. **Foundation Layer** (`foundation/`) - Provides shared utilities and cross-cutting concerns

This architecture facilitates:

- Independent development of features
- Easier testing and maintenance
- Clear separation between web-specific and business logic concerns
- Flexibility to change implementations without affecting other parts of the system

### 1.2 High-Level Module Organization

The system's codebase is organized into key directories that reflect our architectural principles:

```
├── api
│   ├── frontends      # User interfaces (React, etc.)
│   ├── services       # Deployable service executables
│   │   ├── auth       # Authentication service
│   │   ├── sales      # Sales processing service
│   │   └── ...        # Other microservices
│   └── tooling        # Admin tools and utilities
├── app
│   ├── domain         # Application-specific domain implementations
│   │   ├── productapp # Product-related HTTP handlers and models
│   │   ├── userapp    # User-related HTTP handlers and models
│   │   └── ...
│   └── sdk            # Application-level shared utilities
│       ├── auth       # Authentication utilities
│       ├── mid        # HTTP middleware components
│       └── ...
├── business
│   ├── domain         # Business domain implementations
│   │   ├── productbus # Product business logic
│   │   ├── userbus    # User business logic
│   │   └── ...
│   ├── sdk            # Business-level shared utilities
│   │   ├── migrate    # Database migration tools
│   │   ├── order      # Sorting utilities
│   │   └── ...
│   └── types          # Core domain types
│       ├── money      # Money value type
│       ├── name       # Name value type
│       └── ...
└── foundation         # Fundamental shared utilities
    ├── logger         # Logging infrastructure
    ├── web            # Web framework
    └── ...
```

### 1.3 File Structure for New Services

When creating a new service, you need to follow this structure precisely to ensure consistency and maintainability. Let's break down each component:

```
api/
  services/
    myservice/         # Your service's executable
      main.go          # Entry point with configuration and server startup
      build/           # Build artifacts and deployment files
      tests/           # End-to-end and integration tests
app/
  domain/
    myserviceapp/      # HTTP API layer for your service
      myserviceapp.go  # Handler logic with request processing
      model.go         # API models (request/response structures)
      route.go         # Route definitions and endpoint configuration
      filter.go        # Query filter parsing and validation
      order.go         # Sorting options and order mapping
business/
  domain/
    myservicebus/      # Business logic layer
      myservicebus.go  # Core domain logic and operations
      model.go         # Business models (pure domain objects)
      filter.go        # Query filter definitions
      order.go         # Sorting definitions
      stores/
        myservicedb/   # Database access layer
          myservicedb.go # DB operations (Create, Read, Update, Delete)
          model.go     # Database models with mapping functions
          filter.go    # SQL query filter construction
          order.go     # SQL order by clause construction
  types/
    custom_types.go    # Domain-specific value types
```

Each of these files serves a specific purpose in the architecture:

- **main.go**: Configures and starts the service, connecting all components
- **myserviceapp.go**: Contains HTTP handlers that process requests and format responses
- **model.go**: Defines the JSON structures for API input/output and their validation rules
- **route.go**: Configures routing, middleware, and authentication for each endpoint
- **filter.go**: Handles query parameter parsing for filtering data
- **order.go**: Handles sorting parameter parsing for ordering results
- **myservicebus.go**: Implements core business operations and enforces domain rules
- **stores/myservicedb/**: Implements database operations specific to this domain

This structure ensures that responsibilities are clearly separated and that each component has a single, well-defined purpose.

### 1.4 Service Communication Patterns

Services in our system communicate through well-defined interfaces and clear dependency management. The typical flow of data through the system follows this pattern:

1. HTTP requests are received by handlers in the `app/domain/[domainname]app` layer
2. These handlers validate input and transform it into business domain objects
3. Business logic is executed in the `business/domain/[domainname]bus` layer
4. Data persistence is managed through store interfaces in the business layer
5. Results are transformed back into HTTP responses by the application layer

This unidirectional flow ensures that:

- Business logic remains independent of transport concerns
- Testing can be performed at each layer independently
- Changes to API contracts don't affect business logic implementation
- Database implementations can be changed without affecting the rest of the system

Below is a diagram representing how a typical request flows through the system:

```
                   ┌─────────────────────┐
                   │      HTTP Request   │
                   └──────────┬──────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────┐
│                   App Layer                        │
│ ┌──────────────────────────────────────────────┐   │
│ │              HTTP Handler                    │   │
│ │  - Parses request                            │   │
│ │  - Validates input                           │   │
│ │  - Converts to business models               │   │
│ └──────────────────┬───────────────────────────┘   │
└────────────────────┼───────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────┐
│                Business Layer                      │
│ ┌──────────────────────────────────────────────┐   │
│ │             Business Logic                   │   │
│ │  - Enforces domain rules                     │   │
│ │  - Coordinates operations                    │   │
│ │  - Manages transactions                      │   │
│ └──────────────────┬───────────────────────────┘   │
│                    │                               │
│ ┌──────────────────▼───────────────────────────┐   │
│ │              Store Interface                 │   │
│ │  - Defines data access operations            │   │
│ └──────────────────┬───────────────────────────┘   │
└────────────────────┼───────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────┐
│                 Data Layer                         │
│ ┌──────────────────────────────────────────────┐   │
│ │            Database Operations               │   │
│ │  - Constructs queries                        │   │
│ │  - Maps between models                       │   │
│ │  - Handles DB transactions                   │   │
│ └──────────────────┬───────────────────────────┘   │
└────────────────────┼───────────────────────────────┘
                     │
                     ▼
                ┌─────────────┐
                │  Database   │
                └─────────────┘
```

### 1.5 Type Design

Our system employs a strong type system to enforce domain correctness. Instead of using primitive types directly, we define domain-specific value types that encapsulate validation and behavior. For example:

- `name.Name` instead of string for product names
- `money.Money` instead of float64 for monetary values
- `quantity.Quantity` instead of int for product quantities
- `location.Location` instead of string for inventory locations
- `role.Role` instead of string for user roles

These types provide several benefits:

- Type safety and compile-time error detection
- Domain validation at the point of creation
- Self-documenting code that expresses business concepts
- Prevention of common bugs like mixing incompatible values

A typical value type implementation follows this pattern:

```go
// Package name represents a name in the system.
package name

import (
    "fmt"
    "regexp"
)

// Name represents a name in the system.
type Name struct {
    value string
}

// String returns the value of the name.
func (n Name) String() string {
    return n.value
}

// Equal provides support for the go-cmp package and testing.
func (n Name) Equal(n2 Name) bool {
    return n.value == n2.value
}

// MarshalText provides support for logging and any marshal needs.
func (n Name) MarshalText() ([]byte, error) {
    return []byte(n.value), nil
}

var nameRegEx = regexp.MustCompile("^[a-zA-Z0-9' -]{3,20}$")

// Parse parses the string value and returns a name if the value complies
// with the rules for a name.
func Parse(value string) (Name, error) {
    if !nameRegEx.MatchString(value) {
        return Name{}, fmt.Errorf("invalid name %q", value)
    }

    return Name{value}, nil
}

// MustParse parses the string value and returns a name if the value
// complies with the rules for a name. If an error occurs the function panics.
func MustParse(value string) Name {
    name, err := Parse(value)
    if err != nil {
        panic(err)
    }

    return name
}
```

An important design principle is that validation happens at type creation through `Parse` functions, not at usage time, ensuring that invalid values cannot exist within the system.

### 1.6 Domain Model Organization

Each domain in our system follows a consistent organization pattern:

1. **Models**: Define the core domain entities and value objects
2. **Business Operations**: Implement domain logic and rules
3. **Filters**: Define criteria for querying domain objects
4. **Store Interface**: Declares data access requirements
5. **Store Implementation**: Provides concrete data access operations

For example, a product domain might include:

1. **Models**: Product, NewProduct, UpdateProduct
2. **Business Operations**: Create, Update, Delete, Query
3. **Filters**: QueryFilter with fields like Name, Cost, Category
4. **Store Interface**: Create, Update, Delete, Query, QueryByID
5. **Store Implementation**: SQL-specific implementations of the interface

This organization ensures that each domain is self-contained and that dependencies flow in the correct direction.

### 1.7 Dependency Management

Dependencies in our system flow inward, with outer layers depending on inner layers, but never the reverse:

- Application layer depends on Business layer
- Business layer depends on Foundation layer
- No layer depends on layers outside of it

This pattern, known as the Dependency Rule from Clean Architecture, ensures that our core business logic remains isolated from infrastructure and UI concerns.

Dependencies are explicitly injected through constructors, making them visible and testable:

```go
// NewBusiness constructs a product business API for use.
func NewBusiness(log *logger.Logger, userBus *userbus.Business, delegate *delegate.Delegate, storer Storer) *Business {
    b := Business{
        log:      log,
        userBus:  userBus,
        delegate: delegate,
        storer:   storer,
    }

    b.registerDelegateFunctions()

    return &b
}
```

This approach allows for:

- Easy mocking of dependencies in tests
- Clear visibility of what each component needs
- Flexibility to change implementations without changing clients
- Better testability and isolation of concerns

### 1.8 Error Handling Philosophy

Our system follows a structured approach to error handling:

1. **Domain Errors**: Defined as variables in the business layer (e.g., `ErrNotFound`)
2. **Wrapped Errors**: Use `fmt.Errorf("context: %w", err)` for adding context
3. **Error Checking**: Context is added at each layer boundary
4. **HTTP Error Responses**: Converted to appropriate status codes in the app layer

Error handling is explicit and errors are treated as values to be checked, not exceptional cases to be caught.

```go
// Example of proper error handling across layers
func (a *app) queryByID(ctx context.Context, r *http.Request) web.Encoder {
    // Get product from middleware
    prd, err := mid.GetProduct(ctx)
    if err != nil {
        return errs.Newf(errs.Internal, "querybyid: %s", err)
    }

    return toAppProduct(prd)
}

// Business layer error handling
func (b *Business) QueryByID(ctx context.Context, productID uuid.UUID) (Product, error) {
    ctx, span := otel.AddSpan(ctx, "business.productbus.querybyid")
    defer span.End()

    prd, err := b.storer.QueryByID(ctx, productID)
    if err != nil {
        return Product{}, fmt.Errorf("query: productID[%s]: %w", productID, err)
    }

    // Load variants
    variants, err := b.storer.QueryVariantsByProductID(ctx, productID)
    if err != nil {
        return Product{}, fmt.Errorf("query variants: productID[%s]: %w", productID, err)
    }
    prd.Variants = variants

    return prd, nil
}
```

### 1.9 Key Components in Detail

Let's examine key components of the system in more detail:

**1. Application Layer (app/domain/[domainname]app)**

The application layer is responsible for:

- HTTP request handling and routing
- Input validation and sanitization
- Converting between HTTP and business models
- Error translation to HTTP status codes
- Authentication and authorization checks

Key files in this layer include:

- **route.go**: Defines API endpoints and attaches handlers
- **model.go**: Defines JSON request/response structures
- **[domainname]app.go**: Implements HTTP handlers
- **filter.go**: Parses and validates query parameters

**2. Business Layer (business/domain/[domainname]bus)**

The business layer implements core domain logic:

- Business rules and validations
- Coordination of operations
- Transaction management
- Domain event handling

Key files in this layer include:

- **model.go**: Defines domain entities and value objects
- **[domainname]bus.go**: Implements business operations
- **filter.go**: Defines query filter structures
- **order.go**: Defines sort ordering options

**3. Store Layer (business/domain/[domainname]bus/stores)**

The store layer handles data persistence:

- Database query construction
- Mapping between domain and database models
- Transaction handling
- Database-specific optimizations

Key files in this layer include:

- **[storename].go**: Implements the Storer interface
- **model.go**: Defines database models and mapping functions
- **filter.go**: Translates domain filters to database queries
- **order.go**: Translates domain ordering to database syntax

**4. Foundation Layer (foundation/)**

The foundation layer provides infrastructure and utilities:

- Logging and tracing
- HTTP server framework
- Error handling utilities
- Configuration management

Understanding how these components interact is essential for creating new services that integrate properly with the existing architecture.

### 1.10 Interface Design and Dependency Inversion

Our system makes extensive use of interfaces to achieve dependency inversion. For example, the business layer defines a `Storer` interface that abstracts away database access:

```go
// Storer interface declares the behavior this package needs to persist and
// retrieve data.
type Storer interface {
    NewWithTx(tx sqldb.CommitRollbacker) (Storer, error)
    Create(ctx context.Context, prd Product) error
    Update(ctx context.Context, prd Product) error
    Delete(ctx context.Context, prd Product) error
    Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Product, error)
    Count(ctx context.Context, filter QueryFilter) (int, error)
    QueryByID(ctx context.Context, productID uuid.UUID) (Product, error)
    QueryByUserID(ctx context.Context, userID uuid.UUID) ([]Product, error)
}
```

This approach allows the business layer to remain independent of specific database implementations, making it possible to:

- Replace database technology without changing business logic
- Mock the interface for unit testing
- Use different implementations for different deployment scenarios

This pattern is applied consistently throughout the system, ensuring that all dependencies point inward toward the domain core.

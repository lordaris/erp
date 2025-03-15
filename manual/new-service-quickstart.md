# Quick Start Guide for Creating a New Service

This guide provides a streamlined approach to implementing a new service in our architecture. It follows a systematic process, helping you build each layer in the correct order while maintaining architectural consistency.

## Service Creation Workflow

### Phase 1: Planning and Domain Models

1. **Define your domain concept clearly**

   - What entity are you modeling? (e.g., products, orders, inventory)
   - What operations will it support?
   - What relationships does it have with other domains?

2. **Create the business domain model**

   - Start with `business/domain/[domainname]bus/model.go`
   - Define your core entity struct with all properties
   - Define your input/output models (e.g., New[Entity], Update[Entity])
   - See Section 2.3 "Implementing Domain Models" for examples

3. **Define query filters and ordering**
   - Create `business/domain/[domainname]bus/filter.go` for query filters
   - Create `business/domain/[domainname]bus/order.go` for sorting options
   - See Sections 2.4 and 2.5 for implementation details

### Phase 2: Implementing Business Logic

4. **Implement the Store interface**

   - Define the data access interface in `business/domain/[domainname]bus/[domainname]bus.go`
   - Include all CRUD operations and any domain-specific queries
   - See Section 2.6 for interface definition examples

5. **Implement business logic**
   - Complete the Business struct implementation in the same file
   - Create core domain operations (Create, Update, Delete, Query, etc.)
   - Implement any domain-specific business rules
   - See Section 2.7 for business logic implementation examples

### Phase 3: Database Integration

6. **Create database models and mappers**

   - Create `business/domain/[domainname]bus/stores/[domainname]db/model.go`
   - Define database models and mapping functions
   - See Section 4.5 for model mapping examples

7. **Implement database operations**

   - Create `business/domain/[domainname]bus/stores/[domainname]db/[domainname]db.go`
   - Implement the Store interface with database operations
   - See Section 4.3 for store implementation examples

8. **Implement filter and order database logic**

   - Create `business/domain/[domainname]bus/stores/[domainname]db/filter.go`
   - Create `business/domain/[domainname]bus/stores/[domainname]db/order.go`
   - See Sections 4.6 and 4.4 for query construction examples

9. **Create database migration**
   - Add your table definition to `business/sdk/migrate/sql/migrate.sql`
   - See Section 4.8 for migration examples

### Phase 4: API Layer Implementation

10. **Define API models**

    - Create `app/domain/[domainname]app/model.go`
    - Define request/response models and conversion functions
    - See Section 3.8 for API model examples

11. **Implement query parameter handling**

    - Create `app/domain/[domainname]app/filter.go`
    - Create `app/domain/[domainname]app/order.go`
    - See Section 3.9 for parameter handling examples

12. **Implement HTTP handlers**

    - Create `app/domain/[domainname]app/[domainname]app.go`
    - Implement handlers for each API operation
    - See Section 3.10 for handler implementation patterns

13. **Define API routes**
    - Create `app/domain/[domainname]app/route.go`
    - Define routes, HTTP methods, and middleware
    - See Section 3.4 for route registration examples

### Phase 5: Authentication and Authorization

14. **Implement authorization middleware** (if needed)
    - Create middleware for resource authorization
    - See Section 5.5 for resource-based authorization examples

### Phase 6: Service Entry Point

15. **Create the service entry point**
    - Create `api/services/[domainname]/main.go`
    - Configure and start the service
    - See Section 2.17 for service entry point examples

## Development Workflow Tips

- **Follow the "inside-out" approach**: Start with the core domain model and work outward
- **Test as you go**: Write tests for each layer before moving to the next
- **Use existing services as references**: Look at similar services for patterns
- **Check dependencies**: Ensure your service has all required dependencies injected
- **Maintain separation of concerns**: Keep each layer focused on its responsibilities

This guide provides a systematic approach to creating a new service. For detailed implementation examples, refer to the referenced sections in the main documentation.

## 3. Defining API Endpoints

Creating well-designed API endpoints is crucial for building services that are easy to use, maintain, and scale. This chapter will guide you through the process of defining API endpoints in our architectural framework, covering best practices for route structure, request/response handling, and implementation patterns.

### 3.1 API Design Principles

Before implementing specific endpoints, it's important to understand the principles that guide good API design:

1. **Resource-Oriented Design**: Organize endpoints around resources (nouns) rather than actions (verbs).
2. **Consistent URL Structure**: Use a consistent pattern for URL paths across all services.
3. **HTTP Method Semantics**: Use HTTP methods appropriately (GET, POST, PUT, DELETE).
4. **Versioning**: Include API version in the URL path to allow for evolution.
5. **Error Handling**: Provide consistent, informative error responses.
6. **Pagination**: Support pagination for collection endpoints.
7. **Filtering and Sorting**: Allow clients to filter and sort results.
8. **Authentication and Authorization**: Clearly define which endpoints require authentication.

These principles ensure that your APIs are intuitive, maintainable, and adhere to RESTful conventions.

### 3.2 URL Structure and Versioning

Our API URLs follow a consistent structure that includes versioning and resource paths:

```
/{version}/{resource}/{id}/{sub-resource}/{sub-id}
```

For example:

- `/v1/widgets` - List all widgets
- `/v1/widgets/abc123` - Get a specific widget
- `/v1/widgets/abc123/parts` - List parts for a specific widget
- `/v1/widgets/abc123/parts/xyz789` - Get a specific part of a widget

Version prefixing (`/v1/`) allows for backward compatibility as the API evolves. When making breaking changes, you can introduce a new version (`/v2/`) while maintaining the old endpoints.

### 3.3 HTTP Methods and CRUD Operations

Each resource typically supports a set of standard operations mapped to HTTP methods:

| HTTP Method | Operation        | Description                | Example                   |
| ----------- | ---------------- | -------------------------- | ------------------------- |
| GET         | Read             | Retrieve resource(s)       | GET /v1/widgets           |
| POST        | Create           | Create a new resource      | POST /v1/widgets          |
| PUT         | Update (Full)    | Replace a resource         | PUT /v1/widgets/abc123    |
| PATCH       | Update (Partial) | Modify parts of a resource | PATCH /v1/widgets/abc123  |
| DELETE      | Delete           | Remove a resource          | DELETE /v1/widgets/abc123 |

Our framework currently focuses on these primary methods, with PATCH functionality typically handled through PUT with partial updates.

### 3.4 Route Registration

In our framework, routes are registered in the `route.go` file of each application domain. Let's examine how this works by looking at our widgets example:

```go
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

This code registers five endpoints for the widgets resource, each with:

1. **HTTP Method**: Specifies which HTTP verb the endpoint accepts
2. **Version**: Defines the API version (e.g., "v1")
3. **Path**: Specifies the URL path, including any path parameters
4. **Handler**: References the function that will process the request
5. **Middleware**: Lists any middleware to be applied (e.g., authentication)

The registration pattern is consistent across all domains, making it easy to understand the API surface of each service.

### 3.5 Request Handling and Parameter Extraction

Our framework provides utilities for extracting parameters from different parts of the request:

1. **Path Parameters**: Values embedded in the URL path (e.g., `/widgets/{widget_id}`)
2. **Query Parameters**: Values in the URL query string (e.g., `?name=value`)
3. **Request Body**: JSON data sent in the request body

Here's how we handle each type:

#### Path Parameters

Use the `web.Param` function to extract values from the URL path:

```go
widgetID := web.Param(r, "widget_id")
if widgetID == "" {
    return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
        fmt.Errorf("missing widget_id"))
}

id, err := uuid.Parse(widgetID)
if err != nil {
    return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
        fmt.Errorf("invalid widget_id: %w", err))
}
```

#### Query Parameters

Use the `parseQueryParams` function to extract and process query parameters:

```go
func parseQueryParams(r *http.Request) queryParams {
    values := r.URL.Query()

    filter := queryParams{
        Page:          values.Get("page"),
        Rows:          values.Get("rows"),
        OrderBy:       values.Get("orderBy"),
        Name:          values.Get("name"),
        Category:      values.Get("category"),
        // ... other parameters
    }

    return filter
}
```

These parameters are then converted to appropriate domain types using the `parseFilter` function.

#### Request Body

Use the `web.Decode` function to extract and validate JSON data from the request body:

```go
var app NewWidget
if err := web.Decode(r, &app); err != nil {
    return errs.New(errs.InvalidArgument, err)
}
```

This function automatically handles JSON unmarshaling and validation based on struct tags.

### 3.6 Response Formatting

API responses are formatted using a consistent pattern:

1. **Success Responses**: Return a domain-specific encoder that will be JSON-encoded
2. **Error Responses**: Return an error that will be translated into an appropriate HTTP status code

For successful responses, your handler returns an object that implements the `web.Encoder` interface:

```go
// Encoder represents the behavior for endpoint data to be encoded.
type Encoder interface {
    Encode() ([]byte, string, error)
}
```

For example, the widget response model implements this interface:

```go
// Encode implements the encoder interface.
func (app Widget) Encode() ([]byte, string, error) {
    data, err := json.Marshal(app)
    return data, "application/json", err
}
```

For collections, we use the `query.NewResult` function to create a paginated response:

```go
return query.NewResult(toAppWidgets(widgets), total, page)
```

Which produces a response like:

```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "rows": 10,
  "pages": 5
}
```

### 3.7 Error Handling

Error responses are standardized across the API. When an error occurs, the handler returns an `errs.Error` object:

```go
return errs.Newf(errs.Internal, "query: %s", err)
```

The web framework automatically converts this to a JSON response with the appropriate HTTP status code:

```json
{
  "error": {
    "code": "internal",
    "message": "query: widget not found",
    "fields": null
  }
}
```

For field-specific validation errors, we use `errs.FieldErrors`:

```go
var fieldErrors errs.FieldErrors
fieldErrors.Add("name", fmt.Errorf("name is required"))
fieldErrors.Add("category", fmt.Errorf("invalid category"))

return fieldErrors.ToError()
```

Which produces:

```json
{
  "error": {
    "code": "invalid_argument",
    "message": "validation failed",
    "fields": {
      "name": "name is required",
      "category": "invalid category"
    }
  }
}
```

This consistent error format makes it easier for clients to handle errors programmatically.

### 3.8 Authentication and Authorization

Most API endpoints require authentication and authorization. Our framework provides middleware for these concerns:

1. **Authentication**: Verifies the identity of the caller
2. **Authorization**: Determines if the caller has permission to perform the operation

Authentication is handled by the `mid.Authenticate` middleware:

```go
authen := mid.Authenticate(cfg.AuthClient)
```

This middleware extracts and validates JWT tokens from the request.

Authorization can be handled in several ways:

1. **Role-Based**: Checks if the user has a specific role

```go
ruleAny := mid.Authorize(cfg.AuthClient, auth.RuleAny)
ruleUserOnly := mid.Authorize(cfg.AuthClient, auth.RuleUserOnly)
```

2. **Resource-Based**: Checks if the user has permission to access a specific resource

```go
ruleAuthorizeWidget := mid.AuthorizeWidget(cfg.AuthClient, cfg.WidgetBus)
```

This middleware fetches the widget and checks if the user has permission to access it.

All of these middleware components are applied during route registration:

```go
app.HandlerFunc(http.MethodPut, version, "/widgets/{widget_id}", api.update,
    authen, ruleAuthorizeWidget)
```

### 3.9 Pagination, Filtering, and Sorting

Collection endpoints support pagination, filtering, and sorting through query parameters:

1. **Pagination**: `?page=1&rows=10`
2. **Filtering**: `?name=widget&category=tool`
3. **Sorting**: `?orderBy=name:asc`

Let's look at how each is handled:

#### Pagination

Pagination parameters are extracted and converted to a `page.Page` object:

```go
page, err := page.Parse(qp.Page, qp.Rows)
if err != nil {
    return errs.NewFieldErrors("page", err)
}
```

This object is then passed to the business layer for query execution.

#### Filtering

Filter parameters are extracted and converted to a domain-specific `QueryFilter` object:

```go
filter, err := parseFilter(qp)
if err != nil {
    return err.(*errs.Error)
}
```

This object contains strongly-typed filter criteria that the business layer can use.

#### Sorting

Sorting parameters are parsed and converted to an `order.By` object:

```go
orderBy, err := order.Parse(orderByFields, qp.OrderBy, widgetbus.DefaultOrderBy)
if err != nil {
    return errs.NewFieldErrors("order", err)
}
```

This object specifies the field and direction for sorting.

These components are then passed to the business layer for query execution:

```go
widgets, err := a.widgetBus.Query(ctx, filter, orderBy, page)
```

### 3.10 Handler Implementation Pattern

Our framework uses a consistent pattern for implementing API handlers. Each handler follows these steps:

1. **Extract Parameters**: Parse input from the request
2. **Validate Input**: Ensure the input is valid
3. **Call Business Logic**: Delegate to the business layer
4. **Format Response**: Convert the result to an API response

Here's an example of the `create` handler for widgets:

```go
// create adds a new widget to the system.
func (a *app) create(ctx context.Context, r *http.Request) web.Encoder {
    // Extract Parameters: Parse the request body into an API model
    var app NewWidget
    if err := web.Decode(r, &app); err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    // Validate Input: Convert to business model (which validates the input)
    nw, err := toBusNewWidget(ctx, app)
    if err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    // Call Business Logic: Create the widget
    widget, err := a.widgetBus.Create(ctx, nw)
    if err != nil {
        return errs.Newf(errs.Internal, "create: widget[%+v]: %s", app, err)
    }

    // Format Response: Convert to API model
    return toAppWidget(widget)
}
```

This pattern ensures that all handlers are consistent and easy to understand.

### 3.11 Sub-Resources and Nested Routes

For more complex domains, you may need to define sub-resources and nested routes. For example, if widgets have parts, you might define routes like:

```go
app.HandlerFunc(http.MethodGet, version, "/widgets/{widget_id}/parts", api.queryParts,
    authen, ruleAuthorizeWidget)
app.HandlerFunc(http.MethodGet, version, "/widgets/{widget_id}/parts/{part_id}", api.queryPartByID,
    authen, ruleAuthorizeWidget)
app.HandlerFunc(http.MethodPost, version, "/widgets/{widget_id}/parts", api.createPart,
    authen, ruleAuthorizeWidget)
app.HandlerFunc(http.MethodPut, version, "/widgets/{widget_id}/parts/{part_id}", api.updatePart,
    authen, ruleAuthorizeWidget)
app.HandlerFunc(http.MethodDelete, version, "/widgets/{widget_id}/parts/{part_id}", api.deletePart,
    authen, ruleAuthorizeWidget)
```

The handlers for these routes would extract both the widget ID and part ID from the path:

```go
func (a *app) queryPartByID(ctx context.Context, r *http.Request) web.Encoder {
    widget, err := mid.GetWidget(ctx)
    if err != nil {
        return errs.Newf(errs.Internal, "widget missing in context: %s", err)
    }

    partID := web.Param(r, "part_id")
    if partID == "" {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("missing part_id"))
    }

    id, err := uuid.Parse(partID)
    if err != nil {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("invalid part_id: %w", err))
    }

    part, err := a.widgetBus.QueryPartByID(ctx, widget.ID, id)
    if err != nil {
        return errs.Newf(errs.Internal, "query part: partID[%s]: %s", id, err)
    }

    return toAppPart(part)
}
```

This pattern allows for rich, hierarchical API designs that reflect the relationships in your domain model.

### 3.12 Batch Operations

Sometimes you need to perform operations on multiple resources at once. For batch operations, use dedicated endpoints with clear naming:

```go
app.HandlerFunc(http.MethodPost, version, "/widgets/batch/create", api.batchCreate,
    authen, ruleUserOnly)
app.HandlerFunc(http.MethodPut, version, "/widgets/batch/update", api.batchUpdate,
    authen, ruleUserOnly)
app.HandlerFunc(http.MethodDelete, version, "/widgets/batch/delete", api.batchDelete,
    authen, ruleUserOnly)
```

These endpoints accept arrays of resources in the request body:

```go
// BatchCreateWidget defines a batch creation request.
type BatchCreateWidget struct {
    Widgets []NewWidget `json:"widgets" validate:"required,dive"`
}
```

The handler would then process each item in the batch:

```go
func (a *app) batchCreate(ctx context.Context, r *http.Request) web.Encoder {
    var app BatchCreateWidget
    if err := web.Decode(r, &app); err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    // Process each widget in the batch
    results := make([]BatchResult, len(app.Widgets))
    for i, newWidget := range app.Widgets {
        // Convert to business model
        nw, err := toBusNewWidget(ctx, newWidget)
        if err != nil {
            results[i] = BatchResult{
                Success: false,
                Error:   err.Error(),
            }
            continue
        }

        // Create the widget
        widget, err := a.widgetBus.Create(ctx, nw)
        if err != nil {
            results[i] = BatchResult{
                Success: false,
                Error:   err.Error(),
            }
            continue
        }

        // Record success
        results[i] = BatchResult{
            Success: true,
            ID:      widget.ID.String(),
        }
    }

    return BatchCreateResult{Results: results}
}
```

Batch operations can significantly improve performance for clients that need to process multiple resources at once.

### 3.13 Query Parameters and API Flexibility

Well-designed APIs provide flexibility through query parameters. Here are some common query parameters you might implement:

1. **fields**: Allows clients to request specific fields (`?fields=id,name,category`)
2. **include**: Allows clients to request related resources (`?include=parts,metadata`)
3. **expand**: Allows clients to expand nested resources (`?expand=parts`)
4. **search**: Allows full-text search across fields (`?search=widget`)

Implementing these parameters requires changes to your filter parsing:

```go
if qp.Fields != "" {
    fields := strings.Split(qp.Fields, ",")
    filter.Fields = &fields
}

if qp.Include != "" {
    includes := strings.Split(qp.Include, ",")
    filter.Include = &includes
}

if qp.Expand != "" {
    expands := strings.Split(qp.Expand, ",")
    filter.Expand = &expands
}

if qp.Search != "" {
    filter.Search = &qp.Search
}
```

And changes to your business layer to handle these parameters. For example, the `include` parameter might load related entities:

```go
func (b *Business) Query(ctx context.Context, filter QueryFilter, orderBy order.By, page page.Page) ([]Widget, error) {
    widgets, err := b.storer.Query(ctx, filter, orderBy, page)
    if err != nil {
        return nil, fmt.Errorf("query: %w", err)
    }

    // If the include parameter contains "parts", load parts for each widget
    if filter.Include != nil && containsString(*filter.Include, "parts") {
        for i := range widgets {
            parts, err := b.storer.QueryPartsByWidgetID(ctx, widgets[i].ID)
            if err != nil {
                return nil, fmt.Errorf("query parts: widgetID[%s]: %w", widgets[i].ID, err)
            }
            widgets[i].Parts = parts
        }
    }

    return widgets, nil
}
```

This approach allows clients to request exactly the data they need, reducing bandwidth usage and improving performance.

### 3.14 API Versioning Strategies

We've already discussed URL-based versioning (`/v1/widgets`), but there are other strategies to consider:

1. **Header-Based**: Using a custom header like `API-Version: 1`
2. **Accept Header**: Using the Accept header like `Accept: application/vnd.myapi.v1+json`
3. **Query Parameter**: Using a query parameter like `?api-version=1`

URL-based versioning is the most visible and easiest to use, but it can lead to path duplication if many endpoints change. Consider your versioning strategy based on your specific needs.

When implementing a new version, you typically:

1. Create new models for the new version
2. Create new handlers for the new version
3. Register routes for the new version
4. Maintain backwards compatibility for the old version

For example:

```go
// v1 route
app.HandlerFunc(http.MethodGet, "v1", "/widgets", api.v1Query, authen, ruleAny)

// v2 route with enhanced functionality
app.HandlerFunc(http.MethodGet, "v2", "/widgets", api.v2Query, authen, ruleAny)
```

### 3.15 API Documentation

Good API documentation is essential for developers using your service. Our framework doesn't prescribe a specific documentation tool, but we recommend using OpenAPI (Swagger) specifications.

You can define an OpenAPI specification for your service and generate documentation from it. For example:

```yaml
openapi: 3.0.0
info:
  title: Widget API
  version: 1.0.0
  description: API for managing widgets
paths:
  /v1/widgets:
    get:
      summary: List widgets
      parameters:
        - name: page
          in: query
          schema:
            type: integer
        - name: rows
          in: query
          schema:
            type: integer
        # ... other parameters
      responses:
        "200":
          description: A list of widgets
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      $ref: "#/components/schemas/Widget"
                  total:
                    type: integer
                  page:
                    type: integer
                  rows:
                    type: integer
                  pages:
                    type: integer
        "401":
          description: Unauthorized
        "500":
          description: Internal server error
    post:
      summary: Create a widget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/NewWidget"
      responses:
        "201":
          description: Widget created
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Widget"
        "400":
          description: Invalid input
        "401":
          description: Unauthorized
        "500":
          description: Internal server error
  # ... other paths
components:
  schemas:
    Widget:
      type: object
      properties:
        id:
          type: string
          format: uuid
        userID:
          type: string
          format: uuid
        name:
          type: string
        category:
          type: string
        description:
          type: string
        isActive:
          type: boolean
        CreatedAt:
          type: string
          format: date-time
        UpdatedAt:
          type: string
          format: date-time
    NewWidget:
      type: object
      required:
        - name
        - category
      properties:
        name:
          type: string
        category:
          type: string
        description:
          type: string
        isActive:
          type: boolean
    # ... other schemas
```

This specification can be converted to interactive documentation using tools like Swagger UI or ReDoc.

### 3.16 Testing API Endpoints

Testing API endpoints is crucial for ensuring they work correctly. Our framework provides utilities for testing API handlers:

```go
func TestWidgetAPI(t *testing.T) {
    // Create a test context
    ctx := context.Background()

    // Create mock dependencies
    log := logger.New()
    mockWidgetBus := &mocks.WidgetBusiness{}

    // Create the app with mock dependencies
    api := newApp(mockWidgetBus)

    // Set up mock expectations
    mockWidget := widgetbus.Widget{
        ID:          uuid.New(),
        UserID:      uuid.New(),
        Name:        name.MustParse("Test Widget"),
        Category:    category.MustParse("Test Category"),
        Description: "Test Description",
        IsActive:    true,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
    mockWidgetBus.On("QueryByID", mock.Anything, mockWidget.ID).Return(mockWidget, nil)

    // Create a test request
    r := httptest.NewRequest(http.MethodGet, "/widgets/"+mockWidget.ID.String(), nil)
    r = r.WithContext(ctx)

    // Add the widget to the context (simulating middleware)
    ctx = context.WithValue(r.Context(), widgetKey, mockWidget)
    r = r.WithContext(ctx)

    // Execute the handler
    resp := api.queryByID(ctx, nil, r)

    // Assert on the response
    appWidget, ok := resp.(Widget)
    require.True(t, ok)
    assert.Equal(t, mockWidget.ID.String(), appWidget.ID)
    assert.Equal(t, mockWidget.Name.String(), appWidget.Name)
    assert.Equal(t, mockWidget.Category.String(), appWidget.Category)
    assert.Equal(t, mockWidget.Description, appWidget.Description)
    assert.Equal(t, mockWidget.IsActive, appWidget.IsActive)

    // Verify mock expectations
    mockWidgetBus.AssertExpectations(t)
}
```

This test verifies that the `queryByID` handler correctly retrieves a widget and converts it to an API response.

You should also write integration tests that cover the entire API, from HTTP request to database and back:

```go
func TestWidgetAPI_Integration(t *testing.T) {
    // Set up test database
    db := dbtest.New(t, "TestWidgetAPI_Integration")

    // Set up test services
    log := logger.New()
    widgetStorer := widgetdb.NewStore(log, db.DB)
    widgetBus := widgetbus.NewBusiness(log, nil, nil, widgetStorer)

    // Set up test server
    mux := web.NewMux()
    widgetapp.Routes(mux, widgetapp.Config{
        Log:       log,
        WidgetBus: widgetBus,
    })

    // Create a test widget
    ctx := context.Background()
    userID := uuid.New()
    nw := widgetbus.NewWidget{
        UserID:      userID,
        Name:        name.MustParse("Test Widget"),
        Category:    category.MustParse("Test Category"),
        Description: "Test Description",
        IsActive:    true,
    }
    widget, err := widgetBus.Create(ctx, nw)
    require.NoError(t, err)

    // Test GET /widgets/{widget_id}
    req := httptest.NewRequest(http.MethodGet, "/v1/widgets/"+widget.ID.String(), nil)
    resp := httptest.NewRecorder()
    mux.ServeHTTP(resp, req)

    require.Equal(t, http.StatusOK, resp.Code)

    var respWidget Widget
    err = json.Unmarshal(resp.Body.Bytes(), &respWidget)
    require.NoError(t, err)

    assert.Equal(t, widget.ID.String(), respWidget.ID)
    assert.Equal(t, widget.Name.String(), respWidget.Name)
    assert.Equal(t, widget.Category.String(), respWidget.Category)
    assert.Equal(t, widget.Description, respWidget.Description)
    assert.Equal(t, widget.IsActive, respWidget.IsActive)
}
```

This test verifies that the entire API works correctly, from HTTP request to database and back.

### 3.17 Best Practices for API Design

When designing APIs, follow these best practices:

1. **Be Consistent**: Use consistent naming, URL structure, and response formats across all endpoints.
2. **Be Clear**: Use descriptive names for resources and fields. Avoid abbreviations and acronyms.
3. **Be Concise**: Keep URLs short and focused on the resource. Avoid redundant information.
4. **Be Flexible**: Support filtering, sorting, and pagination to allow clients to request exactly what they need.
5. **Be Secure**: Use HTTPS, require authentication, and validate all input.
6. **Be Documented**: Provide clear, comprehensive documentation for all endpoints.
7. **Be Versioned**: Use versioning to maintain backwards compatibility as your API evolves.
8. **Be Tested**: Write comprehensive tests for all endpoints.

Following these practices will help you create APIs that are easy to use, maintain, and extend.

### 3.18 Common Pitfalls to Avoid

When designing and implementing APIs, avoid these common pitfalls:

1. **Inconsistent Naming**: Using different naming conventions across endpoints (e.g., `snake_case` in one place and `camelCase` in another).
2. **Leaking Implementation Details**: Exposing database column names or internal identifiers in the API.
3. **Overly Complex URLs**: Creating deep, nested URL structures that are hard to understand and use.
4. **Missing Validation**: Failing to validate input, leading to unexpected behavior.
5. **Inconsistent Error Responses**: Using different error formats across endpoints.
6. **Hardcoded Dependencies**: Directly instantiating dependencies in handlers instead of using dependency injection.
7. **Missing Documentation**: Failing to document endpoints, parameters, and responses.
8. **Ignoring Content Negotiation**: Not handling different content types (e.g., JSON, XML).

Avoiding these pitfalls will help you create APIs that are robust, maintainable, and user-friendly.

### 3.19 Summary

In this chapter, we've covered:

1. **API Design Principles**: Resource-oriented design, consistent URL structure, HTTP method semantics
2. **URL Structure and Versioning**: Using consistent URL patterns and version prefixes
3. **HTTP Methods and CRUD Operations**: Mapping HTTP methods to operations
4. **Route Registration**: Registering routes in the `route.go` file
5. **Request Handling**: Extracting parameters from paths, queries, and bodies
6. **Response Formatting**: Formatting responses consistently
7. **Error Handling**: Using standardized error responses
8. **Authentication and Authorization**: Securing endpoints with middleware
9. **Pagination, Filtering, and Sorting**: Supporting flexible data retrieval
10. **Handler Implementation Pattern**: Following a consistent pattern for handlers
11. **Sub-Resources and Nested Routes**: Creating hierarchical API designs
12. **Batch Operations**: Processing multiple resources at once
13. **Query Parameters and API Flexibility**: Providing flexibility through parameters
14. **API Versioning Strategies**: Using URL-based versioning and other approaches
15. **API Documentation**: Using OpenAPI to document your API
16. **Testing API Endpoints**: Writing unit and integration tests
17. **Best Practices**: Following best practices for API design
18. **Common Pitfalls**: Avoiding common pitfalls in API implementation

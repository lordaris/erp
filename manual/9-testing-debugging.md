## 9. Testing & Debugging

Comprehensive testing and effective debugging are essential for building reliable, maintainable services. This chapter explores the strategies and tools our architectural framework uses for testing at different levels and debugging issues when they arise.

### 9.1 Testing Philosophy

Our testing approach is built on several core principles that guide how we verify our software's correctness:

1. **Test Pyramid**: We follow the test pyramid approach, with more unit tests than integration tests, and more integration tests than end-to-end tests. This approach provides a good balance between testing speed, coverage, and reliability.

2. **Test Isolation**: Tests should be isolated from each other and from external dependencies when possible. This ensures that test results are consistent and not affected by external factors.

3. **Test Realism**: While isolation is important, tests should also be realistic. Integration tests that interact with actual dependencies (like databases) provide confidence that the system works in real-world scenarios.

4. **Continuous Testing**: Tests should be run continuously, both during development and in CI/CD pipelines, to catch issues early.

5. **Test-Driven Development**: Writing tests before implementation helps clarify requirements and ensures that code is testable from the start.

These principles guide our testing strategies across all layers of the architecture.

### 9.2 Unit Testing

Unit tests focus on testing individual components in isolation, typically at the function or method level. Our framework provides tools and patterns for effective unit testing.

#### 9.2.1 Testing Business Logic

Business logic is the core of our application and requires thorough unit testing. Here's an example of a unit test for a business function:

```go
func TestCreateWidget(t *testing.T) {
    // Setup the test context
    ctx := context.Background()

    // Create mock dependencies
    mockStorer := &mocks.Storer{}
    mockUserBus := &mocks.UserBusiness{}
    delegate := delegate.New(logger.New())

    // Setup mock expectations
    userID := uuid.New()
    user := userbus.User{ID: userID, Enabled: true}
    mockUserBus.On("QueryByID", ctx, userID).Return(user, nil)

    widget := widgetbus.Widget{
        ID:          uuid.New(),
        UserID:      userID,
        Name:        name.MustParse("Test Widget"),
        Cost:        money.MustParse(10.99),
        Quantity:    quantity.MustParse(5),
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
    mockStorer.On("Create", ctx, mock.AnythingOfType("widgetbus.Widget")).Return(nil)

    // Create the business with mocked dependencies
    bus := widgetbus.NewBusiness(logger.New(), mockUserBus, delegate, mockStorer)

    // Create the new widget request
    newWidget := widgetbus.NewWidget{
        UserID:   userID,
        Name:     name.MustParse("Test Widget"),
        Cost:     money.MustParse(10.99),
        Quantity: quantity.MustParse(5),
    }

    // Call the function being tested
    createdWidget, err := bus.Create(ctx, newWidget)

    // Verify results
    require.NoError(t, err)
    assert.Equal(t, newWidget.Name, createdWidget.Name)
    assert.Equal(t, newWidget.Cost, createdWidget.Cost)
    assert.Equal(t, newWidget.Quantity, createdWidget.Quantity)

    // Verify mock expectations
    mockUserBus.AssertExpectations(t)
    mockStorer.AssertExpectations(t)
}
```

Key aspects of our unit testing approach:

1. **Mock Dependencies**: We use mocks (e.g., using the `testify/mock` package) to isolate the component being tested from its dependencies.

2. **Clear Test Setup**: Tests clearly set up their preconditions, execute the function being tested, and verify the results.

3. **Assertions**: We use assertion libraries like `testify/assert` and `testify/require` to make verifications clear and provide helpful error messages.

4. **Mock Verification**: Mock expectations are verified to ensure the component interacts correctly with its dependencies.

#### 9.2.2 Testing HTTP Handlers

HTTP handlers are tested by sending mock HTTP requests and verifying the responses:

```go
func TestQueryByID(t *testing.T) {
    // Setup context
    ctx := context.Background()

    // Create mock business
    mockBus := &mocks.WidgetBusiness{}

    // Setup test data
    widgetID := uuid.New()
    widget := widgetbus.Widget{
        ID:          widgetID,
        UserID:      uuid.New(),
        Name:        name.MustParse("Test Widget"),
        Cost:        money.MustParse(10.99),
        Quantity:    quantity.MustParse(5),
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }

    // Setup mock expectations
    mockBus.On("QueryByID", ctx, widgetID).Return(widget, nil)

    // Create the app with mocked business
    app := newApp(mockBus)

    // Create a request
    r := httptest.NewRequest(http.MethodGet, "/widgets/"+widgetID.String(), nil)
    r = r.WithContext(ctx)

    // Create a context with widget (simulating middleware)
    ctx = context.WithValue(r.Context(), widgetKey, widget)
    r = r.WithContext(ctx)

    // Create a response recorder
    w := httptest.NewRecorder()

    // Call the handler
    err := app.queryByID(ctx, w, r)

    // Verify results
    require.NoError(t, err)

    // Decode the response
    var response widgetapp.Widget
    err = json.NewDecoder(w.Body).Decode(&response)
    require.NoError(t, err)

    // Verify response content
    assert.Equal(t, widgetID.String(), response.ID)
    assert.Equal(t, widget.Name.String(), response.Name)
    assert.Equal(t, widget.Cost.Value(), response.Cost)
    assert.Equal(t, widget.Quantity.Value(), response.Quantity)

    // Verify mock expectations
    mockBus.AssertExpectations(t)
}
```

This test verifies that the handler correctly processes the request, interacts with the business layer, and returns the expected response.

### 9.3 Integration Testing

Integration tests verify that components work together correctly. Our framework provides tools for integration testing with actual dependencies.

#### 9.3.1 Database Integration Testing

Database integration tests verify that our store implementations correctly interact with the database:

```go
func TestWidgetStore_Integration(t *testing.T) {
    // Skip if short testing is enabled
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Create a test database with migrations applied
    db := dbtest.New(t, "TestWidgetStore_Integration")

    // Create the store
    store := widgetdb.NewStore(logger.New(), db.DB)

    // Create a test user (needed for foreign key)
    ctx := context.Background()
    user := userbus.NewUser{
        Name:     name.MustParse("Test User"),
        Email:    "test@example.com",
        Password: "password",
        Roles:    []role.Role{role.User},
    }
    createdUser, err := db.BusDomain.User.Create(ctx, user)
    require.NoError(t, err)

    // Test creating a widget
    widget := widgetbus.Widget{
        ID:          uuid.New(),
        UserID:      createdUser.ID,
        Name:        name.MustParse("Test Widget"),
        Cost:        money.MustParse(10.99),
        Quantity:    quantity.MustParse(5),
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }

    err = store.Create(ctx, widget)
    require.NoError(t, err)

    // Test querying the widget
    foundWidget, err := store.QueryByID(ctx, widget.ID)
    require.NoError(t, err)

    // Verify the widget was stored correctly
    assert.Equal(t, widget.ID, foundWidget.ID)
    assert.Equal(t, widget.UserID, foundWidget.UserID)
    assert.Equal(t, widget.Name.String(), foundWidget.Name.String())
    assert.Equal(t, widget.Cost.Value(), foundWidget.Cost.Value())
    assert.Equal(t, widget.Quantity.Value(), foundWidget.Quantity.Value())
}
```

Our framework provides the `dbtest` package to create isolated test databases with the correct schema for each test. This ensures tests run in a clean environment and don't interfere with each other.

#### 9.3.2 API Integration Testing

API integration tests verify that HTTP endpoints work correctly:

```go
func TestWidgetAPI_Integration(t *testing.T) {
    // Skip if short testing is enabled
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Create a test database
    db := dbtest.New(t, "TestWidgetAPI_Integration")

    // Create necessary business components
    log := logger.New()
    widgetStorer := widgetdb.NewStore(log, db.DB)
    delegate := delegate.New(log)
    widgetBus := widgetbus.NewBusiness(log, db.BusDomain.User, delegate, widgetStorer)

    // Create auth client for testing
    authClient, err := authclient.New("../../zarf/keys", "54bb2165-71e1-41a6-af3e-7da4a0e1e2c1")
    require.NoError(t, err)

    // Create API routes
    mux := web.NewMux()
    widgetapp.Routes(mux, widgetapp.Config{
        Log:        log,
        WidgetBus:  widgetBus,
        AuthClient: authClient,
    })

    // Create a test user
    ctx := context.Background()
    user := userbus.NewUser{
        Name:     name.MustParse("Test User"),
        Email:    "test@example.com",
        Password: "password",
        Roles:    []role.Role{role.User},
    }
    createdUser, err := db.BusDomain.User.Create(ctx, user)
    require.NoError(t, err)

    // Create a test token
    claims := authclient.Claims{
        Subject:   createdUser.ID.String(),
        Issuer:    "test",
        Audience:  []string{"test"},
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(time.Hour).Unix(),
        Roles:     []string{"USER"},
    }
    token, err := authClient.GenerateToken("54bb2165-71e1-41a6-af3e-7da4a0e1e2c1", claims)
    require.NoError(t, err)

    // Test creating a widget
    widgetInput := `{"name":"Test Widget","cost":10.99,"quantity":5}`
    req := httptest.NewRequest(http.MethodPost, "/v1/widgets", strings.NewReader(widgetInput))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)

    resp := httptest.NewRecorder()
    mux.ServeHTTP(resp, req)

    require.Equal(t, http.StatusOK, resp.Code)

    var createdWidget widgetapp.Widget
    err = json.Unmarshal(resp.Body.Bytes(), &createdWidget)
    require.NoError(t, err)

    // Verify the response
    assert.Equal(t, "Test Widget", createdWidget.Name)
    assert.Equal(t, 10.99, createdWidget.Cost)
    assert.Equal(t, 5, createdWidget.Quantity)

    // Test getting the widget
    req = httptest.NewRequest(http.MethodGet, "/v1/widgets/"+createdWidget.ID, nil)
    req.Header.Set("Authorization", "Bearer "+token)

    resp = httptest.NewRecorder()
    mux.ServeHTTP(resp, req)

    require.Equal(t, http.StatusOK, resp.Code)

    var fetchedWidget widgetapp.Widget
    err = json.Unmarshal(resp.Body.Bytes(), &fetchedWidget)
    require.NoError(t, err)

    // Verify the response
    assert.Equal(t, createdWidget.ID, fetchedWidget.ID)
    assert.Equal(t, createdWidget.Name, fetchedWidget.Name)
    assert.Equal(t, createdWidget.Cost, fetchedWidget.Cost)
    assert.Equal(t, createdWidget.Quantity, fetchedWidget.Quantity)
}
```

This test verifies that the entire API flow works correctly, from the HTTP layer through the business layer to the database and back.

### 9.4 End-to-End Testing

End-to-end tests verify that the entire system works correctly, including all services and external dependencies. Our framework supports containerized end-to-end testing using Docker Compose:

```go
func TestEndToEnd(t *testing.T) {
    // Skip if not running full E2E tests
    if !*runE2E {
        t.Skip("skipping E2E test")
    }

    // Start Docker Compose environment
    compose := docker.New(t)
    defer compose.Down()

    compose.Up("database", "auth", "sales")

    // Wait for services to be ready
    waitForService(t, "http://localhost:3000/v1/readiness")
    waitForService(t, "http://localhost:6000/v1/readiness")

    // Create an API client
    client := &http.Client{Timeout: 10 * time.Second}

    // Authenticate
    loginReq := `{"email":"admin@example.com","password":"gophers"}`
    req, err := http.NewRequest(http.MethodPost, "http://localhost:6000/v1/login", strings.NewReader(loginReq))
    require.NoError(t, err)

    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var loginResp struct {
        Token string `json:"token"`
    }
    err = json.NewDecoder(resp.Body).Decode(&loginResp)
    require.NoError(t, err)
    resp.Body.Close()

    // Create a widget
    widgetReq := `{"name":"E2E Widget","cost":15.99,"quantity":10}`
    req, err = http.NewRequest(http.MethodPost, "http://localhost:3000/v1/widgets", strings.NewReader(widgetReq))
    require.NoError(t, err)

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+loginResp.Token)

    resp, err = client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var widget struct {
        ID string `json:"id"`
    }
    err = json.NewDecoder(resp.Body).Decode(&widget)
    require.NoError(t, err)
    resp.Body.Close()

    // Query the widget
    req, err = http.NewRequest(http.MethodGet, "http://localhost:3000/v1/widgets/"+widget.ID, nil)
    require.NoError(t, err)

    req.Header.Set("Authorization", "Bearer "+loginResp.Token)

    resp, err = client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var fetchedWidget struct {
        ID       string  `json:"id"`
        Name     string  `json:"name"`
        Cost     float64 `json:"cost"`
        Quantity int     `json:"quantity"`
    }
    err = json.NewDecoder(resp.Body).Decode(&fetchedWidget)
    require.NoError(t, err)
    resp.Body.Close()

    // Verify the widget
    assert.Equal(t, widget.ID, fetchedWidget.ID)
    assert.Equal(t, "E2E Widget", fetchedWidget.Name)
    assert.Equal(t, 15.99, fetchedWidget.Cost)
    assert.Equal(t, 10, fetchedWidget.Quantity)
}

func waitForService(t *testing.T, url string) {
    client := &http.Client{Timeout: 1 * time.Second}
    maxAttempts := 30
    sleepInterval := 1 * time.Second

    for i := 0; i < maxAttempts; i++ {
        resp, err := client.Get(url)
        if err == nil && resp.StatusCode == http.StatusOK {
            resp.Body.Close()
            return
        }
        if resp != nil {
            resp.Body.Close()
        }

        t.Logf("Waiting for service %s (%d/%d)", url, i+1, maxAttempts)
        time.Sleep(sleepInterval)
    }

    t.Fatalf("Service %s did not become ready in time", url)
}
```

Our Docker Compose configuration includes all the necessary services for end-to-end testing:

```yaml
services:
  database:
    image: postgres:17.3
    container_name: database
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_PASSWORD=postgres
    volumes:
      - ./database-data:/var/lib/postgresql/data
      - ./pg_hba.conf:/etc/pg_hba.conf
    command: ["-c", "hba_file=/etc/pg_hba.conf"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h localhost -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    cpu_count: 2
    networks:
      sales-system-network:
        ipv4_address: 10.5.0.2

  init-migrate-seed:
    image: localhost//sales:0.0.1
    pull_policy: never
    container_name: init-migrate-seed
    restart: unless-stopped
    entrypoint: ["./admin", "migrate-seed"]
    environment:
      - SALES_DB_USER=postgres
      - SALES_DB_PASSWORD=postgres
      - SALES_DB_HOST=database
      - SALES_DB_DISABLE_TLS=true
    networks:
      sales-system-network:
        ipv4_address: 10.5.0.10
    deploy:
      restart_policy:
        condition: none
    depends_on:
      - database

  auth:
    image: localhost//auth:0.0.1
    pull_policy: never
    container_name: auth
    restart: unless-stopped
    ports:
      - "6000:6000"
      - "6010:6010"
    healthcheck:
      test:
        ["CMD-SHELL", "wget -qO- http://localhost:6000/v1/liveness || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 2
      start_period: 2s
    cpu_count: 2
    environment:
      - GOMAXPROCS=2
      - AUTH_DB_USER=postgres
      - AUTH_DB_PASSWORD=postgres
      - AUTH_DB_HOST=database
      - AUTH_DB_DISABLE_TLS=true
      - KUBERNETES_NAMESPACE=compose
      - KUBERNETES_NAME=sales-system
      - KUBERNETES_POD_IP=10.5.0.5
      - KUBERNETES_NODE_NAME=auth
    expose:
      - "6000:6000"
      - "6010:6010"
    networks:
      sales-system-network:
        ipv4_address: 10.5.0.5
    depends_on:
      - database

  sales:
    image: localhost//sales:0.0.1
    pull_policy: never
    container_name: sales
    restart: unless-stopped
    ports:
      - "3000:3000"
      - "3010:3010"
    environment:
      - GOMAXPROCS
      - GOGC=off
      - GOMEMLIMIT
      - SALES_DB_USER=postgres
      - SALES_DB_PASSWORD=postgres
      - SALES_DB_HOST=database
      - SALES_DB_DISABLE_TLS=true
      - SALES_AUTH_HOST=http://auth:6000
      - KUBERNETES_NAMESPACE
      - KUBERNETES_NAME
      - KUBERNETES_POD_IP
      - KUBERNETES_NODE_NAME
    healthcheck:
      test:
        ["CMD-SHELL", "wget -qO- http://localhost:3000/v1/liveness || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 2
      start_period: 2s
    networks:
      sales-system-network:
        ipv4_address: 10.5.0.15
    depends_on:
      - init-migrate-seed
```

This configuration sets up all the necessary services for end-to-end testing, including a PostgreSQL database, authentication service, and the service being tested.

### 9.5 Kubernetes Testing

For testing in Kubernetes environments, our framework provides tools for deploying to a local Kubernetes cluster using Kind:

```go
func TestKubernetes(t *testing.T) {
    // Skip if not running Kubernetes tests
    if !*runK8s {
        t.Skip("skipping Kubernetes test")
    }

    // Create a Kind cluster
    kindConfig := []byte(`
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  # Sales-Api
  - containerPort: 3000
    hostPort: 3000
  # Auth
  - containerPort: 6000
    hostPort: 6000
  # Postgres
  - containerPort: 5432
    hostPort: 5432
`)

    cluster := kind.NewCluster(t, kind.WithConfig(kindConfig))
    defer cluster.Delete()

    // Load Docker images into the cluster
    cluster.LoadDockerImage(t, "localhost//sales:0.0.1")
    cluster.LoadDockerImage(t, "localhost//auth:0.0.1")

    // Apply Kubernetes manifests
    kubectl := cluster.Kubectl(t)
    kubectl.Apply(t, "-f", "../../zarf/k8s/dev/database/")
    kubectl.Apply(t, "-f", "../../zarf/k8s/dev/auth/")
    kubectl.Apply(t, "-f", "../../zarf/k8s/dev/sales/")

    // Wait for services to be ready
    kubectl.WaitForDeployment(t, "auth", "sales-system")
    kubectl.WaitForDeployment(t, "sales", "sales-system")

    // Run the same tests as in the end-to-end test
    // ...
}
```

This test creates a Kind cluster, loads the necessary Docker images, applies Kubernetes manifests, and then runs tests against the deployed services.

### 9.6 Load Testing

Load testing verifies that services can handle expected and peak load. Our framework includes tools for load testing APIs:

```go
func TestLoad(t *testing.T) {
    // Skip if not running load tests
    if !*runLoad {
        t.Skip("skipping load test")
    }

    // Create a vegeta attacker
    rate := vegeta.Rate{Freq: 100, Per: time.Second} // 100 requests per second
    duration := 30 * time.Second                     // Run for 30 seconds
    targeter := vegeta.NewStaticTargeter(
        vegeta.Target{
            Method: "GET",
            URL:    "http://localhost:3000/v1/widgets",
            Header: http.Header{
                "Authorization": []string{"Bearer " + authToken},
            },
        },
    )

    attacker := vegeta.NewAttacker()

    // Run the attack
    var metrics vegeta.Metrics
    for res := range attacker.Attack(targeter, rate, duration, "Load Test") {
        metrics.Add(res)
    }
    metrics.Close()

    // Print the results
    reporter := vegeta.NewTextReporter(&metrics)
    reporter.Report(os.Stdout)

    // Verify performance requirements
    assert.Less(t, metrics.P99, 200*time.Millisecond, "99th percentile response time should be under 200ms")
    assert.Less(t, metrics.Mean, 50*time.Millisecond, "Mean response time should be under 50ms")
    assert.Equal(t, 0, metrics.Errors, "There should be no errors")
}
```

This test uses the Vegeta load testing tool to send a high rate of requests to the API and verify that it meets performance requirements.

### 9.7 Test Coverage and Quality

Our testing approach emphasizes not just test coverage but also test quality. Here are some strategies we use:

#### 9.7.1 Test Coverage

We use Go's built-in coverage tool to measure test coverage:

```bash
# Run tests with coverage and generate a coverage profile
go test -coverprofile=coverage.out ./...

# View coverage in the terminal
go tool cover -func=coverage.out

# Generate an HTML coverage report
go tool cover -html=coverage.out -o coverage.html
```

Our CI/CD pipeline enforces minimum coverage requirements:

```yaml
# GitHub Actions workflow for test coverage
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v2

      - name: Set up Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.20

      - name: Run tests with coverage
        run: go test -race -coverprofile=coverage.out -covermode=atomic ./...

      - name: Check coverage
        run: |
          total=$(go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+')
          if (( $(echo "$total < 80.0" | bc -l) )); then
            echo "Test coverage is below 80%: $total%"
            exit 1
          fi
```

#### 9.7.2 Mutation Testing

To ensure test quality, we use mutation testing tools like go-mutesting to verify that tests catch bugs:

```bash
# Run mutation testing
go-mutesting ./...
```

Mutation testing modifies the code in various ways (e.g., changing `==` to `!=`, `+` to `-`) and verifies that the tests catch these changes. This helps identify areas where tests might not be thorough enough.

#### 9.7.3 Fuzz Testing

For critical components, we use fuzz testing to find edge cases:

```go
func FuzzParseWidget(f *testing.F) {
    // Add seed values
    f.Add([]byte(`{"name":"Test","cost":10.0,"quantity":5}`))
    f.Add([]byte(`{"name":"","cost":-1,"quantity":0}`))

    // Run the fuzzer
    f.Fuzz(func(t *testing.T, data []byte) {
        var widget widgetapp.NewWidget
        err := json.Unmarshal(data, &widget)
        if err != nil {
            return // Invalid JSON is expected
        }

        // If unmarshaling succeeded, validation should work
        err = widget.Validate()

        // Either validation passes or we get a specific validation error
        if err != nil {
            assert.Contains(t, err.Error(), "validate:")
        }
    })
}
```

Fuzz testing generates random inputs to find unexpected behavior or crashes.

### 9.8 Debugging Tools and Techniques

Our framework provides several tools and techniques for debugging issues in development and production:

#### 9.8.1 Logging

Structured logging is essential for debugging. Our `logger` package provides consistent logging across all components:

```go
// Create a logger
log := logger.New()

// Log at different levels
log.Infow("operation started", "operation", "create", "user_id", userID)
log.Debugw("processing data", "data", data)
log.Errorw("operation failed", "operation", "create", "error", err)
```

The logs include important context like trace IDs, which help correlate logs across services:

```json
{
  "level": "info",
  "ts": "2023-01-01T12:00:00.000Z",
  "caller": "widgetbus/widgetbus.go:42",
  "msg": "operation started",
  "trace_id": "abc123",
  "operation": "create",
  "user_id": "45b5fbd3-755f-4379-8f07-a58d4a30fa2f"
}
```

#### 9.8.2 Metrics

Metrics provide insights into the behavior and performance of services. Our system integrates with Prometheus for metrics collection:

```go
// Create a metrics server
metricsServer := metrics.NewServer(log, 3010, 4020)

// Register metrics
errCount := expvar.NewInt("errors")
reqCount := expvar.NewInt("requests")
goroutines := expvar.NewInt("goroutines")

// Update metrics
reqCount.Add(1)
if err != nil {
    errCount.Add(1)
}
goroutines.Set(int64(runtime.NumGoroutine()))
```

These metrics are exposed via HTTP endpoints and collected by Prometheus for visualization in Grafana:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-conf
  namespace: sales-system
data:
  prometheus.yaml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      scrape_timeout: 10s
    scrape_configs:
      - job_name: "sales"
        metrics_path: '/metrics'
        scrape_interval: 5s
        scrape_timeout: 2s
        static_configs:
          - targets: [ "sales-service.sales-system.svc:4020" ]
```

#### 9.8.3 Tracing

Distributed tracing helps understand the flow of requests across services. Our system integrates with OpenTelemetry for tracing:

```go
// Initialize OpenTelemetry
provider, exporter, err := otel.Init(ctx, otel.Config{
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
    if err := exporter.Shutdown(ctx); err != nil {
        log.Errorw("shutdown", "ERROR", err)
    }
    provider.Shutdown(ctx)
}()

// Add spans to operations
ctx, span := otel.AddSpan(ctx, "business.widgetbus.create")
defer span.End()

// Add attributes to spans
span.SetAttributes(
    attribute.String("user.id", userID.String()),
    attribute.String("widget.name", widget.Name.String()),
)

// Track errors in spans
if err != nil {
    span.RecordError
```

## 6. Error Handling & Logging

Effective error handling and logging are essential for creating robust, maintainable services. This chapter explores the strategies and patterns our architectural framework uses to manage errors and provide visibility into system behavior.

### 6.1 Error Handling Philosophy

Our system follows a structured approach to error handling based on several key principles:

1. **Errors are values**: Errors are treated as regular values to be checked and handled, not exceptional cases to be caught.
2. **Context enrichment**: Errors are wrapped with additional context at each layer boundary.
3. **Typed errors**: Domain-specific errors are defined as variables for consistent checking.
4. **Client-friendly errors**: Errors are translated into appropriate HTTP status codes and messages for clients.
5. **Centralized handling**: Error handling is consistent across the system through shared utilities.

This philosophy ensures that errors are handled consistently and provide meaningful information for debugging while maintaining appropriate abstraction across layer boundaries.

### 6.2 Error Types and Categories

Our system defines several error categories to provide consistent handling and reporting:

```go
// Standard error codes for the system.
const (
    Internal          = "internal"            // Internal errors that shouldn't be exposed.
    NotFound          = "not_found"           // Resource was not found.
    InvalidArgument   = "invalid_argument"    // Invalid input parameter.
    FailedPrecondition = "failed_precondition" // Precondition failed.
    Unauthenticated   = "unauthenticated"     // Authentication failed.
    PermissionDenied  = "permission_denied"   // Permission denied.
    Conflict          = "conflict"            // Conflict with the current state.
    ResourceExhausted = "resource_exhausted"  // Resource has been exhausted.
    Canceled          = "canceled"            // Request canceled by the client.
    DeadlineExceeded  = "deadline_exceeded"   // Deadline expired before operation.
    RateLimitExceeded = "rate_limit_exceeded" // Rate limit exceeded.
)
```

These categories map to specific HTTP status codes when errors are returned to clients:

```go
// statusCodeMap maps error codes to HTTP status codes.
var statusCodeMap = map[string]int{
    Internal:          http.StatusInternalServerError,
    NotFound:          http.StatusNotFound,
    InvalidArgument:   http.StatusBadRequest,
    FailedPrecondition: http.StatusBadRequest,
    Unauthenticated:   http.StatusUnauthorized,
    PermissionDenied:  http.StatusForbidden,
    Conflict:          http.StatusConflict,
    ResourceExhausted: http.StatusTooManyRequests,
    Canceled:          http.StatusRequestTimeout,
    DeadlineExceeded:  http.StatusGatewayTimeout,
    RateLimitExceeded: http.StatusTooManyRequests,
}
```

This mapping ensures that clients receive appropriate HTTP status codes based on the type of error that occurred.

### 6.3 Domain-Specific Errors

Each domain defines its own error variables for common error cases:

```go
// Set of error variables for CRUD operations.
var (
    ErrNotFound     = errors.New("widget not found")
    ErrUserDisabled = errors.New("user disabled")
    ErrInvalidInput = errors.New("input not valid")
)
```

These errors provide a consistent way to check for specific error conditions:

```go
if err := b.storer.QueryByID(ctx, widgetID); err != nil {
    switch {
    case errors.Is(err, widgetbus.ErrNotFound):
        return Widget{}, fmt.Errorf("query: widgetID[%s]: %w", widgetID, err)
    default:
        return Widget{}, fmt.Errorf("query: %w", err)
    }
}
```

This approach ensures that error handling is consistent across the system and that specific error conditions can be identified and handled appropriately.

### 6.4 Error Wrapping and Context

Our system uses error wrapping to add context at each layer boundary:

```go
// Create adds a new widget to the system.
func (b *Business) Create(ctx context.Context, nw NewWidget) (Widget, error) {
    // Validate that the user exists and is enabled
    usr, err := b.userBus.QueryByID(ctx, nw.UserID)
    if err != nil {
        return Widget{}, fmt.Errorf("user.querybyid: %s: %w", nw.UserID, err)
    }

    if !usr.Enabled {
        return Widget{}, ErrUserDisabled
    }

    // Create the widget
    widget := Widget{
        ID:          uuid.New(),
        UserID:      nw.UserID,
        Name:        nw.Name,
        // Other fields...
    }

    if err := b.storer.Create(ctx, widget); err != nil {
        return Widget{}, fmt.Errorf("create: %w", err)
    }

    return widget, nil
}
```

Notice how errors from dependencies are wrapped with additional context:

```go
// Without wrapping
return Widget{}, err

// With wrapping
return Widget{}, fmt.Errorf("user.querybyid: %s: %w", nw.UserID, err)
```

This wrapping adds valuable context while preserving the original error for checking with `errors.Is()` or `errors.As()`.

### 6.5 API Error Responses

Errors need to be translated into appropriate HTTP responses. Our `errs` package handles this translation:

```go
// Error represents an error with additional context.
type Error struct {
    Code    string            `json:"code"`
    Message string            `json:"message"`
    Fields  map[string]string `json:"fields,omitempty"`
    status  int
    err     error
}

// Encode implements the encoder interface.
func (e *Error) Encode() ([]byte, string, error) {
    type response struct {
        Error Error `json:"error"`
    }

    resp := response{
        Error: *e,
    }

    data, err := json.Marshal(resp)
    if err != nil {
        return nil, "", err
    }

    return data, "application/json", nil
}

// New creates a new Error with the specified code and error.
func New(code string, err error) *Error {
    status, ok := statusCodeMap[code]
    if !ok {
        status = http.StatusInternalServerError
    }

    return &Error{
        Code:    code,
        Message: err.Error(),
        status:  status,
        err:     err,
    }
}

// NewWithStatus creates a new Error with the specified code, status, and error.
func NewWithStatus(status int, code string, err error) *Error {
    return &Error{
        Code:    code,
        Message: err.Error(),
        status:  status,
        err:     err,
    }
}
```

This package ensures that errors are translated into consistent JSON responses:

```json
{
  "error": {
    "code": "not_found",
    "message": "widget not found"
  }
}
```

It also handles field-specific errors for validation:

```go
// FieldErrors represents a collection of field-specific errors.
type FieldErrors map[string]error

// Add adds a field error.
func (fe *FieldErrors) Add(field string, err error) {
    if *fe == nil {
        *fe = make(map[string]error)
    }
    (*fe)[field] = err
}

// ToError returns a Error with field errors.
func (fe FieldErrors) ToError() *Error {
    fields := make(map[string]string)
    for field, err := range fe {
        fields[field] = err.Error()
    }

    return &Error{
        Code:    InvalidArgument,
        Message: "validation failed",
        Fields:  fields,
        status:  http.StatusBadRequest,
    }
}
```

This produces a response like:

```json
{
  "error": {
    "code": "invalid_argument",
    "message": "validation failed",
    "fields": {
      "name": "name is required",
      "quantity": "quantity must be positive"
    }
  }
}
```

### 6.6 Error Middleware

Errors are caught and handled by middleware to ensure consistent responses:

```go
// Errors handles errors coming out of the call chain.
func Errors() web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            if err := handler(ctx, w, r); err != nil {
                // Log the error.
                logger := web.GetLogger(ctx)
                logger.Errorw("ERROR", "trace_id", web.GetTraceID(ctx), "ERROR", err)

                // Handle different error types.
                var errsErr *errs.Error
                if errors.As(err, &errsErr) {
                    // Use the status and error response from the error.
                    web.Respond(ctx, w, errsErr, errsErr.Status())
                    return nil
                }

                // Handle unknown errors.
                er := errs.New(errs.Internal, fmt.Errorf("internal error: %w", err))
                web.Respond(ctx, w, er, er.Status())
                return nil
            }

            return nil
        }

        return h
    }

    return m
}
```

This middleware catches all errors, logs them, and translates them into appropriate HTTP responses.

### 6.7 Panic Recovery

To prevent service crashes, our system includes panic recovery middleware:

```go
// Panics recovers from panics and converts the panic to an error.
func Panics() web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
            defer func() {
                if rec := recover(); rec != nil {
                    // Log the stack trace.
                    trace := make([]byte, 4096)
                    n := runtime.Stack(trace, false)
                    trace = trace[:n]

                    // Log the panic.
                    logger := web.GetLogger(ctx)
                    logger.Errorw("PANIC", "trace_id", web.GetTraceID(ctx), "ERROR", rec, "TRACE", string(trace))

                    // Return an error to be handled by the error middleware.
                    err = fmt.Errorf("PANIC: %v", rec)
                }
            }()

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

This middleware recovers from panics, logs the stack trace, and converts the panic to an error that can be handled by the error middleware.

### 6.8 Structured Logging

Our system uses structured logging to provide context-rich logs that are easy to parse and analyze. The `logger` package handles this:

```go
// New constructs a new Logger with the specified level.
func New(options ...Option) *Logger {
    logger := &Logger{
        log: zap.New(
            zapcore.NewCore(
                zapcore.NewJSONEncoder(encoderConfig()),
                zapcore.AddSync(os.Stdout),
                zap.NewAtomicLevelAt(zap.InfoLevel),
            ),
            zap.WithCaller(true),
        ),
    }

    for _, option := range options {
        option(logger)
    }

    return logger
}

// Info logs at the info level.
func (l *Logger) Info(msg string, fields ...zapcore.Field) {
    l.log.Info(msg, fields...)
}

// Infow logs at the info level with key-value pairs.
func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
    l.log.Sugar().Infow(msg, keysAndValues...)
}
```

This provides structured logs like:

```json
{
  "level": "info",
  "ts": "2023-01-01T12:00:00.000Z",
  "caller": "app/handler.go:42",
  "msg": "request received",
  "trace_id": "abc123",
  "user_id": "45b5fbd3-755f-4379-8f07-a58d4a30fa2f",
  "method": "GET",
  "path": "/widgets/123"
}
```

### 6.9 Context-Aware Logging

To provide context for logs, our system includes context-aware logging middleware:

```go
// Logging logs request and response information.
func Logging(log *logger.Logger) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Add the logger to the context.
            ctx = context.WithValue(ctx, web.KeyLogger, log)

            // Generate a trace ID for the request.
            traceID := uuid.NewString()
            ctx = context.WithValue(ctx, web.KeyTraceID, traceID)

            // Log the request.
            log.Infow("request started", "trace_id", traceID, "method", r.Method, "path", r.URL.Path)

            // Create a response recorder to capture the response.
            rec := httptest.NewRecorder()

            // Call the handler.
            err := handler(ctx, rec, r)

            // Copy the response recorder to the response writer.
            for k, v := range rec.Header() {
                w.Header()[k] = v
            }
            w.WriteHeader(rec.Code)
            w.Write(rec.Body.Bytes())

            // Log the response.
            log.Infow("request completed",
                "trace_id", traceID,
                "method", r.Method,
                "path", r.URL.Path,
                "status", rec.Code,
                "bytes", rec.Body.Len(),
                "duration", time.Since(start),
            )

            return err
        }

        return h
    }

    return m
}
```

This middleware adds a logger and trace ID to the context, logs requests and responses, and provides a consistent way to access the logger from handlers.

### 6.10 Request Tracing

To understand request flow across services, our system includes distributed tracing:

```go
// Config is used to configure the OpenTelemetry SDK.
type Config struct {
    Exporter    string        // Endpoint for the exporter
    ServiceName string        // Name of the service
    Version     string        // Version of the service
    Probability float64       // Sampling rate
    Timeout     time.Duration // Timeout for shutting down the exporter
}

// Init initializes the OpenTelemetry SDK and returns the provider and exporter.
func Init(ctx context.Context, cfg Config) (*sdktrace.TracerProvider, sdktrace.SpanExporter, error) {
    // Create the exporter.
    exporter, err := otlptracegrpc.New(ctx,
        otlptracegrpc.WithEndpoint(cfg.Exporter),
        otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
    }

    // Create the trace provider.
    provider := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter),
        sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.Probability)),
        sdktrace.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceNameKey.String(cfg.ServiceName),
            semconv.ServiceVersionKey.String(cfg.Version),
        )),
    )

    // Set the global trace provider.
    otel.SetTracerProvider(provider)
    otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
        propagation.TraceContext{},
        propagation.Baggage{},
    ))

    return provider, exporter, nil
}
```

This is integrated with middleware to trace requests:

```go
// OTel adds OpenTelemetry tracing to requests.
func OTel() web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Extract the trace context from the request.
            ctx = otel.ExtractTraceContext(ctx, r)

            // Start a new span for the request.
            ctx, span := otel.AddSpan(ctx, "web.request")
            defer span.End()

            // Add attributes to the span.
            span.SetAttributes(
                attribute.String("method", r.Method),
                attribute.String("path", r.URL.Path),
            )

            // Call the handler.
            err := handler(ctx, w, r)

            // Record any error.
            if err != nil {
                span.RecordError(err)
                span.SetStatus(codes.Error, err.Error())
            }

            return err
        }

        return h
    }

    return m
}
```

This allows for tracing requests across service boundaries and provides valuable information for debugging and performance analysis.

### 6.11 Log Levels and Configuration

Our logging system supports multiple log levels to control verbosity:

```go
// SetLevel sets the log level.
func SetLevel(level string) Option {
    return func(l *Logger) {
        var zapLevel zapcore.Level
        switch strings.ToLower(level) {
        case "debug":
            zapLevel = zap.DebugLevel
        case "info":
            zapLevel = zap.InfoLevel
        case "warn":
            zapLevel = zap.WarnLevel
        case "error":
            zapLevel = zap.ErrorLevel
        default:
            zapLevel = zap.InfoLevel
        }

        l.log.Core().Enabled(zapLevel)
    }
}
```

This allows for configuring log levels at runtime:

```go
// From a service's main function
logLevel := cfg.LogLevel
log := logger.New(logger.SetLevel(logLevel))
```

### 6.12 Database Operation Logging

Database operations are logged for debugging and performance analysis:

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

This provides visibility into database operations for debugging and performance tuning.

### 6.13 Log Output Formats

Our logging system supports multiple output formats:

```go
// SetFormatter sets the log formatter.
func SetFormatter(format string) Option {
    return func(l *Logger) {
        var encoder zapcore.Encoder
        switch strings.ToLower(format) {
        case "json":
            encoder = zapcore.NewJSONEncoder(encoderConfig())
        case "console":
            encoder = zapcore.NewConsoleEncoder(encoderConfig())
        default:
            encoder = zapcore.NewJSONEncoder(encoderConfig())
        }

        core := zapcore.NewCore(
            encoder,
            zapcore.AddSync(os.Stdout),
            l.log.Core().(zapcore.LevelEnabler),
        )

        l.log = zap.New(core, zap.WithCaller(true))
    }
}
```

This allows for configuring log output formats based on the environment:

```go
// From a service's main function
logFormat := cfg.LogFormat
log := logger.New(logger.SetFormatter(logFormat))
```

### 6.14 Log Sampling

For high-volume services, our logging system supports log sampling to reduce log volume:

```go
// SetSampler sets the log sampler.
func SetSampler(fraction int) Option {
    return func(l *Logger) {
        sampler := zap.SamplerOption{
            Tick:   time.Second,
            First:  100,
            Thereafter: fraction,
        }

        l.log = l.log.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
            return zapcore.NewSamplerWithOptions(core, time.Second, 100, fraction)
        }))
    }
}
```

This allows for sampling logs in high-volume environments:

```go
// From a service's main function
logSampling := cfg.LogSampling
log := logger.New(logger.SetSampler(logSampling))
```

### 6.15 Audit Logging

For security-sensitive operations, our system includes audit logging:

```go
// AuditLogger logs security-relevant events.
type AuditLogger struct {
    log     *logger.Logger
    service string
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(log *logger.Logger, service string) *AuditLogger {
    return &AuditLogger{
        log:     log,
        service: service,
    }
}

// Log logs an audit event.
func (a *AuditLogger) Log(ctx context.Context, action string, user string, resource string, result string, metadata map[string]any) {
    fields := make([]interface{}, 0, 12+len(metadata)*2)
    fields = append(fields,
        "service", a.service,
        "action", action,
        "user", user,
        "resource", resource,
        "result", result,
        "timestamp", time.Now().UTC().Format(time.RFC3339),
    )

    if traceID := web.GetTraceID(ctx); traceID != "" {
        fields = append(fields, "trace_id", traceID)
    }

    for k, v := range metadata {
        fields = append(fields, k, v)
    }

    a.log.Infow("AUDIT", fields...)
}
```

This provides a consistent way to log security-relevant events:

```go
// From a handler
auditLogger.Log(ctx, "login", claims.Subject, "auth", "success", map[string]any{
    "ip_address": r.RemoteAddr,
    "user_agent": r.UserAgent(),
})
```

### 6.16 Log Aggregation

For distributed systems, log aggregation is essential. Our system supports sending logs to aggregation services:

```go
// SetOutput sets the log output.
func SetOutput(output string) Option {
    return func(l *Logger) {
        var sink zapcore.WriteSyncer
        switch strings.ToLower(output) {
        case "stdout":
            sink = zapcore.AddSync(os.Stdout)
        case "stderr":
            sink = zapcore.AddSync(os.Stderr)
        case "file":
            // Open a file for writing logs.
            file, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
            if err != nil {
                panic(err)
            }
            sink = zapcore.AddSync(file)
        default:
            sink = zapcore.AddSync(os.Stdout)
        }

        core := zapcore.NewCore(
            l.log.Core().Encoder(),
            sink,
            l.log.Core().(zapcore.LevelEnabler),
        )

        l.log = zap.New(core, zap.WithCaller(true))
    }
}
```

This can be extended to support sending logs to aggregation services like ELK, Loki, or CloudWatch.

### 6.17 Best Practices for Error Handling

When implementing error handling in our system, follow these best practices:

1. **Define Domain-Specific Errors**: Define error variables for common error cases in each domain.
2. **Wrap Errors with Context**: Add context at each layer boundary to provide a clear error trail.
3. **Use `errors.Is` and `errors.As`**: Use these functions to check for specific error types.
4. **Centralize Error Translation**: Use the `errs` package to translate errors to HTTP responses.
5. **Log Errors at the Appropriate Level**: Log errors at the appropriate level based on severity.
6. **Include Relevant Context**: Include relevant context in error messages, like IDs and operations.
7. **Don't Expose Internal Errors**: Don't expose internal errors to clients, translate them to appropriate error codes.
8. **Handle All Errors**: Handle all errors, don't ignore them.
9. **Use Middleware for Common Error Handling**: Use middleware for common error handling patterns.
10. **Test Error Paths**: Test error paths in your code, not just the happy path.

### 6.18 Best Practices for Logging

When implementing logging in our system, follow these best practices:

1. **Use Structured Logging**: Use structured logging to provide context-rich logs.
2. **Include Correlation IDs**: Include trace IDs or correlation IDs in logs to trace requests.
3. **Log at the Appropriate Level**: Use the appropriate log level for each message.
4. **Log Request and Response Information**: Log request and response information for debugging.
5. **Include Timestamps**: Include timestamps in logs for time-based analysis.
6. **Sanitize Sensitive Information**: Don't log sensitive information like passwords or tokens.
7. **Use Consistent Log Formats**: Use consistent log formats across services.
8. **Configure Log Levels**: Configure log levels based on the environment.
9. **Implement Log Rotation**: Implement log rotation for file-based logs.
10. **Monitor Log Storage**: Monitor log storage and implement retention policies.

### 6.19 Common Pitfalls to Avoid

When implementing error handling and logging, avoid these common pitfalls:

1. **Ignoring Errors**: Never ignore errors, always check and handle them.
2. **Exposing Internal Errors**: Don't expose internal errors to clients, translate them to appropriate error codes.
3. **Logging Sensitive Information**: Don't log sensitive information like passwords or tokens.
4. **Excessive Logging**: Don't log excessively, use appropriate log levels.
5. **Missing Context**: Don't log without context, include relevant information.
6. **Inconsistent Error Handling**: Don't handle errors inconsistently across the system.
7. **Returning Incorrect Status Codes**: Don't return incorrect HTTP status codes for errors.
8. **Swallowing Errors**: Don't swallow errors, always propagate them up the call stack.
9. **Using Panics for Normal Errors**: Don't use panics for normal error conditions, only for truly exceptional cases.
10. **Logging Without Structure**: Don't log without structure, use structured logging.

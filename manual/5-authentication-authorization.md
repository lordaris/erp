## 5. Authentication & Authorization

Authentication and authorization are foundational security components in any modern application. This chapter explains how our architectural framework implements these critical security features to protect resources and ensure users have appropriate access.

### 5.1 Authentication and Authorization Overview

In our architecture, authentication and authorization are carefully separated concerns that work together to secure the system:

- **Authentication (AuthN)**: Verifies the identity of a user or service ("Who are you?")
- **Authorization (AuthZ)**: Determines if a user has permission to access a resource ("What can you do?")

This separation allows for greater flexibility, as authentication mechanisms can evolve independently of authorization policies. Our system implements both concepts using industry best practices, including:

1. **Token-based Authentication**: Using JWT (JSON Web Tokens) for stateless authentication
2. **Role-based Access Control (RBAC)**: Assigning permissions based on user roles
3. **Resource-based Authorization**: Checking if a user has permission to access specific resources
4. **Policy-based Authorization**: Using declarative policies to define authorization rules

Let's explore each component in detail.

### 5.2 JWT-based Authentication

Our system uses JWT (JSON Web Tokens) for authentication. JWTs provide a secure, stateless mechanism for verifying user identity across service boundaries. They contain digitally signed claims about the user, eliminating the need for session storage on the server.

#### Token Structure

A JWT consists of three parts, separated by dots:

1. **Header**: Specifies the token type and signing algorithm
2. **Payload**: Contains claims about the user
3. **Signature**: Ensures the token hasn't been tampered with

Our JWTs include the following claims:

```json
{
  "sub": "45b5fbd3-755f-4379-8f07-a58d4a30fa2f", // User ID
  "name": "John Doe", // User name
  "email": "john@example.com", // User email
  "roles": ["USER"], // User roles
  "exp": 1678921834, // Expiration time
  "iat": 1678918234, // Issued at time
  "iss": "your-service.com", // Issuer
  "aud": "your-service.com" // Audience
}
```

These claims provide essential information about the user for both authentication and authorization.

#### Token Management

Token management is handled by the `authclient` package, which provides functions for generating, validating, and parsing JWTs:

```go
// New constructs a new Auth for use.
func New(keyFolderPath string, activeKID string) (*Client, error) {
    if keyFolderPath == "" || activeKID == "" {
        return nil, errors.New("keyFolderPath and activeKID are required")
    }

    // Load the private and public keys needed for token generation and verification.
    ks := keystore.New()
    if err := ks.LoadKeys(os.DirFS(keyFolderPath), activeKID); err != nil {
        return nil, fmt.Errorf("loading keys: %w", err)
    }

    return &Client{
        keystore: ks,
        method:   jwa.RS256,
        parser:   jwt.NewParser(jwt.WithValidate(true)),
    }, nil
}

// GenerateToken generates a JWT for the specified user.
func (c *Client) GenerateToken(kid string, claims Claims) (string, error) {
    // Get the private key for signing the token.
    privateKey, err := c.keystore.PrivateKey(kid)
    if err != nil {
        return "", fmt.Errorf("private key: %w", err)
    }

    token, err := jwt.NewBuilder().
        JwtID(uuid.NewString()). // Assign a unique identifier to the token.
        Issuer(claims.Issuer).
        Subject(claims.Subject).
        Audience(claims.Audience).
        IssuedAt(claims.IssuedAt).
        Expiration(claims.ExpiresAt).
        NotBefore(claims.IssuedAt).
        Claim("roles", claims.Roles).
        Build()
    if err != nil {
        return "", fmt.Errorf("build: %w", err)
    }

    // Sign the token with the specified algorithm and private key.
    signed, err := jwt.Sign(token, jwt.WithKey(c.method, privateKey))
    if err != nil {
        return "", fmt.Errorf("sign: %w", err)
    }

    return string(signed), nil
}

// ValidateToken validates a JWT and returns the claims.
func (c *Client) ValidateToken(tokenStr string) (Claims, error) {
    var claims Claims

    token, err := c.parser.Parse([]byte(tokenStr), jwt.WithValidate(true))
    if err != nil {
        return Claims{}, fmt.Errorf("parse: %w", err)
    }

    // Extract the key id used to sign the token.
    var kid string
    if header, ok := token.ProtectedHeaders().Get("kid"); ok {
        kid, _ = header.(string)
    }
    if kid == "" {
        return Claims{}, errors.New("kid missing from header")
    }

    // Get the public key for validating the token.
    publicKey, err := c.keystore.PublicKey(kid)
    if err != nil {
        return Claims{}, fmt.Errorf("public key: %w", err)
    }

    // Verify the token signature is valid.
    if err := jwt.Verify(token, jwt.WithKey(c.method, publicKey)); err != nil {
        return Claims{}, fmt.Errorf("verify: %w", err)
    }

    // Extract the claims from the token.
    if err := token.DecodeClaims(&claims); err != nil {
        return Claims{}, fmt.Errorf("decode: %w", err)
    }

    return claims, nil
}
```

These functions handle the cryptographic operations needed to securely generate and validate tokens.

#### Key Management

Key management is handled by the `keystore` package, which manages the cryptographic keys used to sign and verify JWTs:

```go
// New constructs a KeyStore for use.
func New() *KeyStore {
    return &KeyStore{
        privateKeys: make(map[string]crypto.PrivateKey),
        publicKeys:  make(map[string]crypto.PublicKey),
    }
}

// LoadKeys loads the private and public keys from the specified folder.
func (ks *KeyStore) LoadKeys(fsys fs.FS, activeKID string) error {
    privatePEM, err := fs.ReadFile(fsys, activeKID+".pem")
    if err != nil {
        return fmt.Errorf("reading private key file: %w", err)
    }

    privateKey, err := jwt.ParsePrivateKey(privatePEM)
    if err != nil {
        return fmt.Errorf("parsing private key: %w", err)
    }

    publicPEM, err := fs.ReadFile(fsys, activeKID+".pub")
    if err != nil {
        return fmt.Errorf("reading public key file: %w", err)
    }

    publicKey, err := jwt.ParsePublicKey(publicPEM)
    if err != nil {
        return fmt.Errorf("parsing public key: %w", err)
    }

    ks.privateKeys[activeKID] = privateKey
    ks.publicKeys[activeKID] = publicKey

    return nil
}
```

This approach allows for key rotation by specifying a new active key ID, while still being able to validate tokens signed with previous keys.

### 5.3 Authentication Middleware

Authentication is enforced through middleware that validates tokens and sets user information in the request context. The `mid.Authenticate` middleware handles this process:

```go
// Authenticate validates a JWT from the `Authorization` header.
func Authenticate(client *authclient.Client) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Extract the token from the Authorization header.
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                    fmt.Errorf("authentication required"))
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                    fmt.Errorf("expected Bearer authentication"))
            }

            // Validate the token.
            claims, err := client.ValidateToken(parts[1])
            if err != nil {
                return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                    fmt.Errorf("invalid token: %w", err))
            }

            // Add the claims to the context.
            ctx = context.WithValue(ctx, auth.Key, claims)

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

This middleware extracts the JWT from the Authorization header, validates it, and adds the claims to the request context for use by downstream handlers.

The claims can then be accessed by handlers using the `auth.GetClaims` function:

```go
// GetClaims extracts the claims from the context.
func GetClaims(ctx context.Context) (authclient.Claims, error) {
    claims, ok := ctx.Value(Key).(authclient.Claims)
    if !ok {
        return authclient.Claims{}, errors.New("claims missing from context")
    }
    return claims, nil
}
```

This approach ensures that all authenticated endpoints have access to the user's identity and roles.

### 5.4 Role-Based Access Control (RBAC)

Role-based access control (RBAC) is used to determine if a user has permission to access a resource based on their roles. Our system defines roles as part of the user's JWT claims:

```json
{
  "sub": "45b5fbd3-755f-4379-8f07-a58d4a30fa2f",
  "roles": ["USER", "ADMIN"],
  "exp": 1678921834,
  "iat": 1678918234,
  "iss": "your-service.com",
  "aud": "your-service.com"
}
```

Roles are defined as constants in the `role` package:

```go
// The set of roles that can be used.
var (
    Admin = newRole("ADMIN")
    User  = newRole("USER")
)
```

The `auth` package provides functions for checking if a user has a specific role:

```go
// HasRole checks if the claims contain the specified role.
func (c Claims) HasRole(role string) bool {
    for _, r := range c.Roles {
        if r == role {
            return true
        }
    }
    return false
}
```

Role-based authorization is enforced through middleware that checks if the user has the required role:

```go
// Authorize validates that a user has at least one of the required roles.
func Authorize(client *authclient.Client, rule string) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Get the claims from the context.
            claims, err := auth.GetClaims(ctx)
            if err != nil {
                return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                    fmt.Errorf("claims missing: %w", err))
            }

            // Apply the rule.
            switch rule {
            case auth.RuleAdmin:
                if !claims.HasRole("ADMIN") {
                    return errs.NewWithStatus(http.StatusForbidden, errs.PermissionDenied,
                        fmt.Errorf("admin role required"))
                }

            case auth.RuleUserOnly:
                if !claims.HasRole("USER") {
                    return errs.NewWithStatus(http.StatusForbidden, errs.PermissionDenied,
                        fmt.Errorf("user role required"))
                }

            case auth.RuleAny:
                // No specific role required, any authenticated user can access.

            default:
                return errs.New(errs.Internal, fmt.Errorf("unknown authorization rule: %s", rule))
            }

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

This middleware checks if the user has the required role and returns an error if they don't.

### 5.5 Resource-Based Authorization

For more fine-grained control, our system also supports resource-based authorization, which checks if a user has permission to access a specific resource. This is implemented through resource-specific middleware:

```go
// AuthorizeWidget checks if the user has permission to access a widget.
func AuthorizeWidget(client *authclient.Client, widgetBus *widgetbus.Business) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Extract widget ID from the request.
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

            // Retrieve the widget from the database.
            widget, err := widgetBus.QueryByID(ctx, id)
            if err != nil {
                switch {
                case errors.Is(err, widgetbus.ErrNotFound):
                    return errs.NewWithStatus(http.StatusNotFound, errs.NotFound,
                        fmt.Errorf("widget not found: %w", err))
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
            if claims.HasRole("ADMIN") {
                ctx = context.WithValue(ctx, widgetKey, widget)
                return handler(ctx, w, r)
            }

            // If you are the owner, you are authorized.
            if widget.UserID.String() == claims.Subject {
                ctx = context.WithValue(ctx, widgetKey, widget)
                return handler(ctx, w, r)
            }

            return errs.NewWithStatus(http.StatusForbidden, errs.PermissionDenied,
                fmt.Errorf("unauthorized access to widget: %s", id))
        }

        return h
    }

    return m
}
```

This middleware fetches the resource from the database and checks if the user has permission to access it. The resource is then added to the context for use by the handler.

The resource can be accessed using a resource-specific function:

```go
// GetWidget returns the widget from the context.
func GetWidget(ctx context.Context) (widgetbus.Widget, error) {
    v, ok := ctx.Value(widgetKey).(widgetbus.Widget)
    if !ok {
        return widgetbus.Widget{}, errors.New("widget value missing from context")
    }
    return v, nil
}
```

This approach allows for fine-grained control over resource access and ensures that handlers only need to focus on business logic, not authorization checks.

### 5.6 Policy-based Authorization

For more complex authorization scenarios, our system can be extended with policy-based authorization using the Open Policy Agent (OPA) and Rego language. This approach allows for declarative authorization policies that can be updated without changing code.

First, we define policies using the Rego language:

```rego
package authz

# Default deny
default allow = false

# Allow admin access to all resources
allow {
    input.roles[_] == "ADMIN"
}

# Allow users to access their own widgets
allow {
    input.action == "read"
    input.resource == "widget"
    input.roles[_] == "USER"
    input.user_id == input.widget.user_id
}

# Allow users to create widgets
allow {
    input.action == "create"
    input.resource == "widget"
    input.roles[_] == "USER"
}

# Allow users to update their own widgets
allow {
    input.action == "update"
    input.resource == "widget"
    input.roles[_] == "USER"
    input.user_id == input.widget.user_id
}

# Allow users to delete their own widgets
allow {
    input.action == "delete"
    input.resource == "widget"
    input.roles[_] == "USER"
    input.user_id == input.widget.user_id
}
```

Then, we integrate OPA with our system using the `auth` package:

```go
// NewPolicyEngine creates a new OPA policy engine.
func NewPolicyEngine(policies []byte) (*PolicyEngine, error) {
    engine := opa.New(opa.Options{})

    if err := engine.SetPolicy(policies); err != nil {
        return nil, fmt.Errorf("set policy: %w", err)
    }

    return &PolicyEngine{
        engine: engine,
    }, nil
}

// Authorize checks if the user is authorized to perform the action on the resource.
func (p *PolicyEngine) Authorize(ctx context.Context, input map[string]interface{}) (bool, error) {
    result, err := p.engine.Eval(ctx, opa.EvalOptions{
        Input: input,
        Query: "data.authz.allow",
    })
    if err != nil {
        return false, fmt.Errorf("eval: %w", err)
    }

    if result.Undefined {
        return false, nil
    }

    allowed, ok := result.Result.(bool)
    if !ok {
        return false, fmt.Errorf("unexpected result type: %T", result.Result)
    }

    return allowed, nil
}
```

This can then be used in middleware to enforce policies:

```go
// AuthorizePolicy checks if the user is authorized according to the policy.
func AuthorizePolicy(client *authclient.Client, policyEngine *auth.PolicyEngine, action, resource string) web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Get the claims from the context.
            claims, err := auth.GetClaims(ctx)
            if err != nil {
                return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                    fmt.Errorf("claims missing: %w", err))
            }

            // Create the input for policy evaluation.
            input := map[string]interface{}{
                "action":   action,
                "resource": resource,
                "user_id":  claims.Subject,
                "roles":    claims.Roles,
            }

            // Add resource-specific data to the input, if available.
            if widget, err := GetWidget(ctx); err == nil {
                input["widget"] = map[string]interface{}{
                    "id":      widget.ID.String(),
                    "user_id": widget.UserID.String(),
                }
            }

            // Check if the user is authorized.
            allowed, err := policyEngine.Authorize(ctx, input)
            if err != nil {
                return errs.New(errs.Internal, fmt.Errorf("authorize: %w", err))
            }

            if !allowed {
                return errs.NewWithStatus(http.StatusForbidden, errs.PermissionDenied,
                    fmt.Errorf("unauthorized access to %s: %s", resource, action))
            }

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

This approach allows for more complex authorization rules that can depend on resource attributes, user attributes, and contextual information.

### 5.7 Login and Token Generation

The login process generates a JWT for the user after successful authentication. This is handled by the `authapp` package:

```go
// login authenticates a user and returns a JWT.
func (a *app) login(ctx context.Context, r *http.Request) web.Encoder {
    var app LoginRequest
    if err := web.Decode(r, &app); err != nil {
        return errs.New(errs.InvalidArgument, err)
    }

    // Authenticate the user with email and password.
    user, err := a.userBus.Authenticate(ctx, app.Email, app.Password)
    if err != nil {
        switch {
        case errors.Is(err, userbus.ErrAuthenticationFailure):
            return errs.NewWithStatus(http.StatusUnauthorized, errs.Unauthenticated,
                fmt.Errorf("authentication failed"))
        default:
            return errs.New(errs.Internal, fmt.Errorf("authenticate: %w", err))
        }
    }

    // Generate a JWT for the user.
    tkn, err := a.createToken(user)
    if err != nil {
        return errs.New(errs.Internal, fmt.Errorf("create token: %w", err))
    }

    return LoginResponse{
        Token: tkn,
        User: User{
            ID:    user.ID.String(),
            Name:  user.Name.String(),
            Email: user.Email,
            Roles: user.Roles,
        },
    }
}

// createToken generates a JWT for the user.
func (a *app) createToken(user userbus.User) (string, error) {
    // Create claims for the token.
    claims := authclient.Claims{
        Subject:   user.ID.String(),
        Issuer:    "your-service.com",
        Audience:  []string{"your-service.com"},
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(8 * time.Hour).Unix(),
        Roles:     role.ParseToString(user.Roles),
    }

    // Generate the token.
    tkn, err := a.authClient.GenerateToken(a.authClient.ActiveKID(), claims)
    if err != nil {
        return "", fmt.Errorf("generate token: %w", err)
    }

    return tkn, nil
}
```

This process involves:

1. Authenticating the user with email and password
2. Creating JWT claims based on the user's identity and roles
3. Signing the claims to create a JWT
4. Returning the JWT to the client

### 5.8 Password Management

Secure password management is a critical aspect of authentication. Our system uses bcrypt for password hashing and verification:

```go
// Authenticate verifies a user's password.
func (b *Business) Authenticate(ctx context.Context, email, password string) (User, error) {
    ctx, span := otel.AddSpan(ctx, "business.userbus.authenticate")
    defer span.End()

    // Get the user by email.
    user, err := b.storer.QueryByEmail(ctx, email)
    if err != nil {
        return User{}, fmt.Errorf("query by email: %w", err)
    }

    // Compare the provided password with the stored hash.
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
        return User{}, fmt.Errorf("authenticate: %w", ErrAuthenticationFailure)
    }

    return user, nil
}

// HashPassword hashes a password for storage.
func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", fmt.Errorf("hashing password: %w", err)
    }

    return string(hash), nil
}
```

This approach ensures that passwords are never stored in plaintext and that they are securely verified during authentication.

### 5.9 User Management

User management in our system involves creating, updating, and disabling users. The `userbus` package handles these operations:

```go
// Create adds a new user to the system.
func (b *Business) Create(ctx context.Context, nu NewUser) (User, error) {
    ctx, span := otel.AddSpan(ctx, "business.userbus.create")
    defer span.End()

    hash, err := HashPassword(nu.Password)
    if err != nil {
        return User{}, fmt.Errorf("hash password: %w", err)
    }

    now := time.Now()

    usr := User{
        ID:           uuid.New(),
        Name:         nu.Name,
        Email:        nu.Email,
        PasswordHash: hash,
        Roles:        nu.Roles,
        Department:   nu.Department,
        Enabled:      true,
        CreatedAt:  now,
        UpdatedAt:  now,
    }

    if err := b.storer.Create(ctx, usr); err != nil {
        return User{}, fmt.Errorf("create: %w", err)
    }

    b.dispatchUserCreated(ctx, usr)

    return usr, nil
}

// Update modifies information about a user.
func (b *Business) Update(ctx context.Context, user User, uu UpdateUser) (User, error) {
    ctx, span := otel.AddSpan(ctx, "business.userbus.update")
    defer span.End()

    if uu.Name != nil {
        user.Name = *uu.Name
    }

    if uu.Email != nil {
        user.Email = *uu.Email
    }

    if uu.Password != nil {
        hash, err := HashPassword(*uu.Password)
        if err != nil {
            return User{}, fmt.Errorf("hash password: %w", err)
        }
        user.PasswordHash = hash
    }

    if uu.Roles != nil {
        user.Roles = *uu.Roles
    }

    if uu.Department != nil {
        user.Department = *uu.Department
    }

    if uu.Enabled != nil {
        user.Enabled = *uu.Enabled
    }

    user.UpdatedAt = time.Now()

    if err := b.storer.Update(ctx, user); err != nil {
        return User{}, fmt.Errorf("update: %w", err)
    }

    b.dispatchUserUpdated(ctx, user)

    return user, nil
}

// Delete removes a user from the system.
func (b *Business) Delete(ctx context.Context, user User) error {
    ctx, span := otel.AddSpan(ctx, "business.userbus.delete")
    defer span.End()

    if err := b.storer.Delete(ctx, user); err != nil {
        return fmt.Errorf("delete: %w", err)
    }

    b.dispatchUserDeleted(ctx, user)

    return nil
}
```

These operations ensure that users are properly managed throughout their lifecycle, from creation to deletion.

### 5.10 Security Best Practices

Our authentication and authorization system implements several security best practices:

#### Token Security

1. **Short-lived Tokens**: Tokens expire after a configurable period (e.g., 8 hours)
2. **Asymmetric Cryptography**: Tokens are signed with RS256 (RSA + SHA-256)
3. **Token Validation**: Tokens are validated for authenticity, expiration, and issuer

#### Password Security

1. **Password Hashing**: Passwords are hashed using bcrypt with a appropriate cost factor
2. **Password Validation**: Password strength requirements are enforced
3. **Password Storage**: Passwords are never stored in plaintext

#### API Security

1. **HTTPS Enforcement**: All API endpoints require HTTPS
2. **Authentication Middleware**: All protected endpoints require valid authentication
3. **Authorization Middleware**: Access to resources is strictly controlled
4. **Input Validation**: All input is validated before processing

#### Security Headers

Our API also sets security headers to protect against common web vulnerabilities:

```go
// Secure adds security-related HTTP headers to the response.
func Secure() web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Add security headers.
            w.Header().Set("Content-Security-Policy", "default-src 'self'")
            w.Header().Set("X-Content-Type-Options", "nosniff")
            w.Header().Set("X-Frame-Options", "DENY")
            w.Header().Set("X-XSS-Protection", "1; mode=block")
            w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

These headers protect against common web vulnerabilities like XSS, CSRF, and clickjacking.

### 5.11 Testing Authentication and Authorization

Testing authentication and authorization is crucial for ensuring security. Our framework provides utilities for testing both components:

#### Testing Authentication

```go
func TestAuthenticate(t *testing.T) {
    // Create a test auth client with known keys.
    authClient, err := authclient.New("testdata/keys", "test-kid")
    require.NoError(t, err)

    // Create test claims.
    claims := authclient.Claims{
        Subject:   uuid.New().String(),
        Issuer:    "test-issuer",
        Audience:  []string{"test-audience"},
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(time.Hour).Unix(),
        Roles:     []string{"USER"},
    }

    // Generate a token.
    token, err := authClient.GenerateToken("test-kid", claims)
    require.NoError(t, err)

    // Create a test request with the token.
    r := httptest.NewRequest(http.MethodGet, "/", nil)
    r.Header.Set("Authorization", "Bearer "+token)

    // Create a test handler.
    handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
        // Get the claims from the context.
        gotClaims, err := auth.GetClaims(ctx)
        if err != nil {
            return err
        }

        // Verify the claims.
        assert.Equal(t, claims.Subject, gotClaims.Subject)
        assert.Equal(t, claims.Roles, gotClaims.Roles)

        return nil
    }

    // Create the middleware.
    middleware := mid.Authenticate(authClient)

    // Execute the middleware.
    w := httptest.NewRecorder()
    err = middleware(handler)(context.Background(), w, r)
    require.NoError(t, err)
}
```

#### Testing Authorization

```go
func TestAuthorize(t *testing.T) {
    // Create a test auth client with known keys.
    authClient, err := authclient.New("testdata/keys", "test-kid")
    require.NoError(t, err)

    // Create test claims with the USER role.
    claims := authclient.Claims{
        Subject:   uuid.New().String(),
        Issuer:    "test-issuer",
        Audience:  []string{"test-audience"},
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(time.Hour).Unix(),
        Roles:     []string{"USER"},
    }

    // Create a test context with the claims.
    ctx := context.WithValue(context.Background(), auth.Key, claims)

    // Create a test handler.
    handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
        return nil
    }

    // Create the middleware.
    middleware := mid.Authorize(authClient, auth.RuleUserOnly)

    // Create a test request.
    r := httptest.NewRequest(http.MethodGet, "/", nil)

    // Execute the middleware.
    w := httptest.NewRecorder()
    err = middleware(handler)(ctx, w, r)
    require.NoError(t, err)

    // Test with a role that shouldn't have access.
    claims.Roles = []string{"GUEST"}
    ctx = context.WithValue(context.Background(), auth.Key, claims)

    // Execute the middleware again.
    w = httptest.NewRecorder()
    err = middleware(handler)(ctx, w, r)
    require.Error(t, err)

    // Check that we got a permission denied error.
    var errsErr *errs.Error
    require.True(t, errors.As(err, &errsErr))
    assert.Equal(t, errs.PermissionDenied, errsErr.Code)
}
```

These tests verify that authentication and authorization are working correctly, ensuring that only authorized users can access protected resources.

### 5.12 OAuth Integration

Our system can be extended to support OAuth 2.0 for authentication with external providers like Google, GitHub, or Microsoft. This is implemented in the `oauthapp` package:

```go
// Config contains the configuration for OAuth providers.
type Config struct {
    Google struct {
        ClientID     string
        ClientSecret string
        RedirectURL  string
    }
    GitHub struct {
        ClientID     string
        ClientSecret string
        RedirectURL  string
    }
}

// App manages the set of APIs for OAuth access.
type app struct {
    log         *logger.Logger
    userBus     *userbus.Business
    authClient  *authclient.Client
    oauthConfig Config
    providers   map[string]*oauth2.Config
}

// newApp constructs an app for handling OAuth requests.
func newApp(log *logger.Logger, userBus *userbus.Business, authClient *authclient.Client, oauthConfig Config) *app {
    providers := make(map[string]*oauth2.Config)

    // Configure Google OAuth.
    providers["google"] = &oauth2.Config{
        ClientID:     oauthConfig.Google.ClientID,
        ClientSecret: oauthConfig.Google.ClientSecret,
        RedirectURL:  oauthConfig.Google.RedirectURL,
        Scopes:       []string{"profile", "email"},
        Endpoint:     google.Endpoint,
    }

    // Configure GitHub OAuth.
    providers["github"] = &oauth2.Config{
        ClientID:     oauthConfig.GitHub.ClientID,
        ClientSecret: oauthConfig.GitHub.ClientSecret,
        RedirectURL:  oauthConfig.GitHub.RedirectURL,
        Scopes:       []string{"user:email"},
        Endpoint:     github.Endpoint,
    }

    return &app{
        log:         log,
        userBus:     userBus,
        authClient:  authClient,
        oauthConfig: oauthConfig,
        providers:   providers,
    }
}

// login redirects the user to the OAuth provider's login page.
func (a *app) login(ctx context.Context, r *http.Request) web.Encoder {
    provider := web.Param(r, "provider")
    if provider == "" {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("missing provider"))
    }

    config, ok := a.providers[provider]
    if !ok {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("unknown provider: %s", provider))
    }

    // Generate a random state for CSRF protection.
    state := uuid.NewString()

    // Store the state in a cookie.
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        MaxAge:   int(time.Hour.Seconds()),
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    })

    // Redirect to the OAuth provider's login page.
    url := config.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusFound)

    return nil
}

// callback handles the OAuth callback from the provider.
func (a *app) callback(ctx context.Context, r *http.Request) web.Encoder {
    provider := web.Param(r, "provider")
    if provider == "" {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("missing provider"))
    }

    config, ok := a.providers[provider]
    if !ok {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("unknown provider: %s", provider))
    }

    // Get the state from the cookie.
    cookie, err := r.Cookie("oauth_state")
    if err != nil {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("missing oauth_state cookie"))
    }

    // Verify the state.
    if r.URL.Query().Get("state") != cookie.Value {
        return errs.NewWithStatus(http.StatusBadRequest, errs.InvalidArgument,
            fmt.Errorf("invalid state"))
    }

    // Exchange the code for a token.
    code := r.URL.Query().Get("code")
    token, err := config.Exchange(ctx, code)
    if err != nil {
        return errs.New(errs.Internal, fmt.Errorf("exchange: %w", err))
    }

    // Get the user's profile from the provider.
    client := config.Client(ctx, token)
    profileData, err := a.getUserProfile(provider, client)
    if err != nil {
        return errs.New(errs.Internal, fmt.Errorf("get user profile: %w", err))
    }

    // Find or create the user in our system.
    user, err := a.findOrCreateUser(ctx, provider, profileData)
    if err != nil {
        return errs.New(errs.Internal, fmt.Errorf("find or create user: %w", err))
    }

    // Generate a JWT for the user.
    tkn, err := a.createToken(user)
    if err != nil {
        return errs.New(errs.Internal, fmt.Errorf("create token: %w", err))
    }

    // Redirect to the frontend with the token.
    redirectURL := fmt.Sprintf("/oauth/success?token=%s", tkn)
    http.Redirect(w, r, redirectURL, http.StatusFound)

    return nil
}
```

This implementation supports OAuth 2.0 authentication with multiple providers, making it easy for users to log in with their existing accounts.

### 5.13 Secure Communication

For secure communication between services, our system supports mutual TLS (mTLS) authentication. This is implemented using the `tls` package:

```go
// Config for TLS configuration.
type TLSConfig struct {
    CertFile   string
    KeyFile    string
    CAFile     string
    ServerName string
}

// ConfigureTLS configures a TLS client for secure communication.
func ConfigureTLS(cfg TLSConfig) (*tls.Config, error) {
    // Load the client certificate and key.
    cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
    if err != nil {
        return nil, fmt.Errorf("load client cert: %w", err)
    }

    // Load the CA certificate.
    caCert, err := os.ReadFile(cfg.CAFile)
    if err != nil {
        return nil, fmt.Errorf("read ca cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("append ca cert: invalid PEM")
    }

    // Create the TLS configuration.
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        ServerName:   cfg.ServerName,
        MinVersion:   tls.VersionTLS12,
    }

    return tlsConfig, nil
}
```

This configuration ensures that services can communicate securely and verify each other's identity.

### 5.14 Rate Limiting and Brute Force Protection

To protect against brute force attacks, our system implements rate limiting on sensitive endpoints like login and token generation:

```go
// RateLimit limits the number of requests a client can make in a time period.
func RateLimit(limit int, window time.Duration) web.MidHandler {
    // Create a store for tracking client requests.
    store := cache.New(window, time.Minute)

    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Get the client's IP address.
            clientIP := r.RemoteAddr
            if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
                clientIP = strings.Split(forwardedFor, ",")[0]
            }

            // Get the current count for this client.
            key := fmt.Sprintf("%s:%s:%s", r.Method, r.URL.Path, clientIP)
            count, found := store.Get(key)
            if !found {
                store.Set(key, 1, window)
                return handler(ctx, w, r)
            }

            // Check if the client has exceeded the limit.
            if count.(int) >= limit {
                w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
                return errs.NewWithStatus(http.StatusTooManyRequests, errs.RateLimitExceeded,
                    fmt.Errorf("rate limit exceeded"))
            }

            // Increment the counter.
            store.Increment(key, 1)

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}
```

This middleware limits the number of requests a client can make to sensitive endpoints, protecting against brute force attacks.

### 5.15 Best Practices for Authentication and Authorization

When implementing authentication and authorization in our system, follow these best practices:

1. **Defense in Depth**: Implement multiple layers of security, not just a single point of defense.
2. **Principle of Least Privilege**: Grant users only the permissions they need, no more.
3. **Fail Securely**: When in doubt, deny access and provide clear error messages.
4. **Secure by Default**: Require authentication for all endpoints unless explicitly marked as public.
5. **Separation of Concerns**: Keep authentication and authorization logic separate from business logic.
6. **Strong Cryptography**: Use industry-standard algorithms and key lengths for cryptographic operations.
7. **Short Token Lifetimes**: Keep JWT expiration times short to minimize the impact of token theft.
8. **HTTPS Everywhere**: Require HTTPS for all API endpoints to prevent token interception.
9. **Input Validation**: Validate all input to prevent injection attacks.
10. **Audit Logging**: Log all authentication and authorization events for forensic analysis.

### 5.16 Common Pitfalls to Avoid

When implementing authentication and authorization, avoid these common pitfalls:

1. **Hardcoded Credentials**: Never hardcode credentials in source code or configuration files.
2. **Weak Passwords**: Enforce strong password policies to prevent dictionary attacks.
3. **Insecure Token Storage**: Store tokens securely on the client side, preferably in HTTP-only cookies.
4. **Insufficient Token Validation**: Validate all aspects of tokens, including signature, expiration, and issuer.
5. **Missing Authorization Checks**: Ensure every sensitive operation has appropriate authorization checks.
6. **Overreliance on Client-Side Validation**: Always validate on the server side, never trust client input.
7. **Verbose Error Messages**: Avoid leaking sensitive information in error messages.
8. **Lack of Rate Limiting**: Implement rate limiting on sensitive endpoints to prevent brute force attacks.
9. **Insecure Dependencies**: Keep dependencies up to date to avoid known vulnerabilities.
10. **Insufficient Testing**: Test both positive and negative cases for authentication and authorization.

### 5.17 Summary

In this chapter, we've covered:

1. **Authentication and Authorization Overview**: The foundational security concepts in our system.
2. **JWT-based Authentication**: Using JSON Web Tokens for stateless authentication.
3. **Authentication Middleware**: Validating tokens and setting user information in the request context.
4. **Role-Based Access Control (RBAC)**: Determining access based on user roles.
5. **Resource-Based Authorization**: Checking if a user has permission to access a specific resource.
6. **Policy-based Authorization**: Using declarative policies for complex authorization scenarios.
7. **Login and Token Generation**: Authenticating users and generating JWTs.
8. **Password Management**: Securely hashing and verifying passwords.
9. **User Management**: Creating, updating, and disabling users.
10. **Security Best Practices**: Implementing security best practices in our system.
11. **Testing Authentication and Authorization**: Verifying that security controls work correctly.
12. **OAuth Integration**: Supporting authentication with external providers.
13. **Secure Communication**: Using mutual TLS for service-to-service communication.
14. **Rate Limiting and Brute Force Protection**: Protecting against common attacks.
15. **Best Practices for Authentication and Authorization**: Guidelines for secure implementation.
16. **Common Pitfalls to Avoid**: Issues to watch out for in security implementation.

By implementing these security controls and following best practices, our system provides robust protection for sensitive resources while maintaining a good user experience. The separation of authentication and authorization concerns allows for flexible security policies that can adapt to changing requirements.

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

## 7. Deployment & Scaling

Deploying and scaling services effectively is crucial for building resilient, performant systems. This chapter explores the strategies and tools our architectural framework uses for containerization, orchestration, load balancing, and continuous integration/delivery (CI/CD).

### 7.1 Deployment Architecture Overview

Our deployment architecture follows cloud-native principles, emphasizing containerization, orchestration, and infrastructure as code. This approach provides several benefits:

1. **Consistency**: The same service runs identically across all environments
2. **Scalability**: Services can scale horizontally to handle increased load
3. **Isolation**: Services are isolated from each other and the underlying infrastructure
4. **Resilience**: The system can recover automatically from failures
5. **Observability**: The system provides comprehensive metrics, logs, and traces

The deployment architecture consists of several key components:

- **Containerization**: Services are packaged as Docker containers
- **Orchestration**: Kubernetes manages container deployment and scaling
- **Service Mesh**: Istio handles service-to-service communication
- **Configuration Management**: ConfigMaps and Secrets manage configuration
- **Observability**: Prometheus, Grafana, and Jaeger provide monitoring and tracing
- **CI/CD**: GitHub Actions or Jenkins handle continuous integration and delivery

These components work together to provide a robust, scalable deployment platform for our services.

### 7.2 Containerization with Docker

Docker containers are the fundamental building block of our deployment strategy. Each service is packaged as a Docker container, containing the service binary and all its dependencies.

#### Dockerfile for Services

Here's a typical Dockerfile for one of our services:

```dockerfile
# Build stage
FROM golang:1.20 AS build

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o service ./api/services/myservice

# Final stage
FROM alpine:3.18

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the build stage
COPY --from=build /app/service .
COPY --from=build /app/zarf/keys ./zarf/keys

# Run as non-root user
RUN addgroup -g 1000 app && \
    adduser -u 1000 -G app -h /app -D app && \
    chown -R app:app /app
USER app

# Set the entrypoint
ENTRYPOINT ["./service"]
```

This Dockerfile follows several best practices:

1. **Multi-stage builds**: The build stage compiles the code, while the final stage contains only the binary and necessary files
2. **Minimal base image**: Alpine Linux provides a small, secure base image
3. **Non-root user**: The container runs as a non-root user for security
4. **Dependency caching**: Dependencies are downloaded before copying the source code to leverage Docker's layer caching

#### Building and Pushing Docker Images

Docker images are built and pushed to a container registry as part of the CI/CD pipeline:

```bash
# Build the Docker image
docker build -t myregistry.example.com/myservice:${VERSION} .

# Push the Docker image to the registry
docker push myregistry.example.com/myservice:${VERSION}
```

This process ensures that each version of the service is available as a Docker image in the registry, ready to be deployed.

### 7.3 Kubernetes Deployment

Kubernetes is used to orchestrate the deployment of our containers. It provides several key features:

1. **Declarative configuration**: Infrastructure is defined as code
2. **Self-healing**: Failed containers are automatically restarted
3. **Scaling**: Services can be scaled horizontally to handle increased load
4. **Load balancing**: Traffic is automatically distributed across instances
5. **Service discovery**: Services can discover and communicate with each other

#### Kubernetes Manifests

Kubernetes resources are defined in YAML files called manifests. Here's a typical deployment manifest for one of our services:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
  namespace: default
  labels:
    app: myservice
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
  template:
    metadata:
      labels:
        app: myservice
    spec:
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:1.0.0
          ports:
            - containerPort: 3000
              name: http
          env:
            - name: DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: myservice-config
                  key: db-host
            - name: DB_USER
              valueFrom:
                secretKeyRef:
                  name: myservice-secrets
                  key: db-user
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: myservice-secrets
                  key: db-password
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          readinessProbe:
            httpGet:
              path: /v1/check/readiness
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /v1/check/liveness
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
```

This manifest defines a deployment with several important features:

1. **Replicas**: Three instances of the service are deployed for redundancy
2. **Container image**: The specific version of the service image to deploy
3. **Environment variables**: Configuration is provided through environment variables
4. **Resource limits**: CPU and memory resources are constrained
5. **Health checks**: Readiness and liveness probes ensure the service is healthy

#### Service Manifest

A Kubernetes Service is used to expose the deployment:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myservice
  namespace: default
  labels:
    app: myservice
spec:
  selector:
    app: myservice
  ports:
    - port: 80
      targetPort: http
      name: http
  type: ClusterIP
```

This service provides a stable network identity for the deployment, allowing other services to communicate with it.

#### Ingress Manifest

An Ingress resource is used to expose the service to the outside world:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myservice
  namespace: default
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
    - host: myservice.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: myservice
                port:
                  name: http
  tls:
    - hosts:
        - myservice.example.com
      secretName: myservice-tls
```

This Ingress resource defines how external traffic is routed to the service, including TLS configuration for HTTPS.

### 7.4 Configuration Management

Configuration is a critical aspect of deployment. Our system uses several mechanisms to manage configuration:

1. **Environment variables**: Basic configuration is provided through environment variables
2. **ConfigMaps**: Non-sensitive configuration is stored in Kubernetes ConfigMaps
3. **Secrets**: Sensitive configuration is stored in Kubernetes Secrets
4. **Feature flags**: Dynamic configuration is managed through feature flags

#### ConfigMap Example

ConfigMaps store non-sensitive configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: myservice-config
  namespace: default
data:
  db-host: postgres.database.svc.cluster.local
  log-level: info
  otel-endpoint: otel-collector.monitoring.svc.cluster.local:4317
```

#### Secret Example

Secrets store sensitive configuration:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: myservice-secrets
  namespace: default
type: Opaque
data:
  db-user: cG9zdGdyZXM= # base64 encoded "postgres"
  db-password: cGFzc3dvcmQ= # base64 encoded "password"
  jwt-key: ZXhhbXBsZS1rZXk= # base64 encoded "example-key"
```

#### Accessing Configuration in Services

Configuration is accessed in our services through environment variables:

```go
// Config for the service.
type Config struct {
    Web struct {
        APIHost         string        `conf:"default:0.0.0.0:3000"`
        DebugHost       string        `conf:"default:0.0.0.0:4000"`
        ReadTimeout     time.Duration `conf:"default:5s"`
        WriteTimeout    time.Duration `conf:"default:10s"`
        IdleTimeout     time.Duration `conf:"default:120s"`
        ShutdownTimeout time.Duration `conf:"default:20s"`
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
    Auth struct {
        KeysFolder string `conf:"default:zarf/keys/"`
        ActiveKID  string `conf:"default:54bb2165-71e1-41a6-af3e-7da4a0e1e2c1"`
    }
    Otel struct {
        ExporterEndpoint string        `conf:"default:localhost:4317"`
        ServiceName      string        `conf:"default:myservice"`
        ServiceVersion   string        `conf:"default:0.1.0"`
        Probability      float64       `conf:"default:0.01"`
        Timeout          time.Duration `conf:"default:30s"`
    }
}

// Parse the configuration from environment variables.
const prefix = "MYSERVICE"
var cfg Config
help, err := conf.Parse(prefix, &cfg)
if err != nil {
    if errors.Is(err, conf.ErrHelpWanted) {
        fmt.Println(help)
        return nil
    }
    return fmt.Errorf("parsing config: %w", err)
}
```

This approach allows for flexible configuration across different environments while maintaining type safety and default values.

### 7.5 Scaling Strategies

Scaling is essential for handling varying loads. Our system supports several scaling strategies:

1. **Horizontal Pod Autoscaling**: Automatically adjusts the number of pod replicas based on CPU or memory usage
2. **Vertical Pod Autoscaling**: Automatically adjusts the resource requests of pods based on usage
3. **Manual Scaling**: Manually adjust the number of replicas through Kubernetes commands
4. **Database Scaling**: Use connection pooling and read replicas to scale database access

#### Horizontal Pod Autoscaling

Horizontal Pod Autoscaling (HPA) automatically scales the number of pod replicas based on observed metrics:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: myservice
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myservice
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

This HPA scales the deployment between 3 and 10 replicas based on CPU and memory utilization.

#### Vertical Pod Autoscaling

Vertical Pod Autoscaling (VPA) automatically adjusts the resource requests of pods based on usage:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: myservice
  namespace: default
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myservice
  updatePolicy:
    updateMode: Auto
  resourcePolicy:
    containerPolicies:
      - containerName: myservice
        minAllowed:
          cpu: 100m
          memory: 128Mi
        maxAllowed:
          cpu: 1
          memory: 1Gi
```

This VPA automatically adjusts the resource requests of the deployment based on observed usage, within the specified limits.

#### Database Connection Pooling

Database connections are pooled to efficiently use resources:

```go
// DB configuration.
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
```

This ensures that database connections are efficiently utilized as the service scales.

### 7.6 Load Balancing

Load balancing is essential for distributing traffic across service instances. Our system uses several load balancing mechanisms:

1. **Kubernetes Service**: Distributes traffic to pods within the cluster
2. **Ingress Controller**: Routes external traffic to services
3. **Service Mesh**: Provides advanced traffic routing capabilities

#### Kubernetes Service Load Balancing

Kubernetes Services provide basic load balancing:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myservice
  namespace: default
spec:
  selector:
    app: myservice
  ports:
    - port: 80
      targetPort: http
  type: ClusterIP
```

This Service distributes traffic to all pods that match the selector, using a round-robin algorithm.

#### Ingress Controller Load Balancing

Ingress Controllers provide more advanced load balancing for external traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myservice
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/load-balance: "round_robin"
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "*"
spec:
  rules:
    - host: myservice.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: myservice
                port:
                  name: http
```

This Ingress uses the NGINX Ingress Controller to route external traffic to the service, with additional features like CORS support.

#### Service Mesh Load Balancing

Service meshes like Istio provide advanced traffic routing capabilities:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: myservice
  namespace: default
spec:
  hosts:
    - myservice.example.com
  gateways:
    - istio-system/ingressgateway
  http:
    - match:
        - uri:
            prefix: /
      route:
        - destination:
            host: myservice
            port:
              number: 80
          weight: 90
        - destination:
            host: myservice-canary
            port:
              number: 80
          weight: 10
```

This VirtualService routes 90% of traffic to the main service and 10% to a canary deployment, enabling advanced deployment strategies like canary releases.

### 7.7 Continuous Integration and Continuous Delivery (CI/CD)

CI/CD pipelines automate the building, testing, and deployment of our services. We use GitHub Actions or Jenkins for CI/CD.

#### GitHub Actions Workflow

Here's a typical GitHub Actions workflow for our services:

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Set up Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.20

      - name: Build
        run: go build -v ./...

      - name: Test
        run: go test -v ./...

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v1

      - name: Login to Registry
        uses: docker/login-action@v1
        with:
          registry: myregistry.example.com
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v2
        with:
          context: .
          push: true
          tags: myregistry.example.com/myservice:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Set up Kustomize
        uses: imranismail/setup-kustomize@v1

      - name: Update Kubernetes manifests
        run: |
          cd kustomize/overlays/production
          kustomize edit set image myregistry.example.com/myservice=myregistry.example.com/myservice:${{ github.sha }}

      - name: Commit and push updated manifests
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add kustomize/overlays/production
          git commit -m "Update image to ${{ github.sha }}"
          git push

      - name: Set up kubectl
        uses: azure/setup-kubectl@v1

      - name: Deploy to Kubernetes
        run: |
          echo "${{ secrets.KUBECONFIG }}" > kubeconfig
          export KUBECONFIG=./kubeconfig
          kubectl apply -k kustomize/overlays/production
```

This workflow automates several steps:

1. **Build and test**: The code is built and tested
2. **Build Docker image**: A Docker image is built and pushed to the registry
3. **Update manifests**: Kubernetes manifests are updated with the new image tag
4. **Deploy**: The updated manifests are applied to the Kubernetes cluster

This ensures that changes are automatically deployed to the production environment after passing tests.

#### GitOps with Argo CD

We also use GitOps principles with Argo CD for continuous delivery:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myservice
  namespace: argocd
spec:
  project: default
  source:
    repoURL: git@github.com:example/myservice.git
    targetRevision: HEAD
    path: kustomize/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

This Argo CD Application automatically syncs the Kubernetes manifests from the Git repository to the cluster, ensuring that the cluster state always matches the desired state in Git.

### 7.8 Multi-Environment Deployment

Our system supports deployment to multiple environments (development, staging, production) using Kustomize:

#### Base Kustomization

The base Kustomization defines common resources:

```yaml
# kustomize/base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - service.yaml
  - configmap.yaml
```

#### Development Overlay

The development overlay customizes resources for the development environment:

```yaml
# kustomize/overlays/development/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
bases:
  - ../../base
namespace: development
patchesStrategicMerge:
  - deployment-patch.yaml
  - configmap-patch.yaml
```

#### Production Overlay

The production overlay customizes resources for the production environment:

```yaml
# kustomize/overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
bases:
  - ../../base
namespace: production
patchesStrategicMerge:
  - deployment-patch.yaml
  - configmap-patch.yaml
```

This approach allows for environment-specific configuration while maintaining a single source of truth for common resources.

### 7.9 Blue-Green and Canary Deployments

Our system supports advanced deployment strategies like blue-green and canary deployments:

#### Blue-Green Deployment

Blue-green deployment involves running two identical environments (blue and green) and switching traffic between them:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myservice
  namespace: default
spec:
  selector:
    app: myservice
    version: blue # Initially points to the blue deployment
  ports:
    - port: 80
      targetPort: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice-blue
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
      version: blue
  template:
    metadata:
      labels:
        app: myservice
        version: blue
    spec:
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:1.0.0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice-green
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
      version: green
  template:
    metadata:
      labels:
        app: myservice
        version: green
    spec:
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:2.0.0
```

To switch traffic from blue to green, the service selector is updated:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myservice
  namespace: default
spec:
  selector:
    app: myservice
    version: green # Now points to the green deployment
  ports:
    - port: 80
      targetPort: http
```

#### Canary Deployment

Canary deployment involves gradually routing traffic to a new version:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: myservice
  namespace: default
spec:
  hosts:
    - myservice
  http:
    - route:
        - destination:
            host: myservice
            subset: v1
          weight: 90
        - destination:
            host: myservice
            subset: v2
          weight: 10
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: myservice
  namespace: default
spec:
  host: myservice
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
```

This routes 90% of traffic to version v1 and 10% to version v2. The weights can be adjusted gradually until all traffic is routed to v2.

### 7.10 Stateful Services

Some services require state, such as databases or message queues. Kubernetes provides StatefulSets for managing stateful applications:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: database
spec:
  serviceName: postgres
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:13
          ports:
            - containerPort: 5432
              name: postgres
          env:
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-secrets
                  key: password
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 10Gi
```

This StatefulSet deploys a PostgreSQL database with persistent storage. Each instance gets a stable network identity (postgres-0, postgres-1, postgres-2) and persistent storage.

### 7.11 Health Checks and Readiness Probes

Health checks and readiness probes ensure that services are healthy and ready to receive traffic:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
  template:
    metadata:
      labels:
        app: myservice
    spec:
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:1.0.0
          ports:
            - containerPort: 3000
              name: http
          readinessProbe:
            httpGet:
              path: /v1/check/readiness
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /v1/check/liveness
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
```

These probes serve different purposes:

- **Readiness Probe**: Determines if the pod is ready to receive traffic
- **Liveness Probe**: Determines if the pod is alive and healthy

The service implements these endpoints:

```go
// Routes adds specific routes for health checks.
func Routes(app *web.App, cfg Config) {
    const version = "v1"

    api := newApp(cfg.Log, cfg.DB)

    app.Handle(http.MethodGet, version, "/check/readiness", api.readiness)
    app.Handle(http.MethodGet, version, "/check/liveness", api.liveness)
}

// readiness checks if the service is ready to receive traffic.
func (a *app) readiness(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
    status := Success{
        Status: "ok",
    }

    // Check database connection.
    err := sqldb.StatusCheck(ctx, a.db)
    if err != nil {
        status.Status = "db not ready"
        return web.Respond(ctx, w, status, http.StatusInternalServerError)
    }

    return web.Respond(ctx, w, status, http.StatusOK)
}

// liveness returns simple status info if the service is alive.
func (a *app) liveness(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
    status := Success{
        Status: "ok",
    }

    return web.Respond(ctx, w, status, http.StatusOK)
}
```

These endpoints allow Kubernetes to monitor the health of the service and take action if it becomes unhealthy.

### 7.12 Resource Management

Resource management is critical for efficient utilization of cluster resources. Our services specify resource requests and limits:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
  template:
    metadata:
      labels:
        app: myservice
    spec:
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:1.0.0
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
```

These resource specifications serve different purposes:

- **Requests**: The amount of resources guaranteed to the container
- **Limits**: The maximum amount of resources the container can use

This ensures that services have the resources they need without monopolizing the cluster.

### 7.13 Monitoring and Alerting

Monitoring and alerting are essential for maintaining the health of deployed services. We use Prometheus and Grafana for monitoring:

#### Prometheus ServiceMonitor

Prometheus automatically discovers and scrapes metrics from our services:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: myservice
  namespace: monitoring
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: myservice
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

This ServiceMonitor configures Prometheus to scrape metrics from our service.

#### Prometheus AlertRule

Prometheus AlertManager generates alerts based on metric thresholds:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: myservice-alerts
  namespace: monitoring
  labels:
    release: prometheus
spec:
  groups:
    - name: myservice
      rules:
        - alert: HighErrorRate
          expr: sum(rate(http_requests_total{job="myservice",status=~"5.."}[5m])) / sum(rate(http_requests_total{job="myservice"}[5m])) > 0.1
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "High error rate in myservice"
            description: 'Error rate in myservice exceeds 10% ({{ $value | printf "%.2f" }}%)'
```

This rule generates an alert when the error rate exceeds 10% for 5 minutes.

#### Grafana Dashboard

Grafana visualizes metrics from Prometheus:

```yaml
apiVersion: integreatly.org/v1alpha1
kind: GrafanaDashboard
metadata:
  name: myservice
  namespace: monitoring
  labels:
    release: grafana
spec:
  json: |
    {
      "annotations": {
        "list": [
          {
            "builtIn": 1,
            "datasource": "-- Grafana --",
            "enable": true,
            "hide": true,
            "iconColor": "rgba(0, 211, 255, 1)",
            "name": "Annotations & Alerts",
            "type": "dashboard"
          }
        ]
      },
      "editable": true,
      "gnetId": null,
      "graphTooltip": 0,
      "id": 1,
      "links": [],
      "panels": [
        {
          "datasource": null,
          "fieldConfig": {
            "defaults": {
              "color": {
                "mode": "palette-classic"
              },
              "custom": {
                "axisLabel": "",
                "axisPlacement": "auto",
                "barAlignment": 0,
                "drawStyle": "line",
                "fillOpacity": 0,
                "gradientMode": "none",
                "hideFrom": {
                  "legend": false,
                  "tooltip": false,
                  "viz": false
                },
                "lineInterpolation": "linear",
                "lineWidth": 1,
                "pointSize": 5,
                "scaleDistribution": {
                  "type": "linear"
                },
                "showPoints": "auto",
                "spanNulls": false,
                "stacking": {
                  "group": "A",
                  "mode": "none"
                },
                "thresholdsStyle": {
                  "mode": "off"
                }
              },
              "mappings": [],
              "thresholds": {
                "mode": "absolute",
                "steps": [
                  {
                    "color": "green",
                    "value": null
                  },
                  {
                    "color": "red",
                    "value": 80
                  }
                ]
              }
            },
            "overrides": []
          },
          "gridPos": {
            "h": 9,
            "w": 12,
            "x": 0,
            "y": 0
          },
          "id": 2,
          "options": {
            "legend": {
              "calcs": [],
              "displayMode": "list",
              "placement": "bottom"
            },
            "tooltip": {
              "mode": "single"
            }
          },
          "title": "Request Rate",
          "type": "timeseries"
        },
        {
          "datasource": null,
          "fieldConfig": {
            "defaults": {
              "color": {
                "mode": "palette-classic"
              },
              "custom": {
                "axisLabel": "",
                "axisPlacement": "auto",
                "barAlignment": 0,
                "drawStyle": "line",
                "fillOpacity": 0,
                "gradientMode": "none",
                "hideFrom": {
                  "legend": false,
                  "tooltip": false,
                  "viz": false
                },
                "lineInterpolation": "linear",
                "lineWidth": 1,
                "pointSize": 5,
                "scaleDistribution": {
                  "type": "linear"
                },
                "showPoints": "auto",
                "spanNulls": false,
                "stacking": {
                  "group": "A",
                  "mode": "none"
                },
                "thresholdsStyle": {
                  "mode": "off"
                }
              },
              "mappings": [],
              "thresholds": {
                "mode": "absolute",
                "steps": [
                  {
                    "color": "green",
                    "value": null
                  },
                  {
                    "color": "red",
                    "value": 80
                  }
                ]
              }
            },
            "overrides": []
          },
          "gridPos": {
            "h": 9,
            "w": 12,
            "x": 12,
            "y": 0
          },
          "id": 3,
          "options": {
            "legend": {
              "calcs": [],
              "displayMode": "list",
              "placement": "bottom"
            },
            "tooltip": {
              "mode": "single"
            }
          },
          "title": "Error Rate",
          "type": "timeseries"
        }
      ],
      "schemaVersion": 31,
      "style": "dark",
      "tags": [],
      "templating": {
        "list": []
      },
      "time": {
        "from": "now-6h",
        "to": "now"
      },
      "timepicker": {},
      "timezone": "",
      "title": "MyService Dashboard",
      "uid": "myservice",
      "version": 1
    }
  name: myservice
```

This dashboard visualizes key metrics for our service, such as request rate and error rate.

### 7.14 Disaster Recovery

Disaster recovery is essential for ensuring data durability and service availability in the event of a failure. Our system implements several disaster recovery strategies:

1. **Database Backups**: Regular backups of database data
2. **Multi-zone Deployments**: Deployments span multiple availability zones
3. **Multi-region Deployments**: Critical services span multiple regions
4. **Data Replication**: Data is replicated across instances or regions

#### Database Backup CronJob

Database backups are automated using a Kubernetes CronJob:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: database
spec:
  schedule: "0 2 * * *" # Run at 2:00 AM every day
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: postgres-backup
              image: postgres:13
              command:
                - "/bin/sh"
                - "-c"
                - |
                  pg_dump -h postgres -U postgres -d mydatabase > /backups/mydatabase-$(date +%Y%m%d).sql
              env:
                - name: PGPASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: postgres-secrets
                      key: password
              volumeMounts:
                - name: backup-volume
                  mountPath: /backups
          volumes:
            - name: backup-volume
              persistentVolumeClaim:
                claimName: backup-pvc
          restartPolicy: OnFailure
```

This CronJob backs up the database every day at 2:00 AM.

#### Multi-zone Deployment

Services are deployed across multiple availability zones for resilience:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
  template:
    metadata:
      labels:
        app: myservice
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - myservice
                topologyKey: topology.kubernetes.io/zone
```

This deployment uses pod anti-affinity to spread pods across different availability zones.

### 7.15 Security Considerations

Security is a critical concern in deployment. Our system implements several security measures:

1. **Pod Security Policies**: Enforce security best practices for pods
2. **Network Policies**: Control traffic flow between pods
3. **Secret Management**: Securely store and access sensitive data
4. **Service Accounts**: Limit pod permissions

#### Pod Security Context

Pod security context enforces security best practices:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myservice
  template:
    metadata:
      labels:
        app: myservice
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
        - name: myservice
          image: myregistry.example.com/myservice:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
```

This security context ensures that the container runs as a non-root user with minimal privileges.

#### Network Policy

Network policies control traffic flow:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: myservice
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: myservice
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

This network policy allows traffic only from the frontend to the service on port 3000, and from the service to the database on port 5432 and DNS on port 53.

### 7.16 Performance Optimization

Performance optimization is crucial for efficient resource utilization and responsiveness. Our system implements several optimization strategies:

1. **Caching**: Use in-memory and distributed caching
2. **Connection Pooling**: Pool database connections
3. **Compression**: Compress API responses
4. **Resource Limits**: Set appropriate resource limits

#### Caching with Redis

Redis is used for caching:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: cache
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: redis:6
          ports:
            - containerPort: 6379
```

Our services integrate with Redis for caching:

```go
// New creates a new cache client.
func New(redisURL string) (*Cache, error) {
    opts, err := redis.ParseURL(redisURL)
    if err != nil {
        return nil, fmt.Errorf("parse redis url: %w", err)
    }

    client := redis.NewClient(opts)
    if err := client.Ping(context.Background()).Err(); err != nil {
        return nil, fmt.Errorf("ping redis: %w", err)
    }

    return &Cache{
        client: client,
    }, nil
}

// Get gets a value from the cache.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
    val, err := c.client.Get(ctx, key).Bytes()
    if err != nil {
        if err == redis.Nil {
            return nil, nil
        }
        return nil, fmt.Errorf("get: %w", err)
    }

    return val, nil
}

// Set sets a value in the cache.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
    if err := c.client.Set(ctx, key, value, ttl).Err(); err != nil {
        return fmt.Errorf("set: %w", err)
    }

    return nil
}
```

This provides a fast, in-memory cache for frequently accessed data.

#### Compression Middleware

Compression middleware reduces response size:

```go
// Compress compresses HTTP responses.
func Compress() web.MidHandler {
    m := func(handler web.Handler) web.Handler {
        h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
            // Skip compression for certain content types.
            if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                w.Header().Set("Content-Encoding", "gzip")
                gzw := gzip.NewWriter(w)
                defer gzw.Close()
                w = &gzipResponseWriter{ResponseWriter: w, Writer: gzw}
            }

            return handler(ctx, w, r)
        }

        return h
    }

    return m
}

// gzipResponseWriter is a wrapper around http.ResponseWriter that compresses responses.
type gzipResponseWriter struct {
    http.ResponseWriter
    Writer *gzip.Writer
}

// Write compresses the response before writing it.
func (w *gzipResponseWriter) Write(b []byte) (int, error) {
    return w.Writer.Write(b)
}
```

This middleware compresses HTTP responses using gzip, reducing bandwidth usage and improving performance.

### 7.17 Best Practices for Deployment

When deploying services, follow these best practices:

1. **Infrastructure as Code**: Define all infrastructure as code for consistency and reproducibility
2. **Immutable Infrastructure**: Use immutable containers and infrastructure
3. **Automated Testing**: Automate testing as part of the deployment pipeline
4. **Graceful Shutdown**: Implement graceful shutdown to handle termination signals
5. **Rolling Updates**: Use rolling updates to minimize downtime
6. **Health Checks**: Implement comprehensive health checks
7. **Resource Limits**: Set appropriate resource limits for all containers
8. **Monitoring and Alerting**: Implement comprehensive monitoring and alerting
9. **Secret Management**: Securely manage secrets
10. **Backup and Recovery**: Implement backup and recovery procedures

### 7.18 Common Pitfalls to Avoid

When deploying services, avoid these common pitfalls:

1. **Insufficient Resource Limits**: Not setting appropriate resource limits, leading to resource starvation
2. **Missing Health Checks**: Not implementing health checks, leading to unhealthy services receiving traffic
3. **Inadequate Monitoring**: Not implementing comprehensive monitoring, leading to undetected issues
4. **Hardcoded Configuration**: Hardcoding configuration values, making it difficult to manage different environments
5. **Single Points of Failure**: Not designing for resilience, leading to service outages
6. **Insecure Secret Management**: Not securely managing secrets, leading to security vulnerabilities
7. **Manual Deployments**: Relying on manual deployments, leading to inconsistency and errors
8. **Insufficient Testing**: Not testing deployments, leading to issues in production
9. **Ignoring Graceful Shutdown**: Not implementing graceful shutdown, leading to disruptions during updates
10. **Overlooking Network Policies**: Not implementing network policies, leading to security vulnerabilities

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

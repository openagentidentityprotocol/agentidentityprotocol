# Policy Reference

> **Note**: This is a user-friendly guide to writing AIP policies. For the formal specification, see [spec/aip-v1alpha1.md](../spec/aip-v1alpha1.md).

Complete reference for AIP policy YAML files (`agent.yaml`).

## Table of Contents

- [Overview](#overview)
- [Schema](#schema)
- [Metadata](#metadata)
- [Spec Fields](#spec-fields)
- [Tool Rules](#tool-rules)
- [DLP Configuration](#dlp-configuration)
- [Examples](#examples)
- [Validation](#validation)

## Overview

AIP policies are declarative YAML files that define what tools an agent can use and under what conditions. The policy is loaded at proxy startup and evaluated for every `tools/call` request.

**Design principle**: Default deny. If a tool is not explicitly allowed, it's blocked.

## Schema

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: string           # Policy identifier
  version: string        # Semantic version (optional)
  owner: string          # Contact email (optional)
  signature: string      # Policy signature (optional, v1alpha2)
spec:
  mode: enforce | monitor
  allowed_tools: [string]
  tool_rules: [ToolRule]
  dlp: DLPConfig
  identity: IdentityConfig # (optional, v1alpha2)
  server: ServerConfig     # (optional, v1alpha2)
```

## Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for this policy |
| `version` | string | No | Semantic version (e.g., "1.0.0") |
| `owner` | string | No | Contact email for policy questions |
| `signature` | string | No | Ed25519 signature for policy integrity (v1alpha2) |

Example:
```yaml
metadata:
  name: code-review-agent
  version: "2.1.0"
  owner: platform-team@company.com
  signature: "ed25519:YWJjZGVm..."
```

## Spec Fields

### mode

Controls whether policy violations are enforced or just logged.

| Value | Behavior |
|-------|----------|
| `enforce` | Block violations, return JSON-RPC error (default) |
| `monitor` | Log violations but allow through (dry-run) |

```yaml
spec:
  mode: enforce  # or "monitor"
```

**Use case for monitor mode**: Test new policies in production before enforcement.

### allowed_tools

Allowlist of tool names that the agent can invoke. Tool names must exactly match what the MCP server reports.

```yaml
spec:
  allowed_tools:
    - github_get_repo
    - github_list_pulls
    - read_file
    - list_directory
```

**Important**: If a tool is not in this list AND not in `tool_rules` with `action: allow`, it will be blocked.

## Tool Rules

Fine-grained control over individual tools. Each rule can specify an action and argument validation.

### Structure

```yaml
spec:
  tool_rules:
    - tool: string          # Tool name (required)
      action: string        # allow | block | ask (default: allow)
      allow_args: object    # Argument validation patterns
      rate_limit: string    # Rate limiting (e.g., "10/minute")
      schema_hash: string   # Tool schema integrity hash (v1alpha2)
```

### Actions

| Action | Description |
|--------|-------------|
| `allow` | Permit the tool call (subject to `allow_args` validation) |
| `block` | Deny unconditionally |
| `ask` | Prompt user via native OS dialog for approval |

### Block Action

Explicitly deny a tool:

```yaml
tool_rules:
  - tool: github_delete_repo
    action: block
  
  - tool: exec_command
    action: block
```

### Ask Action (Human-in-the-Loop)

Require user approval for sensitive operations:

```yaml
tool_rules:
  - tool: run_training
    action: ask
  
  - tool: deploy_production
    action: ask
```

When triggered:
1. Native OS dialog appears: "Allow tool 'run_training'?"
2. User clicks "Allow" or "Deny"
3. If no response in 60 seconds: auto-deny

### Argument Validation

Use `allow_args` to validate tool arguments with regex patterns:

```yaml
tool_rules:
  - tool: exec_command
    action: ask
    allow_args:
      command: "^(ls|cat|echo|pwd)\\s.*"  # Only safe commands
  
  - tool: postgres_query
    action: allow
    allow_args:
      query: "^SELECT\\s+.*"  # Only SELECT, no INSERT/UPDATE/DELETE
```

**Rules**:
- Regex must match the **entire** argument value (implicit `^...$`)
- If any `allow_args` pattern fails, the request is blocked
- Arguments not in `allow_args` are not validated

### Rate Limiting

Limit how often a tool can be called:

```yaml
tool_rules:
  - tool: list_gpus
    rate_limit: "10/minute"
  
  - tool: search_files
    rate_limit: "100/minute"
```

**Format**: `<count>/<period>` where period is `second`, `minute`, or `hour`.

When rate limit is exceeded:
- Request is blocked with JSON-RPC error code `-32003`
- Audit log records `RATE_LIMITED` event

## Identity Configuration (v1alpha2)

Configure agent identity and session management.

```yaml
spec:
  identity:
    enabled: true             # Enable identity management
    token_ttl: "10m"          # Token lifetime
    rotation_interval: "8m"   # Rotate before expiry
    require_token: true       # Enforce token presence
    session_binding: "strict" # Binding mode
    audience: "https://api.example.com" # Token audience
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable identity features |
| `token_ttl` | duration | `"5m"` | Token time-to-live |
| `rotation_interval` | duration | `"4m"` | When to rotate token |
| `require_token` | bool | `false` | Block requests without valid token |
| `session_binding` | string | `"process"` | `process`, `policy`, or `strict` |
| `audience` | string | `metadata.name` | Token audience URI |

### Session Binding Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `process` | Binds to OS process ID | Single-machine, local agents |
| `policy` | Binds to policy hash | Distributed agents sharing policy |
| `strict` | Binds to process + policy + host | High security, non-ephemeral |

## Server Configuration (v1alpha2)

Configure the built-in HTTP server for remote validation.

```yaml
spec:
  server:
    enabled: true
    listen: "127.0.0.1:9443"
    failover_mode: "fail_closed"
    tls:
      cert: "/path/to/cert.pem"
      key: "/path/to/key.pem"
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable HTTP server |
| `listen` | string | `"127.0.0.1:9443"` | Bind address |
| `failover_mode` | string | `"fail_closed"` | `fail_closed`, `fail_open`, `local_policy` |
| `timeout` | duration | `"5s"` | Validation timeout |

## DLP Configuration

Data Loss Prevention scans tool responses for sensitive patterns and redacts matches.

### Structure

```yaml
spec:
  dlp:
    enabled: true          # Optional, true when dlp block present
    patterns:
      - name: string       # Rule name for audit log
        regex: string      # Regex pattern to match
```

### Built-in Pattern Library

```yaml
dlp:
  patterns:
    # API Keys
    - name: "AWS Key"
      regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    
    - name: "GitHub Token"
      regex: "ghp_[a-zA-Z0-9]{36}"
    
    - name: "Generic Secret"
      regex: "(?i)(api_key|secret|password)\\s*[:=]\\s*['\"]?([a-zA-Z0-9-_]+)['\"]?"
    
    # PII
    - name: "Email"
      regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    
    - name: "SSN"
      regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    
    - name: "Credit Card"
      regex: "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b"
    
    # Secrets
    - name: "Private Key"
      regex: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
```

### Redaction Output

Matched content is replaced with: `[REDACTED:<RuleName>]`

```
Before: "Connect with: AKIAIOSFODNN7EXAMPLE"
After:  "Connect with: [REDACTED:AWS Key]"
```

## Examples

### Read-Only Policy

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: read-only
spec:
  mode: enforce
  allowed_tools:
    - read_file
    - list_directory
    - search_files
  tool_rules:
    - tool: write_file
      action: block
    - tool: delete_file
      action: block
```

### GPU/ML Policy

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gpu-policy
spec:
  mode: enforce
  allowed_tools:
    - list_gpus
    - get_gpu_metrics
  tool_rules:
    - tool: list_gpus
      rate_limit: "10/minute"
    - tool: run_training
      action: ask  # Interactive approval
    - tool: allocate_gpu
      action: ask
```

### Prompt Injection Defense

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gemini-jack-defense
spec:
  mode: enforce
  allowed_tools:
    - read_file
    - search_code
  tool_rules:
    # Block all external communication
    - tool: send_email
      action: block
    - tool: post_slack
      action: block
    - tool: http_request
      action: block
    
    # Block file system writes
    - tool: write_file
      action: block
    - tool: exec_command
      action: block
  
  dlp:
    patterns:
      - name: "Exfil URL"
        regex: "https?://[a-zA-Z0-9.-]+\\.(ngrok|requestbin|pipedream)"
```

### Monitor Mode (Testing)

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: test-policy
spec:
  mode: monitor  # Log only, don't block
  allowed_tools:
    - list_files
```

## Validation

### Policy File Validation

AIP validates policies at startup. Common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid apiVersion` | Wrong API version | Use `aip.io/v1alpha1` |
| `empty allowed_tools` | No tools specified | Add tools or tool_rules |
| `invalid regex in allow_args` | Bad regex pattern | Validate regex syntax |
| `invalid rate_limit format` | Wrong rate limit format | Use `<N>/<period>` |
| `rotation_interval >= token_ttl` | Rotation must happen before expiry | Reduce rotation_interval |

### Common Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32001 | Forbidden | Tool not allowed |
| -32002 | Rate Limited | Too many requests |
| -32008 | Token Required | Missing identity token (v1alpha2) |
| -32009 | Token Invalid | Expired or invalid token (v1alpha2) |
| -32010 | Signature Invalid | Policy signature verification failed (v1alpha2) |
| -32013 | Schema Mismatch | Tool definition changed (v1alpha2) |

### Testing Policies

1. **Dry run with monitor mode**:
   ```yaml
   spec:
     mode: monitor
   ```

2. **Check audit logs**:
   ```bash
   cat aip-audit.jsonl | jq 'select(.violation == true)'
   ```

3. **Verbose logging**:
   ```bash
   ./aip --policy policy.yaml --target "..." --verbose
   ```

## Best Practices

1. **Start restrictive**: Begin with minimal `allowed_tools`, expand as needed
2. **Use monitor mode first**: Test policies before enforcement
3. **Review audit logs**: Regularly check for unexpected tool usage
4. **Version your policies**: Use semantic versioning in metadata
5. **Document decisions**: Add comments explaining why tools are blocked
6. **Separate policies per agent type**: Different agents need different permissions

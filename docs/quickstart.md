# Quickstart: AIP Proxy Interception Test

This guide walks through a minimal test demonstrating the AIP proxy's policy enforcement. By the end, you'll see how the proxy blocks unauthorized tool calls while allowing permitted ones.

## Prerequisites

- Go 1.23+
- Python 3.x

## What We're Building

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   stdin     │────▶│    AIP Proxy     │────▶│  echo_server.py │
│  (you)      │     │  (policy check)  │     │  (dummy MCP)    │
│             │◀────│                  │◀────│                 │
└─────────────┘     └──────────────────┘     └─────────────────┘
```

The proxy sits between your input and a dummy MCP server, intercepting `tools/call` requests and checking them against a policy file.

## Step 1: Build the Proxy

```bash
cd proxy
go build -o aip-proxy ./cmd/aip-proxy
```

## Step 2: Create a Test Policy

Create `test/agent.yaml`:

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: test-policy
spec:
  allowed_tools:
    - "list_files"
  # "delete_files" is implicitly blocked
```

This policy allows only `list_files`. Any other tool call will be rejected.

## Step 3: Create a Dummy MCP Server

Create `test/echo_server.py`:

```python
#!/usr/bin/env python3
"""
Dummy MCP server that echoes back JSON-RPC requests.
"""
import sys
import json

def main():
    sys.stdout.reconfigure(line_buffering=True)
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            request = json.loads(line)
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "echo": request,
                    "message": "Request received by echo_server"
                }
            }
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError as e:
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }), flush=True)

if __name__ == "__main__":
    main()
```

## Step 4: Run the Test

Start the proxy with verbose logging:

```bash
./aip-proxy --policy test/agent.yaml --target "python3 test/echo_server.py" --verbose
```

In another terminal (or pipe input), send two requests:

### Test 1: Allowed Tool (`list_files`)

```json
{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_files"}, "id": 1}
```

**Expected:** Request passes through to `echo_server.py`, response returned.

### Test 2: Blocked Tool (`delete_files`)

```json
{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_files"}, "id": 2}
```

**Expected:** Proxy blocks the request, returns error. Request **never reaches** the server.

## Expected Output

```
[aip-proxy] Loaded policy: test-policy
[aip-proxy] Allowed tools: [list_files]
[aip-proxy] Started subprocess PID 2850: python3 test/echo_server.py

[aip-proxy] → [upstream] method=tools/call id=1
[aip-proxy] Tool call intercepted: list_files
[aip-proxy] ALLOWED: Tool "list_files" permitted by policy

[aip-proxy] → [upstream] method=tools/call id=2
[aip-proxy] Tool call intercepted: delete_files
[aip-proxy] BLOCKED: Tool "delete_files" not allowed by policy
```

### JSON Responses

**Blocked request (delete_files):**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32001,
    "message": "Forbidden",
    "data": {
      "reason": "Tool not in allowed_tools list",
      "tool": "delete_files"
    }
  }
}
```

**Allowed request (list_files):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "echo": {
      "jsonrpc": "2.0",
      "method": "tools/call",
      "params": {"name": "list_files"},
      "id": 1
    },
    "message": "Request received by echo_server"
  }
}
```

## One-Liner Test

Run both requests in a single command:

```bash
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_files"}, "id": 1}
{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_files"}, "id": 2}' | \
./aip-proxy --policy test/agent.yaml --target "python3 test/echo_server.py" --verbose
```

## Key Takeaways

| Scenario | Policy Decision | Behavior |
|----------|-----------------|----------|
| Tool in `allowed_tools` | ALLOW | Forward to subprocess |
| Tool not in `allowed_tools` | DENY | Return `-32001 Forbidden`, never forward |
| Non-tool methods | PASSTHROUGH | Forward without policy check |

## Security Properties Demonstrated

1. **Fail-Closed**: Unknown tools are denied by default
2. **Zero Trust**: Every `tools/call` is checked, no implicit permissions
3. **Audit Trail**: All decisions logged with tool name and outcome
4. **Isolation**: Blocked requests never reach the target server

## Next Steps

- Add more tools to `allowed_tools` in your policy
- Try with a real MCP server (e.g., `npx @modelcontextprotocol/server-filesystem`)
- Explore the proxy source code in `cmd/aip-proxy/main.go`

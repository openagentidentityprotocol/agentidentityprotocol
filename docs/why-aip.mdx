# Why AIP? The Problem with AI Agent Security

This document explains the security challenges that AIP addresses and why existing solutions are insufficient.

## The Problem: God Mode by Default

Modern AI agents operate with **unrestricted access** to powerful tools. When you grant an LLM access to your GitHub account, database, or cloud infrastructure, you're not just giving it an API key—you're granting **unbounded intent execution** with no policy layer.

## The Threat Model

| Threat | Description | Real-World Example |
|--------|-------------|-------------------|
| **Indirect Prompt Injection** | Malicious instructions embedded in data the agent processes | [*GeminiJack*](https://embrace-the-red.com/blog/gemini-jack/) (2024): Attackers embedded prompts in Google Docs that hijacked Gemini's actions |
| **Consent Fatigue** | Users approve broad permissions without understanding scope | "Allow GitHub access" grants `repo:delete`, not just `repo:read` |
| **Shadow AI** | Agents operating outside enterprise security boundaries | Developers running local Copilot instances with production credentials |
| **Privilege Escalation** | Agents accumulating permissions across tool calls | Agent chains: Slack → Calendar → Email → sends unauthorized messages |
| **Data Exfiltration** | Sensitive data leaving through unmonitored egress | Agent "summarizing" code by posting to external APIs |

## API Keys Are for Code. AIP Is for Intent.

Traditional security assumes **deterministic code execution**. API keys authenticate the *application*. But LLMs are non-deterministic systems executing *user intent* through *model interpretation*.

```
Traditional: Code → API Key → Resource
    └── Deterministic, auditable, predictable

Agent World: User Intent → LLM Interpretation → Tool Call → Resource
    └── Non-deterministic, opaque, emergent behavior
```

**We need a security primitive that authenticates and authorizes *intent*, not just identity.**

## Security Comparison

| Aspect | Standard MCP | AIP-Enabled MCP |
|--------|--------------|-----------------|
| **Authentication** | Static API keys | Short-lived OIDC tokens |
| **Authorization** | None (full access) | Per-action policy check |
| **Scope** | Implicit (whatever key allows) | Explicit manifest declaration |
| **Audit** | Application logs (if any) | Immutable, structured audit trail |
| **Egress Control** | None | Network-level filtering (planned) |
| **Revocation** | Rotate API keys | Instant token/session revocation |
| **Human-in-the-Loop** | Not supported | Configurable approval gates |
| **Blast Radius** | Unlimited | Scoped to manifest |
| **Compliance** | Manual attestation | Policy-as-code, auditable |

## Why Not Just Use...?

### OAuth Scopes?

OAuth scopes are:
- **Coarse-grained**: "repo access" vs "read pull requests from org X"
- **Static**: Granted at install time, can't change per-session
- **User-facing**: Leads to consent fatigue

AIP policies are:
- **Fine-grained**: Per-tool, per-argument validation
- **Dynamic**: Can change without re-authentication
- **Developer-controlled**: Defined in config files, version-controlled

### Service Mesh (Istio)?

Service meshes operate at the **service level**, not the **action level**. They can say "Service A can call Service B" but not "Agent can only call `repos.get` with `org:mycompany/*`".

AIP operates at the **tool call level** within a service.

### Container Sandboxing?

Containers provide **process isolation** but not **semantic authorization**. A containerized agent with network access can still exfiltrate data.

AIP provides **policy-based authorization** that understands what the agent is *trying to do*.

## Comparison Table

| Approach | Authentication | Authorization | Audit | Revocation |
|----------|---------------|---------------|-------|------------|
| **Raw API Keys** | Static token | None | App logs | Rotate everywhere |
| **OAuth Scopes** | Token-based | Coarse-grained | Varies | Token expiry |
| **Service Mesh (Istio)** | mTLS | Service-level | Yes | Certificate rotation |
| **AIP** | Short-lived OIDC | Per-action policy | Immutable trail | Instant session kill |

AIP is purpose-built for the unique challenge of non-deterministic AI agents executing user intent.

## Architecture Principles

1. **Defense in Depth**: Multiple independent security layers (identity, policy, egress, audit)
2. **Least Privilege by Default**: Agents start with zero capabilities; everything is opt-in
3. **Fail Closed**: Unknown actions are denied; network errors = deny
4. **Immutable Audit**: All decisions logged; logs cannot be modified by agents
5. **Human Sovereignty**: Critical actions require human approval
6. **Manifest Portability**: Same manifest works across runtimes (local, Kubernetes, serverless)

## Prior Art & Inspiration

AIP builds on established security patterns:

- **[SPIFFE/SPIRE](https://spiffe.io/)**: Workload identity framework — AIP extends this to agent identity
- **[Open Policy Agent](https://www.openpolicyagent.org/)**: Policy-as-code — AIP's policy engine draws from OPA's design
- **[Istio](https://istio.io/)**: Service mesh authorization — AIP applies mesh principles to agent traffic
- **[AWS IAM](https://aws.amazon.com/iam/)**: Fine-grained permissions — AIP manifests are IAM policies for agents
- **[OAuth 2.0 / OIDC](https://openid.net/connect/)**: Token-based identity — AIP leverages OIDC for federation

## Next Steps

- **Read the specification**: [spec/aip-v1alpha1.md](../spec/aip-v1alpha1.md)
- **Try the reference implementation**: [implementations/go-proxy/](../implementations/go-proxy/)
- **Write your first policy**: [Policy Reference](policy-reference.md)

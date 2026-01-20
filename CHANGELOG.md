# Changelog

All notable changes to the Agent Identity Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation (architecture, policy reference, integration guide)
- GitHub Actions CI/CD workflows
- GoReleaser configuration for cross-platform builds
- Issue templates (bug report, feature request, security concern)
- Pull request template
- Dependabot configuration for automated dependency updates
- GitHub Copilot instructions for AI-assisted development
- CODEOWNERS file for code review routing
- Labels script for GitHub project management

### Changed
- Enhanced README with "Sudo for AI" demonstration

## [0.1.0] - 2026-01-20

### Added
- **AIP Proxy**: Core policy enforcement proxy for MCP servers
  - stdin/stdout passthrough for JSON-RPC messages
  - Tool call interception and policy evaluation
  - Graceful subprocess management
  
- **Policy Engine**: Declarative YAML-based policy system
  - `allowed_tools`: Allowlist of permitted tools
  - `tool_rules`: Fine-grained per-tool rules
  - `action: allow | block | ask`: Control tool behavior
  - `allow_args`: Regex-based argument validation
  - `rate_limit`: Per-tool rate limiting
  - `mode: enforce | monitor`: Enforcement vs dry-run mode

- **Human-in-the-Loop**: Native OS prompts for sensitive operations
  - macOS: AppleScript dialogs via `osascript`
  - Linux: `zenity` / `kdialog` support
  - Configurable timeout (default 60s)
  - Fail-closed on timeout

- **DLP Scanner**: Data Loss Prevention for response filtering
  - Configurable regex patterns
  - Content redaction with `[REDACTED:<RuleName>]`
  - Support for MCP content arrays and full-string fallback

- **Audit Logger**: Immutable JSONL audit trail
  - All tool calls logged with decision and context
  - DLP event logging
  - Monitor mode violation tracking

- **CLI**: Command-line interface
  - `--target`: MCP server command
  - `--policy`: Policy file path
  - `--verbose`: Detailed logging
  - `--audit`: Audit log path
  - `--generate-cursor-config`: Cursor IDE integration

- **Example Policies**:
  - `agent.yaml`: Full-featured example
  - `read-only.yaml`: Read-only filesystem access
  - `monitor-mode.yaml`: Dry-run testing
  - `gemini-jack-defense.yaml`: Prompt injection defense
  - `agent-monitor.yaml`: Monitoring configuration

### Security
- Fail-closed design: Unknown tools denied by default
- Zero-trust: Every tool call evaluated
- Least privilege: Explicit capability declaration
- Audit trail: Immutable logging for compliance

---

## Versioning

- **Major version (X.0.0)**: Breaking changes to policy schema or CLI
- **Minor version (0.X.0)**: New features, backward-compatible
- **Patch version (0.0.X)**: Bug fixes, no API changes

## Links

- [GitHub Releases](https://github.com/ArangoGutierrez/agent-identity-protocol/releases)
- [Documentation](https://github.com/ArangoGutierrez/agent-identity-protocol#readme)
- [Contributing](CONTRIBUTING.md)

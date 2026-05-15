# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeRisk is an AI-Native Risk Intelligence System — a multi-agent SRE/AIOps platform that performs DeepResearch Root Cause Analysis through coordinated agents (SRE-Agent, Code-Agent, ReportAgent, Vis-Agent, Data-Agent). Built on a Python uv workspace monorepo with a Next.js frontend.

## Build & Run Commands

### Install Dependencies
```bash
uv sync --all-packages --frozen \
    --extra "base" --extra "proxy_openai" --extra "rag" \
    --extra "storage_chromadb" --extra "derisks" --extra "storage_oss2" \
    --extra "client" --extra "ext_base" --extra "channel_dingtalk"
```

### Start Server
```bash
uv run derisk quickstart                    # Zero-config startup (port 7777)
uv run derisk quickstart -p 8888            # Custom port
uv run derisk quickstart -c configs/derisk-proxy-aliyun.toml  # With config
./start.sh                                  # Shell script wrapper
```

### Lint & Format
```bash
make fmt          # Format with ruff (format + isort + lint --fix)
make fmt-check    # Check formatting without changes
make mypy         # Type-check with mypy (rag, datasource, client, agent, vis, experimental)
make pre-commit   # Run fmt-check + test + test-doc + mypy
```

### Test
```bash
make test         # Run pytest (all)
make test-doc     # Run doctests only (derisk/core)
make coverage     # Run pytest with coverage
# Run a single test file:
uv run pytest tests/test_file.py
# Run a single test:
uv run pytest tests/test_file.py::test_function -k "test_name"
```

### Frontend (web/)
```bash
cd web && npm install
npm run dev       # Dev server
npm run build     # Production build (static export)
npm run lint      # ESLint
```

## Monorepo Architecture

### Package Dependency Chain
```
derisk-core  →  derisk-ext  →  derisk-serve  →  derisk-app
                                    ↓
                              derisk-client
```

| Package | Path | PyPI Name | Role |
|---------|------|-----------|------|
| **derisk-core** | `packages/derisk-core/` | `derisk` | Foundation: IoC container, agent framework, model adapters, RAG, storage, AWEL DAG engine, CLI, sandbox, tools, permissions |
| **derisk-ext** | `packages/derisk-ext/` | `derisk-ext` | Extensions: auth plugin (JWT/OAuth/RBAC), concrete storage backends (Milvus/ChromaDB/Weaviate/ES), datasource connectors (MySQL/PG/SQLite/OceanBase), RAG pipelines, agent actions, MCP gateway, channels (DingTalk/Feishu) |
| **derisk-serve** | `packages/derisk-serve/` | `derisk-serve` | API/service layer: 26 serve modules each following `serve.py → api/endpoints.py → api/schemas.py → models/models.py → service/service.py` pattern |
| **derisk-client** | `packages/derisk-client/` | `derisk-client` | Thin async HTTP client SDK (httpx) |
| **derisk-app** | `packages/derisk-app/` | `derisk-app` | Top-level app: FastAPI server assembly, thin auth web adapter (routes + checker), config, OpenAPI routes, static web UI |

### Key Abstractions

- **`SystemApp`** (derisk-core): Central IoC container singleton holding all component instances keyed by `ComponentType`
- **`BaseComponent`**: Lifecycle-managed ABC with hooks: `on_init`, `after_init`, `before_start`, `after_start`, `before_stop`
- **`BaseServe`** (derisk-serve): Serve component with DB manager creation and API prefix/tags registration
- **`BaseService`** (derisk-serve): Generic CRUD service with DAO pattern, integrates DAGManager
- **`AWEL`** (derisk-core): Agentic Workflow Expression Language — DAG engine for LLM pipelines with HTTP triggers, map/reduce operators
- **`ConfigManager`** (derisk-core): JSON-based config with `${secrets.key}` reference resolution for encrypted values
- **`SandboxBase` / `tool_registry`** (derisk-core): Sandboxed code execution and tool abstraction

### Startup Flow
1. `derisk_server.py:run_webserver()` → load TOML or zero-config
2. `scan_configs()` → register model providers, serve configs, storage configs
3. `SystemApp(FastAPI)` created → config loaded
4. `initialize_app()` → `server_init()`, `mount_routers()`, DB migration, OAuth2 sync
5. `register_serve_apps()` → register 18+ BaseServe components
6. Model worker initialization → Core_v2 Agent Runtime registered → Feature plugin routers mounted
7. uvicorn serves FastAPI app on port 7777

## Code Conventions

- **Python**: Ruff formatter, line-length 88, target py310, isort with `known-first-party = ["derisk", "derisk_client", "derisk_ext", "derisk_serve", "derisk_app"]`
- **Linting**: Ruff select `E, F, I`; `derisk-serve` has relaxed rules (ignores `F811, F841`)
- **Testing**: pytest with `pythonpath = ["packages", "."]`, `--import-mode=importlib`, test files match `test_*.py` or `*_test.py`
- **Frontend**: Next.js 15, React 18, TypeScript (strict), Ant Design 5, Tailwind CSS 4, ESLint + Prettier
- **Build**: All packages use `hatchling` build backend with `src/` layout
- **Config**: Dual system — legacy TOML files in `configs/` and new JSON config at `~/.derisk/derisk.json` via `derisk_core.config.ConfigManager`

## Important Paths

- **Configs**: `configs/` (TOML), `configs/agents/`, `configs/scenes/`, `configs/engineering/`
- **Entry point**: `packages/derisk-core/src/derisk/cli/cli_scripts.py` (Click CLI)
- **Web server**: `packages/derisk-app/src/derisk_app/derisk_server.py`
- **App factory**: `packages/derisk-app/src/derisk_app/app.py` (AppCreator)
- **Serve registration**: `packages/derisk-app/src/derisk_app/initialization/serve_initialization.py`
- **Frontend**: `web/` (Next.js 15 static export)
- **Tests**: `tests/` (integration/unit), `tests/e2e/` (end-to-end)
- **Docs**: `docs/` (Docusaurus site)
- **Auth plugin (core)**: `packages/derisk-ext/src/derisk_ext/plugin/auth/` (JWT, OAuth, User, RBAC)
- **Auth web adapter**: `packages/derisk-app/src/derisk_app/auth/` (routes, checker, bootstrap)
- **Auth bridge**: `packages/derisk-serve/src/derisk_serve/utils/auth.py` (get_user_from_headers)
- **Database schema**: `assets/schema/derisk.sql`
- **OpenSpec changes**: `openspec/`

## Optional Dependency Groups

Most integrations are optional extras. Key groups:
- **derisk-core**: `proxy_openai`, `proxy_zhipuai`, `proxy_tongyi`, `proxy_qianfan`, `proxy_anthropic`, `agent`, `framework`, `rag`, `hf`, `code`, `client`, `cli`
- **derisk-ext**: `auth` (pyjwt, cryptography), `rag`, `graph_rag`, `datasource_mysql`, `datasource_postgres`, `storage_milvus`, `storage_chromadb`, `storage_weaviate`, `storage_elasticsearch`, `mcp_gateway`, `channel_feishu`, `channel_dingtalk`, `ext_base`, `prometheus`
- **derisk-app**: `base` (pulls all core extras), `cache` (rocksdict), `observability` (OpenTelemetry)
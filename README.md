<p align="center">
  <img src="https://img.shields.io/badge/status-in%20development-yellow?style=for-the-badge" alt="Status"/>
  <img src="https://img.shields.io/badge/spring%20boot-4.0-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" alt="Spring Boot"/>
  <img src="https://img.shields.io/badge/python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/LangGraph-multi--agent-FF6F00?style=for-the-badge" alt="LangGraph"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">
  <img src="./assets/mantis-logo.svg" alt="MANTIS" width="600" />
</h1>

<h3 align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Space+Grotesk&weight=600&size=20&pause=1000&color=3B82F6&center=true&vCenter=true&width=800&height=40&lines=Multi-Agent+Neural+Threat+Intelligence+System;AI-powered+vulnerability+scanner;Understands,+explains,+and+fixes+flaws" alt="Typing Subtitle" />
</h3>

<p align="center">
  <em>An AI-powered vulnerability scanner that doesn't just find flaws — it understands, explains, and fixes them.</em>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> •
  <a href="#pipeline">Pipeline</a> •
  <a href="#ai-engine">AI Engine</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#roadmap">Roadmap</a>
</p>

---

> [!NOTE]
> **MANTIS is currently in active development.** Core architecture is finalized, module implementation is underway. Contributions and feedback are welcome.

---

## Why MANTIS?

Traditional vulnerability scanners dump thousands of findings on your team — raw SARIF, cryptic CWE codes, no context. Developers spend hours triaging, Googling CVEs, and writing patches manually.

**MANTIS changes that.**

It's not another scanner. It's an **intelligent security co-pilot** that combines static analysis, dependency scanning, and CVE intelligence with a **multi-agent AI system** that:

| Capability | How |
|---|---|
| 🔍 **Finds** vulnerabilities | Runs Semgrep, CodeQL, and Trivy in parallel — catches what one tool misses |
| 🧠 **Understands** them | AI agents analyze findings using RAG-augmented knowledge from NVD, MITRE, and real-world exploit data |
| 📝 **Explains** them | Generates human-readable explanations — no more deciphering `CWE-89` alone |
| 🛠️ **Fixes** them | Produces validated code patches, reviewed by an AI Reviewer agent before delivery |
| ⚡ **Prioritizes** them | CVSS scoring + contextual risk analysis = focus on what actually matters |

---

<h2 id="architecture">🏗️ Architecture</h2>

MANTIS follows a **microservices architecture** with two independent services communicating through an asynchronous message broker.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          MANTIS — Monorepo                             │
│                                                                        │
│   ┌──────────────────────┐        RabbitMQ         ┌────────────────┐  │
│   │   Backend Service    │◄══════════════════════►  │   AI Service   │  │
│   │   Spring Boot 4.0    │    scan.results ──►      │   Python 3.12  │  │
│   │   Java 25            │    ◄── ai.results        │   LangGraph    │  │
│   │                      │                          │   FastAPI      │  │
│   │   • Auth (JWT)       │                          │   Multi-Agent  │  │
│   │   • Scan Orchestration│                         │   RAG + Cache  │  │
│   │   • REST API         │                          │   Guardrails   │  │
│   │   • Dashboard Data   │                          │                │  │
│   └────────┬─────────────┘                          └───────┬────────┘  │
│            │                                                │           │
│   ┌────────▼─────────────────────────────────────────────────▼────────┐ │
│   │                        Data Layer                                 │ │
│   │   PostgreSQL    │    MongoDB     │    Redis    │    Pinecone      │ │
│   │   (Structured)  │    (Documents) │    (Cache)  │    (Vectors)     │ │
│   └───────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### Service Boundaries

| Service | Responsibility | Stack |
|---------|---------------|-------|
| **Backend** | User auth, project management, scan orchestration, REST API, notifications | Spring Boot 4.0, Java 25, PostgreSQL |
| **AI Service** | Vulnerability analysis, patch generation, CVE enrichment, risk scoring | Python 3.12, LangGraph, FastAPI |
| **Message Broker** | Async decoupling between services | RabbitMQ |

---

<h2 id="pipeline">🔄 Vulnerability Analysis Pipeline</h2>

```
                          ┌──────────────┐
                          │  Upload Code │
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┐
                 ▼               ▼               ▼
          ┌─────────────┐ ┌───────────┐ ┌──────────────┐
          │   Semgrep   │ │  CodeQL   │ │ Trivy / Snyk │
          │  Patterns   │ │  Taint    │ │    Deps      │
          │  Secrets    │ │  SQLi/XSS │ │   CVE Scan   │
          │  OWASP      │ │           │ │              │
          └──────┬──────┘ └─────┬─────┘ └──────┬───────┘
                 │              │               │
                 │         SARIF Format         │
                 └───────────────┼───────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   Merge & Deduplicate  │
                    │  Normalize → CWE/CVSS  │
                    └────────────┬───────────┘
                                 ▼
                    ┌────────────────────────┐
                    │ CVE Intelligence Engine │◄─── NVD / MITRE
                    │   CVSS Scoring          │◄─── GitHub Advisories
                    └────────────┬───────────┘
                                 ▼
                         ┌──── RabbitMQ ────┐
                         │  scan.results    │
                         └───────┬──────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   🧠 MANTIS AI Engine  │
                    │   Multi-Agent System   │
                    └────────────┬───────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   Security Report      │
                    │  • Dashboard           │
                    │  • Slack Alerts         │
                    │  • Patch Suggestions    │
                    └────────────────────────┘
```

---

<h2 id="ai-engine">🧠 AI Engine — Multi-Agent Orchestration</h2>

MANTIS uses **LangGraph** to orchestrate a team of specialized AI agents. Each agent has a focused responsibility, and the graph ensures they collaborate in the right order with conditional routing.

```
                    ┌─────────────────────────┐
                    │     SARIF Input          │
                    │   (Vulnerability Data)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   🔍 Analyst Agent      │
                    │   Understands the vuln   │
                    │   Classifies severity    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   📚 Enricher Agent     │
                    │   CVE lookup (NVD/MITRE)│
                    │   RAG knowledge base     │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   🛠️ Coder Agent        │
                    │   Generates code patch   │
                    │   Context-aware fix      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   ✅ Reviewer Agent      │
                    │   Validates the patch    │
                    │   Security check        │──── ✗ → Back to Coder
                    └────────────┬────────────┘
                                 │ ✓
                                 ▼
                    ┌─────────────────────────┐
                    │   📊 Final Report       │
                    │   Explanation + Patch    │
                    │   + Risk Score           │
                    └─────────────────────────┘
```

### Agent Details

| Agent | Role | Tools Available |
|-------|------|-----------------|
| **Analyst** | Parses SARIF, understands vulnerability context, classifies severity | SARIF parser, CWE database |
| **Enricher** | Looks up CVE details, finds known exploits, retrieves similar past vulnerabilities | NVD API, GitHub Advisories, RAG Vector Store |
| **Coder** | Generates a context-aware code patch that fixes the vulnerability | Code context, patch templates, RAG |
| **Reviewer** | Validates the patch doesn't introduce regressions or new vulnerabilities | Static analysis, guardrails |

### Intelligence Features

- **RAG (Retrieval-Augmented Generation)** — Queries a vector database of CVE advisories, security documentation, and known fix patterns to ground AI responses in real data
- **Semantic Cache** — Redis-backed cache that avoids re-calling the LLM for previously analyzed vulnerability patterns, reducing cost and latency
- **NeMo Guardrails** — Ensures the AI never generates malicious code, prompt injections, or harmful outputs

---

<h2 id="tech-stack">⚙️ Tech Stack</h2>

### Backend Service (Java)

| Technology | Purpose |
|-----------|---------|
| Spring Boot 4.0 | Application framework |
| Java 25 | Language runtime |
| Spring Security + JWT | Authentication & authorization |
| PostgreSQL 16 | Relational data (users, projects, findings) |
| Spring Data JPA | ORM / Data access |
| SpringDoc OpenAPI 3 | API documentation (Swagger UI) |
| Lombok | Boilerplate reduction |

### AI Service (Python)

| Technology | Purpose |
|-----------|---------|
| Python 3.12+ | Language runtime |
| FastAPI | HTTP endpoints & health checks |
| LangChain + LangGraph | Multi-agent orchestration |
| Pydantic | Data validation (SARIF in, Patch out) |
| aio-pika | Async RabbitMQ client |
| Redis | Semantic cache layer |
| Pinecone / Weaviate | Vector store for RAG |
| NeMo Guardrails | AI safety & output filtering |
| Jinja2 | Prompt template engine |

### Infrastructure

| Technology | Purpose |
|-----------|---------|
| RabbitMQ | Async message broker between services |
| Docker + Docker Compose | Containerization |
| MongoDB | Document store (raw scans, CVE advisories) |

### Security Scanners

| Scanner | Detects |
|---------|---------|
| Semgrep | Patterns, secrets, misconfigs, OWASP Top 10 |
| CodeQL | Taint analysis, SQLi, XSS, injection flows |
| Trivy / Snyk | Vulnerable dependencies, CVEs in libraries |

---

## 📁 Project Structure

```
mantis/
├── src/                              # 🟢 Backend Service (Spring Boot)
│   └── main/java/.../
│       ├── auth/                     #   JWT authentication
│       ├── user/                     #   User management
│       ├── config/security/          #   Security configuration
│       ├── project/                  #   Project management
│       ├── scan/                     #   Scan lifecycle
│       ├── scanner/                  #   Scanner orchestration
│       ├── finding/                  #   Vulnerability findings
│       ├── cve/                      #   CVE intelligence
│       ├── patch/                    #   Patch suggestions
│       └── notification/            #   Alerts (Slack, email)
│
├── ai-service/                       # 🟣 AI Service (Python)
│   ├── app/
│   │   ├── core/                     #   Config, logging, exceptions
│   │   ├── api/                      #   FastAPI routes
│   │   ├── broker/                   #   RabbitMQ consumer/publisher
│   │   ├── schemas/                  #   Pydantic models (SARIF, Patch)
│   │   ├── graph/                    #   LangGraph orchestration
│   │   │   └── nodes/               #   Individual AI agents
│   │   ├── tools/                    #   External tool wrappers
│   │   ├── prompts/                  #   Versioned prompts + Jinja2
│   │   ├── models/                   #   LLM abstraction (factory)
│   │   ├── rag/                      #   Vector store + embeddings
│   │   ├── cache/                    #   Redis semantic cache
│   │   └── security/                #   NeMo Guardrails
│   └── tests/                        #   Unit + integration tests
│
├── compose.yaml                      # 🐳 Docker Compose
└── pom.xml                           # Maven configuration
```

---

<h2 id="getting-started">🚀 Getting Started</h2>

> [!WARNING]
> MANTIS is in active development. The instructions below describe the target setup — not all modules are implemented yet.

### Prerequisites

- Java 25+
- Python 3.12+
- Docker & Docker Compose
- Maven 3.9+
- Node.js 20+ (for future frontend)

### 1. Clone the repository

```bash
git clone https://github.com/your-org/mantis.git
cd mantis
```

### 2. Start infrastructure services

```bash
docker compose up -d
```

This starts PostgreSQL, RabbitMQ, Redis, and MongoDB.

### 3. Run the Backend Service

```bash
./mvnw spring-boot:run
```

Backend runs at `http://localhost:8080` — Swagger UI at `/swagger-ui.html`

### 4. Run the AI Service

```bash
cd ai-service
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

AI Service runs at `http://localhost:8000`

---

## 🗄️ Data Layer Strategy

MANTIS uses a **polyglot persistence** approach — each type of data goes to the store best suited for it.

| Store | Data | Why |
|-------|------|-----|
| **PostgreSQL** | Users, projects, findings, CVE records, audit logs, patches | Relational integrity, ACID transactions, complex queries |
| **MongoDB** | Raw SARIF JSON, security events, LLM response cache, NVD advisories | Flexible schema, large JSON documents, time-series events |
| **Redis** | Semantic cache (LLM responses for known patterns) | Sub-millisecond reads, TTL-based expiration, cost optimization |
| **Pinecone** | CVE embeddings, security doc vectors, code pattern vectors | Similarity search for RAG, scalable vector operations |

---

<h2 id="roadmap">📍 Roadmap</h2>

### Phase 1 — Foundation `← current`
- [x] Monorepo structure
- [x] Spring Boot backend with JWT authentication
- [x] AI Service architecture (12 modules, 54 files)
- [ ] Core module implementation (config, logging, exceptions)
- [ ] Pydantic schemas (SARIF / Patch validation)
- [ ] RabbitMQ broker integration

### Phase 2 — AI Engine
- [ ] LangGraph multi-agent workflow
- [ ] Analyst, Coder, Reviewer, Enricher agents
- [ ] RAG pipeline with Pinecone
- [ ] Semantic cache with Redis
- [ ] NeMo Guardrails integration

### Phase 3 — Scanner Integration
- [ ] Semgrep integration
- [ ] CodeQL integration
- [ ] Trivy dependency scanning
- [ ] SARIF merge & deduplication engine
- [ ] CVE Intelligence Engine (NVD + MITRE + GitHub)

### Phase 4 — Backend Modules
- [ ] Project management module
- [ ] Scan lifecycle management
- [ ] Finding aggregation
- [ ] Patch suggestion storage
- [ ] Notification system (Slack, email)

### Phase 5 — Frontend & Polish
- [ ] React dashboard
- [ ] Real-time scan progress
- [ ] Interactive vulnerability explorer
- [ ] Patch diff viewer
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Kubernetes deployment manifests

---

## 🔒 Security Philosophy

MANTIS practices **security-by-design** at every layer:

- **Zero trust** — JWT required on every endpoint, STATELESS sessions
- **AI Safety** — NeMo Guardrails prevent the AI from generating malicious code
- **Secret management** — All credentials via environment variables, never in code
- **Input validation** — Pydantic schemas validate every data boundary
- **Audit trail** — Every scan, analysis, and patch is logged with timestamps

---

## 👥 Authors

<table>
  <tr>
    <td align="center">
      <strong>Ismail Allouch</strong><br/>
      Software & AI Engineer
    </td>
    <td align="center">
      <strong>Taha Ben Ahmadi</strong><br/>
      Software Engineer
    </td>
  </tr>
</table>

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>MANTIS</strong> — Because the best defense isn't just finding threats. It's understanding them.
</p>

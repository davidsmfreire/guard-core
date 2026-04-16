# @guardcore — Implementation Plan
> Grounded in the actual `guard-core` Python codebase.

---

## What This Is

A TypeScript port of `guard-core`. The Python codebase is the source of truth for features,
architecture, and behavior. This is not a reimagining — it's a faithful translation into
TypeScript idioms, with one key advantage: TypeScript is natively async throughout, so there
is no `sync/` namespace needed. One codebase serves all four framework adapters.

---

## Architecture Overview

The Python architecture has distinct layers. The TS port preserves them exactly:

```
Protocols (interfaces)
    ↓
Adapters (framework wrappers implementing those interfaces)
    ↓
SecurityMiddleware (framework-specific: Express / Fastify / NestJS / Hono)
    ↓ wires together:
    ├── HandlerInitializer       (startup: Redis, Agent, GeoIP, Cloud → HandlerRegistry)
    ├── SecurityCheckPipeline    (17 checks, sequential, first-block-wins)
    ├── SecurityEventBus         (agent telemetry, optional)
    ├── MetricsCollector         (performance metrics, optional)
    ├── RouteConfigResolver      (per-route decorator config)
    ├── RequestValidator         (path exclusion, HTTPS, proxy trust)
    ├── BypassHandler            (passthrough + security bypass)
    ├── BehavioralProcessor      (usage/return rules, post-response)
    └── ErrorResponseFactory     (responses + security headers + CORS on errors + custom modifier)
```

Individual handlers (managed by HandlerRegistry):
```
IPBanManager | RateLimitManager | CloudHandler | SusPatternsManager
SecurityHeadersManager | BehaviorTracker | RedisManager | DynamicRuleManager
```

Detection engine (used by SusPatternsManager):
```
PatternCompiler → ContentPreprocessor → SemanticAnalyzer → PerformanceMonitor
```

---

## Monorepo Structure

```
guardcore-ts/
├── packages/
│   ├── core/                           ← @guardcore/core
│   │   └── src/
│   │       ├── protocols/
│   │       │   ├── request.ts          ← GuardRequest interface
│   │       │   ├── response.ts         ← GuardResponse + GuardResponseFactory
│   │       │   ├── middleware.ts       ← GuardMiddlewareProtocol
│   │       │   ├── geo-ip.ts          ← GeoIPHandler
│   │       │   ├── agent.ts           ← AgentHandlerProtocol
│   │       │   └── redis.ts           ← RedisHandlerProtocol
│   │       ├── models/
│   │       │   ├── config.ts           ← SecurityConfig (Zod schema)
│   │       │   ├── route-config.ts     ← RouteConfig class
│   │       │   ├── behavior-rule.ts    ← BehaviorRule class
│   │       │   └── dynamic-rules.ts    ← DynamicRules model (Zod schema)
│   │       ├── handlers/
│   │       │   ├── registry.ts         ← HandlerRegistry type
│   │       │   ├── ip-ban.ts
│   │       │   ├── rate-limit.ts       ← includes Redis Lua script for atomic operations
│   │       │   ├── cloud.ts
│   │       │   ├── sus-patterns.ts     ← SusPatternsManager
│   │       │   ├── security-headers.ts
│   │       │   ├── behavior.ts         ← BehaviorTracker
│   │       │   ├── redis.ts            ← RedisManager
│   │       │   ├── dynamic-rules.ts    ← DynamicRuleManager
│   │       │   └── geoip.ts            ← IPInfoManager (default GeoIPHandler)
│   │       ├── detection-engine/
│   │       │   ├── compiler.ts         ← PatternCompiler (re2-wasm + worker_threads fallback)
│   │       │   ├── preprocessor.ts     ← ContentPreprocessor
│   │       │   ├── semantic.ts         ← SemanticAnalyzer
│   │       │   └── monitor.ts          ← PerformanceMonitor
│   │       ├── core/
│   │       │   ├── checks/
│   │       │   │   ├── base.ts         ← SecurityCheck abstract class
│   │       │   │   ├── pipeline.ts     ← SecurityCheckPipeline
│   │       │   │   ├── helpers.ts      ← shared check utilities (IP, auth, referrer, UA, detection)
│   │       │   │   └── implementations/
│   │       │   │       ├── route-config.ts
│   │       │   │       ├── emergency-mode.ts
│   │       │   │       ├── https-enforcement.ts
│   │       │   │       ├── request-logging.ts
│   │       │   │       ├── request-size-content.ts
│   │       │   │       ├── required-headers.ts
│   │       │   │       ├── authentication.ts
│   │       │   │       ├── referrer.ts
│   │       │   │       ├── custom-validators.ts
│   │       │   │       ├── time-window.ts
│   │       │   │       ├── cloud-ip-refresh.ts
│   │       │   │       ├── ip-security.ts
│   │       │   │       ├── cloud-provider.ts
│   │       │   │       ├── user-agent.ts
│   │       │   │       ├── rate-limit.ts
│   │       │   │       ├── suspicious-activity.ts
│   │       │   │       └── custom-request.ts
│   │       │   ├── events/
│   │       │   │   ├── event-bus.ts    ← SecurityEventBus
│   │       │   │   └── metrics.ts      ← MetricsCollector
│   │       │   ├── initialization/
│   │       │   │   └── handler-initializer.ts
│   │       │   ├── routing/
│   │       │   │   ├── context.ts
│   │       │   │   └── resolver.ts     ← RouteConfigResolver
│   │       │   ├── validation/
│   │       │   │   ├── context.ts
│   │       │   │   └── validator.ts    ← RequestValidator
│   │       │   ├── bypass/
│   │       │   │   ├── context.ts
│   │       │   │   └── handler.ts      ← BypassHandler
│   │       │   ├── behavioral/
│   │       │   │   ├── context.ts
│   │       │   │   └── processor.ts    ← BehavioralProcessor
│   │       │   └── responses/
│   │       │       ├── context.ts
│   │       │       └── factory.ts      ← ErrorResponseFactory
│   │       ├── decorators/
│   │       │   ├── base.ts
│   │       │   ├── access-control.ts
│   │       │   ├── rate-limiting.ts
│   │       │   ├── authentication.ts
│   │       │   ├── content-filtering.ts
│   │       │   ├── behavioral.ts
│   │       │   └── advanced.ts
│   │       ├── utils.ts
│   │       └── index.ts
│   ├── express/                        ← @guardcore/express
│   ├── fastify/                        ← @guardcore/fastify
│   ├── nestjs/                         ← @guardcore/nestjs
│   └── hono/                           ← @guardcore/hono
├── fixtures/                           ← shared test data (JSON, exported from Python)
├── pnpm-workspace.yaml
├── turbo.json
├── tsconfig.base.json
└── package.json
```

---

## Tooling

| Tool | Purpose |
|------|---------|
| `pnpm` + workspaces | Package management |
| `turborepo` | Build orchestration, caching |
| `tsup` | Library bundler — ESM + CJS output |
| `vitest` | Testing — TS-native, fast |
| `zod` | Runtime config validation (replaces Pydantic) |
| `ioredis` | Redis client (Node environments, async throughout) |
| `lru-cache` | TTL-based in-memory caching (replaces Python's `cachetools.TTLCache`) |
| `maxmind` | GeoIP — same `.mmdb` format as Python side (Node-only) |
| `ipaddr.js` | IP address + CIDR parsing |
| `he` | HTML entity decoding in ContentPreprocessor |
| `acorn` | JS AST parsing in SemanticAnalyzer |
| `re2-wasm` | Linear-time regex engine for ReDoS-safe pattern matching (edge-compatible) |
| `typescript` `^5.x` | Strict mode, `exactOptionalPropertyTypes` |

---

## Settled Decisions

**1. Package naming**
Scoped under `@guardcore`. Packages: `@guardcore/core`, `@guardcore/express`,
`@guardcore/fastify`, `@guardcore/nestjs`, `@guardcore/hono`. Scope prevents name
squatting and is the standard for multi-package ecosystems. Works with npm, pnpm, bun, yarn.

**2. ReDoS isolation**
`re2-wasm` is the primary regex engine. RE2 guarantees linear-time matching — no
catastrophic backtracking, ever. This is non-negotiable for a security library:
JavaScript is single-threaded, so a hanging regex blocks the entire event loop and
every connection with it. `re2-wasm` is edge-compatible (WebAssembly, no native addons).

For the rare pattern that requires backtracking features (lookaheads/lookbehinds) that
RE2 does not support, fall back to native `RegExp` executed inside a `worker_threads`
pool with hard timeout. The pool is persistent (created once at startup) with message
channels for zero-copy communication. This matches Python's `ThreadPoolExecutor` approach.

The `PatternCompiler` API exposes which engine was used per pattern so consumers can audit.

**3. GeoIP on edge**
`maxmind` requires Node `fs` — won't run on Cloudflare Workers or Deno. `SecurityConfig`
exposes a `geoResolver?: (ip: string) => string | null` field. Node environments populate this
via `IPInfoManager`. Edge environments pass `(ip) => c.req.raw.cf?.country ?? null` (Cloudflare)
or equivalent. `IPInfoManager` is the default when `geoIpHandler` is provided and
`geoResolver` is not.

**4. `ast.parse` equivalent in SemanticAnalyzer**
Python's `SemanticAnalyzer` uses `ast.parse(content, mode='eval')` to score code injection
risk. In v1, this is replaced by `acorn.parse()` for JS syntax detection — different language,
same intent: detect valid expression syntax as a code injection signal. The contribution to
the total threat score is small (~0.3 of a 1.0 max), so any approximation is acceptable.

**5. Express `call_next` response capture**
Starlette's `BaseHTTPMiddleware` returns a clean `Response` object from `call_next`.
Express middleware does not. The `@guardcore/express` adapter captures the outgoing
response by overriding `res.write` and `res.end` to buffer the body, enabling post-response
behavioral processing and the `customResponseModifier` hook. This is internal to the adapter —
consumers see no difference in the API. The Express adapter must also preserve the raw
request body (before body-parser) for accurate suspicious pattern detection.

**6. Edge-safe protocols**
All protocol types use `Uint8Array` instead of Node's `Buffer` for binary data. In Node,
`Buffer` extends `Uint8Array`, so Node adapters can return `Buffer` and it satisfies the
interface transparently. Edge adapters return `Uint8Array`. This ensures `@guardcore/core`
has zero Node-only type dependencies.

**7. CORS handling (split responsibility, matching Python)**
Core's `ErrorResponseFactory` applies CORS headers to error/blocked responses — without
this, browsers get an opaque network error instead of a readable 403. Each adapter
exposes a `configureCors(app, config)` helper that wires the framework's native CORS
middleware using fields from `SecurityConfig`:
- Express → `cors` package
- Fastify → `@fastify/cors`
- NestJS → built-in `app.enableCors()`
- Hono → `hono/cors`

`SecurityConfig` CORS fields are the single source of truth. Users must NOT also configure
CORS separately or they will get duplicate headers. This is documented prominently.

**8. Redis features are Node-only**
`ioredis` does not run on edge runtimes. Redis-dependent features (distributed rate limiting,
shared IP bans, cloud IP caching) require Node. Edge deployments operate in in-memory-only
mode. The `HandlerInitializer` gracefully skips Redis initialization when the runtime does not
support it. This is documented per-feature.

**9. Rate limiting uses Redis Lua scripts for atomicity**
The Python `RateLimitHandler` uses a Lua script (`RATE_LIMIT_SCRIPT`) for atomic
sliding-window rate limiting in Redis. The TS port replicates this via `ioredis`
`eval`/`evalsha`. The Lua script is identical — it's Redis-side, language-agnostic.

**10. Handler lifecycle: HandlerRegistry (no global singletons)**
Python uses `__new__` singletons for all 8 handlers. The TS port replaces this with a
`HandlerRegistry` pattern:
- `HandlerInitializer.initialize(config)` creates all handler instances and returns a
  `HandlerRegistry` object holding: `redisHandler`, `ipBanHandler`, `rateLimitHandler`,
  `cloudHandler`, `susPatternsHandler`, `securityHeadersHandler`, `behaviorTracker`,
  `dynamicRuleHandler`, `geoIpHandler`
- The middleware stores the registry and exposes handlers via `GuardMiddlewareProtocol`
  properties (`this.middleware.rateLimitHandler`, etc.)
- Checks access handlers through the middleware protocol — same as Python
- No global state, no `static getInstance()`, parallel-test-safe
- Tests create a fresh `HandlerInitializer` per test case — zero shared state

This is not a behavioral change: Python's checks already access handlers through the
middleware protocol, not by calling `getInstance()` directly. The singleton is an internal
implementation detail that users never interact with. Dropping it formalizes what's already true.

**11. Logging strategy**
`SecurityConfig` accepts an optional `logger` field conforming to a `Logger` interface
(methods: `info`, `warn`, `error`, `debug`). Default: a minimal console-based logger.
Users can plug in `pino`, `winston`, or any compatible logger. This keeps core
runtime-agnostic (no dependency on Node's `process.stdout`).

---

## Intentional Omissions from Python

These Python fields/features are NOT ported. Each omission is deliberate:

| Python field | Reason |
|-------------|--------|
| `ipinfo_token` | Deprecated in Python. Replaced by `geoIpHandler` protocol. |
| `ipinfo_db_path` | Deprecated. `IPInfoManager` manages DB path internally. |
| `to_agent_config()` | Agent is stubbed in v1 — no consumer for this factory method. |
| `sync/` namespace | TS is natively async. Not needed. |
| Python `test_sync/` tests | Tests the sync namespace. No equivalent in TS. |

---

## Pre-Implementation Steps

### RE2 Pattern Validation Script

Before any implementation begins, validate all patterns against RE2:

1. Export all pattern strings from `guard_core/handlers/suspatterns_handler.py` to JSON
2. Also export patterns from `ContentPreprocessor.attack_indicators` and `PatternCompiler` safety checks
3. Load in Node.js, attempt `new RE2(pattern, 'gim')` compilation for each
4. Log failures — those patterns need the `worker_threads` fallback path
5. Verify `(?i)` inline flag behavior in RE2-wasm (RE2 applies it to entire pattern, not as toggle)

### Test Fixture Export Script

Python script to export shared test data to `fixtures/*.json`:

- All suspicious pattern strings + their context sets
- Attack payloads from the Python test suite
- `SemanticAnalyzer.attack_keywords` dict (5 categories, 50+ keywords)
- `SecurityHeadersManager.default_headers` dict (10 headers)
- `ContentPreprocessor.attack_indicators` list (21 patterns)
- 10-20 "golden" inputs with expected detection outcomes

Both Python and TS test suites load from the same fixtures for cross-language parity validation.

---

## Phase 0 — Monorepo Bootstrap

```bash
mkdir guardcore-ts && cd guardcore-ts
pnpm init
pnpm add -D turbo typescript tsup vitest
mkdir -p packages/{core,express,fastify,nestjs,hono}
```

**`pnpm-workspace.yaml`**
```yaml
packages:
  - 'packages/*'
```

**`turbo.json`**
```json
{
  "$schema": "https://turbo.build/schema.json",
  "tasks": {
    "build": { "dependsOn": ["^build"], "outputs": ["dist/**"] },
    "test":  { "dependsOn": ["^build"] },
    "lint":  {}
  }
}
```

**`tsconfig.base.json`**
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "exactOptionalPropertyTypes": true,
    "declaration": true,
    "skipLibCheck": true
  }
}
```

---

## Phase 1 — `@guardcore/core`

Do not touch adapters until this is complete and tested.

### 1.1 Protocols

Direct translation of Python's `@runtime_checkable Protocol` classes into TypeScript interfaces.
Python has 6 protocols; all 6 are ported.

```typescript
// protocols/request.ts
export interface GuardRequest {
  readonly urlPath: string;
  readonly urlScheme: string;
  readonly urlFull: string;
  urlReplaceScheme(scheme: string): string;
  readonly method: string;
  readonly clientHost: string | null;
  readonly headers: Readonly<Record<string, string>>;
  readonly queryParams: Readonly<Record<string, string>>;
  body(): Promise<Uint8Array>;
  readonly state: GuardRequestState;
  readonly scope?: Readonly<Record<string, unknown>>;
}

export interface GuardRequestState {
  guardRouteId?: string;
  guardEndpointId?: string;
  guardDecorator?: BaseSecurityDecorator;
  [key: string]: unknown;
}

// protocols/response.ts
export interface GuardResponse {
  readonly statusCode: number;
  readonly headers: Record<string, string>;
  setHeader(name: string, value: string): void;
  readonly body: Uint8Array | null;
  readonly bodyText: string | null;
}

export interface GuardResponseFactory {
  createResponse(content: string, statusCode: number): GuardResponse;
  createRedirectResponse(url: string, statusCode: number): GuardResponse;
}

// protocols/middleware.ts
export interface GuardMiddlewareProtocol {
  readonly config: ResolvedSecurityConfig;
  readonly logger: Logger;
  lastCloudIpRefresh: number;
  suspiciousRequestCounts: Map<string, number>;
  readonly eventBus: SecurityEventBus;
  readonly routeResolver: RouteConfigResolver;
  readonly responseFactory: ErrorResponseFactory;
  readonly rateLimitHandler: RateLimitManager;
  readonly agentHandler: AgentHandlerProtocol | null;
  readonly geoIpHandler: GeoIPHandler | null;
  readonly guardResponseFactory: GuardResponseFactory;
  createErrorResponse(statusCode: number, defaultMessage: string): Promise<GuardResponse>;
  refreshCloudIpRanges(): Promise<void>;
}

// protocols/geo-ip.ts
export interface GeoIPHandler {
  readonly isInitialized: boolean;
  initialize(): Promise<void>;
  initializeRedis(redisHandler: RedisHandlerProtocol): Promise<void>;
  initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void>;
  getCountry(ip: string): string | null;
}

// protocols/agent.ts
export interface AgentHandlerProtocol {
  initializeRedis(redisHandler: RedisHandlerProtocol): Promise<void>;
  sendEvent(event: unknown): Promise<void>;
  sendMetric(metric: unknown): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  flushBuffer(): Promise<void>;
  getDynamicRules(): Promise<unknown | null>;
  healthCheck(): Promise<boolean>;
}

// protocols/redis.ts
export interface RedisHandlerProtocol {
  getKey(namespace: string, key: string): Promise<unknown>;
  setKey(namespace: string, key: string, value: unknown, ttl?: number): Promise<boolean | null>;
  delete(namespace: string, key: string): Promise<number | null>;
  keys(pattern: string): Promise<string[] | null>;
  initialize(): Promise<void>;
  getConnection(): AsyncDisposable;
}
```

### 1.2 SecurityConfig (Zod)

Full translation of Python's `SecurityConfig` Pydantic model. Every field, every validator.
Python has 47 fields; 44 are ported (3 deprecated fields omitted — see Intentional Omissions).

```typescript
// models/config.ts
import { z } from 'zod';

const IpOrCidrSchema = z.string().refine(isValidIpOrCidr, 'Invalid IP or CIDR');

export const SecurityConfigSchema = z.object({
  // Proxy
  trustedProxies:         z.array(IpOrCidrSchema).default([]),
  trustedProxyDepth:      z.number().int().min(1).default(1),
  trustXForwardedProto:   z.boolean().default(false),

  // Mode
  passiveMode:            z.boolean().default(false),

  // GeoIP
  geoIpHandler:           z.custom<GeoIPHandler>().optional(),
  geoResolver:            z.custom<(ip: string) => string | null>().optional(),

  // Redis
  enableRedis:            z.boolean().default(true),
  redisUrl:               z.string().url().default('redis://localhost:6379'),
  redisPrefix:            z.string().default('guard_core:'),

  // IP filtering
  whitelist:              z.array(IpOrCidrSchema).nullable().default(null),
  blacklist:              z.array(IpOrCidrSchema).default([]),

  // Country filtering
  whitelistCountries:     z.array(z.string().length(2)).default([]),
  blockedCountries:       z.array(z.string().length(2)).default([]),

  // User agent
  blockedUserAgents:      z.array(z.string()).default([]),

  // Auto-ban
  autoBanThreshold:       z.number().int().positive().default(10),
  autoBanDuration:        z.number().int().positive().default(3600),

  // Logging
  logger:                 z.custom<Logger>().optional(),
  customLogFile:          z.string().nullable().default(null),
  logSuspiciousLevel:     z.enum(['INFO','DEBUG','WARNING','ERROR','CRITICAL']).nullable().default('WARNING'),
  logRequestLevel:        z.enum(['INFO','DEBUG','WARNING','ERROR','CRITICAL']).nullable().default(null),
  logFormat:              z.enum(['text', 'json']).default('text'),

  // Error responses
  customErrorResponses:   z.record(z.coerce.number(), z.string()).default({}),

  // Rate limiting
  rateLimit:              z.number().int().positive().default(10),
  rateLimitWindow:        z.number().int().positive().default(60),

  // HTTPS
  enforceHttps:           z.boolean().default(false),

  // Security headers
  securityHeaders: z.object({
    enabled:              z.boolean().default(true),
    hsts: z.object({
      maxAge:             z.number().default(31536000),
      includeSubdomains:  z.boolean().default(true),
      preload:            z.boolean().default(false),
    }).optional(),
    csp:                  z.record(z.string(), z.array(z.string())).nullable().default(null),
    frameOptions:         z.enum(['DENY', 'SAMEORIGIN']).default('SAMEORIGIN'),
    contentTypeOptions:   z.string().default('nosniff'),
    xssProtection:        z.string().default('1; mode=block'),
    referrerPolicy:       z.string().default('strict-origin-when-cross-origin'),
    permissionsPolicy:    z.string().default('geolocation=(), microphone=(), camera=()'),
    custom:               z.record(z.string(), z.string()).nullable().default(null),
  }).nullable().default({
    enabled: true, frameOptions: 'SAMEORIGIN', contentTypeOptions: 'nosniff',
    xssProtection: '1; mode=block', referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'geolocation=(), microphone=(), camera=()', csp: null, custom: null,
  }),

  // Custom hooks
  customRequestCheck: z.custom<(req: GuardRequest) => Promise<GuardResponse | null>>().optional(),
  customResponseModifier: z.custom<(res: GuardResponse) => Promise<GuardResponse>>().optional(),

  // CORS
  enableCors:             z.boolean().default(false),
  corsAllowOrigins:       z.array(z.string()).default(['*']),
  corsAllowMethods:       z.array(z.string()).default(['GET','POST','PUT','PATCH','DELETE','OPTIONS']),
  corsAllowHeaders:       z.array(z.string()).default(['*']),
  corsAllowCredentials:   z.boolean().default(false),
  corsExposeHeaders:      z.array(z.string()).default([]),
  corsMaxAge:             z.number().int().positive().default(600),

  // Cloud provider blocking
  blockCloudProviders:    z.set(z.enum(['AWS','GCP','Azure'])).default(new Set()),
  cloudIpRefreshInterval: z.number().int().min(60).max(86400).default(3600),

  // Excluded paths — empty by default, framework adapters may suggest defaults in their docs
  excludePaths: z.array(z.string()).default([]),

  // Feature flags
  enableIpBanning:            z.boolean().default(true),
  enableRateLimiting:         z.boolean().default(true),
  enablePenetrationDetection: z.boolean().default(true),

  // Emergency mode
  emergencyMode:       z.boolean().default(false),
  emergencyWhitelist:  z.array(z.string()).default([]),

  // Per-endpoint rate limits
  endpointRateLimits:  z.record(z.string(), z.tuple([z.number(), z.number()])).default({}),

  // Detection engine tuning
  detectionCompilerTimeout:        z.number().min(0.1).max(10).default(2.0),
  detectionMaxContentLength:       z.number().int().min(1000).max(100000).default(10000),
  detectionPreserveAttackPatterns: z.boolean().default(true),
  detectionSemanticThreshold:      z.number().min(0).max(1).default(0.7),
  detectionAnomalyThreshold:       z.number().min(1).max(10).default(3.0),
  detectionSlowPatternThreshold:   z.number().min(0.01).max(1).default(0.1),
  detectionMonitorHistorySize:     z.number().int().min(100).max(10000).default(1000),
  detectionMaxTrackedPatterns:     z.number().int().min(100).max(5000).default(1000),

  // Agent / SaaS
  enableAgent:         z.boolean().default(false),
  agentApiKey:         z.string().nullable().default(null),
  agentEndpoint:       z.string().url().default('https://api.fastapi-guard.com'),
  agentProjectId:      z.string().nullable().default(null),
  agentBufferSize:     z.number().int().positive().default(100),
  agentFlushInterval:  z.number().int().positive().default(30),
  agentEnableEvents:   z.boolean().default(true),
  agentEnableMetrics:  z.boolean().default(true),
  agentTimeout:        z.number().int().positive().default(30),
  agentRetryAttempts:  z.number().int().nonnegative().default(3),

  // Dynamic rules
  enableDynamicRules:  z.boolean().default(false),
  dynamicRuleInterval: z.number().int().positive().default(300),

}).superRefine((data, ctx) => {
  if (data.enableAgent && !data.agentApiKey) {
    ctx.addIssue({ code: 'custom', message: 'agentApiKey required when enableAgent is true' });
  }
  if (data.enableDynamicRules && !data.enableAgent) {
    ctx.addIssue({ code: 'custom', message: 'enableAgent must be true when enableDynamicRules is true' });
  }
  if ((data.blockedCountries.length || data.whitelistCountries.length) && !data.geoIpHandler && !data.geoResolver) {
    ctx.addIssue({ code: 'custom', message: 'geoIpHandler or geoResolver required when using country filtering' });
  }
});

export type SecurityConfig = z.input<typeof SecurityConfigSchema>;
export type ResolvedSecurityConfig = z.output<typeof SecurityConfigSchema>;
```

### 1.3 RouteConfig

Python has 21 properties. All 21 ported.

```typescript
// models/route-config.ts
export class RouteConfig {
  rateLimit: number | null = null;
  rateLimitWindow: number | null = null;
  ipWhitelist: string[] | null = null;
  ipBlacklist: string[] | null = null;
  blockedCountries: string[] | null = null;
  whitelistCountries: string[] | null = null;
  bypassedChecks: Set<string> = new Set();
  requireHttps = false;
  authRequired: string | null = null;
  customValidators: Array<(...args: unknown[]) => unknown> = [];
  blockedUserAgents: string[] = [];
  requiredHeaders: Record<string, string> = {};
  behaviorRules: BehaviorRule[] = [];
  blockCloudProviders: Set<string> = new Set();
  maxRequestSize: number | null = null;
  allowedContentTypes: string[] | null = null;
  timeRestrictions: { start: string; end: string } | null = null;
  enableSuspiciousDetection = true;
  requireReferrer: string[] | null = null;
  apiKeyRequired = false;
  sessionLimits: Record<string, number> | null = null;
  geoRateLimits: Record<string, [number, number]> | null = null;
}
```

### 1.4 DynamicRules

Flat schema matching Python's 20 fields for wire-format parity with the agent SaaS backend.

```typescript
// models/dynamic-rules.ts
import { z } from 'zod';

export const DynamicRulesSchema = z.object({
  ruleId: z.string(),
  version: z.number().int(),
  timestamp: z.string().datetime(),
  expiresAt: z.string().datetime().nullable().default(null),
  ttl: z.number().int().default(300),
  ipBlacklist: z.array(z.string()).default([]),
  ipWhitelist: z.array(z.string()).default([]),
  ipBanDuration: z.number().int().default(3600),
  blockedCountries: z.array(z.string().length(2)).default([]),
  whitelistCountries: z.array(z.string().length(2)).default([]),
  globalRateLimit: z.number().int().nullable().default(null),
  globalRateWindow: z.number().int().nullable().default(null),
  endpointRateLimits: z.record(z.string(), z.tuple([z.number(), z.number()])).default({}),
  blockedCloudProviders: z.set(z.enum(['AWS','GCP','Azure'])).default(new Set()),
  blockedUserAgents: z.array(z.string()).default([]),
  suspiciousPatterns: z.array(z.string()).default([]),
  enablePenetrationDetection: z.boolean().nullable().default(null),
  enableIpBanning: z.boolean().nullable().default(null),
  enableRateLimiting: z.boolean().nullable().default(null),
  emergencyMode: z.boolean().default(false),
  emergencyWhitelist: z.array(z.string()).default([]),
});

export type DynamicRules = z.output<typeof DynamicRulesSchema>;
```

### 1.5 Detection Engine

**`PatternCompiler`** — LRU-cached regex compilation. `re2-wasm` as primary engine for
guaranteed linear-time matching. Native `RegExp` via `worker_threads` pool as fallback
for patterns requiring backtracking features (lookaheads/lookbehinds).

```typescript
// detection-engine/compiler.ts
import RE2 from 're2-wasm';

export class PatternCompiler {
  private cache = new Map<string, RE2 | RegExp>();
  private cacheOrder: string[] = [];
  private workerPool: RegexWorkerPool | null = null;

  constructor(
    private readonly defaultTimeoutMs = 2000,
    private readonly maxCacheSize = 1000,
  ) {}

  compile(pattern: string, flags = 'gi'): RE2 {
    const key = `${pattern}:${flags}`;
    if (this.cache.has(key)) {
      this.cacheOrder.splice(this.cacheOrder.indexOf(key), 1);
      this.cacheOrder.push(key);
      return this.cache.get(key) as RE2;
    }
    if (this.cache.size >= this.maxCacheSize) {
      this.cache.delete(this.cacheOrder.shift()!);
    }
    const re = new RE2(pattern, flags);
    this.cache.set(key, re);
    this.cacheOrder.push(key);
    return re;
  }

  async safeMatch(
    pattern: string,
    content: string,
    timeoutMs?: number,
  ): Promise<RegExpExecArray | null> {
    try {
      return this.compile(pattern).exec(content);
    } catch {
      return this.fallbackMatch(pattern, content, timeoutMs ?? this.defaultTimeoutMs);
    }
  }

  private async fallbackMatch(
    pattern: string,
    content: string,
    timeoutMs: number,
  ): Promise<RegExpExecArray | null> {
    if (!this.workerPool) {
      this.workerPool = new RegexWorkerPool();
    }
    return this.workerPool.exec(pattern, content, timeoutMs);
  }

  validatePatternSafety(pattern: string, testStrings?: string[]): [boolean, string] {
    // Port from Python: detect dangerous constructs (nested quantifiers, etc.)
    // Test against default strings with timeout
    // Returns [isSafe, reason]
  }

  async batchCompile(patterns: string[], validate = false): Promise<Map<string, RE2 | RegExp>> {
    // Compile multiple patterns, optionally validate safety
  }

  async clearCache(): Promise<void> {
    this.cache.clear();
    this.cacheOrder = [];
  }

  async destroy(): Promise<void> {
    await this.workerPool?.terminate();
  }
}
```

**`ContentPreprocessor`** — Unicode normalization, URL/HTML entity decoding (via `he`),
null byte removal, attack-region-aware truncation. Port all lookalike maps (25 mappings)
and attack indicator patterns (21 patterns) verbatim from Python.

**`SemanticAnalyzer`** — Token-based attack probability (XSS, SQLi, command, path, template),
entropy calculation, obfuscation detection, encoding layer counting, code injection risk.
The Python `ast.parse` check is replaced with `acorn.parse()` for JS syntax detection.
The signal is equivalent: valid parseable expression syntax in unexpected content = elevated
code injection risk score.

Threat score calculation (matching Python):
- `max(attack_probs) * 0.3 + is_obfuscated * 0.2 + encoding_layers * 0.1 + injection_risk * 0.2 + pattern_count * 0.05`
- Clamped to [0.0, 1.0]

**`PerformanceMonitor`** — Rolling window of execution times per pattern. Anomaly detection
via Z-score: `(execution_time - mean(recent_times)) / stdev(recent_times)`. Three anomaly types:
timeout, slow execution (> `detectionSlowPatternThreshold`), statistical (Z-score > `detectionAnomalyThreshold`).

### 1.6 SusPatternsManager

All `_pattern_definitions` from Python ported verbatim — they're regex strings,
they work identically in RE2 (validated by pre-implementation script). Context sets
(`CTX_XSS`, `CTX_SQLI`, `CTX_DIR_TRAVERSAL`, `CTX_CMD_INJECTION`, etc.) become `ReadonlySet<string>`.
Context values: `query_param`, `header`, `url_path`, `request_body`, `unknown`.

`detect()` flow: preprocess → regex patterns with context filtering → semantic analysis →
combine scores → emit agent event if threat.

```typescript
// handlers/sus-patterns.ts
export class SusPatternsManager {
  private compiler: PatternCompiler;
  private preprocessor: ContentPreprocessor;
  private semantic: SemanticAnalyzer;
  private monitor: PerformanceMonitor;
  private redisHandler: RedisHandlerProtocol | null = null;
  private agentHandler: AgentHandlerProtocol | null = null;
  private semanticThreshold: number;

  private readonly patternDefinitions: Array<[string, ReadonlySet<string>]> = [
    [String.raw`<script[^>]*>[^<]*<\/script\s*>`, CTX_XSS],
    [String.raw`javascript:\s*[^\s]+`, CTX_XSS],
    // ... complete list — all entries ported verbatim from Python
    // Exact count verified by RE2 validation script
  ];

  constructor(config: ResolvedSecurityConfig) {
    // Normal constructor, no singleton — managed by HandlerRegistry
  }

  async detect(content: string, ipAddress: string, context = 'unknown', correlationId?: string): Promise<DetectionResult> {
    const processed = await this.preprocessor.preprocess(content);
    const [regexThreats, timeouts] = await this.checkRegexPatterns(processed, ipAddress, correlationId, context);
    const [semanticThreats] = await this.checkSemanticThreats(processed);
    const threats = [...regexThreats, ...semanticThreats];
    const isThreat = threats.length > 0;
    if (isThreat) await this.sendThreatEvent(/* ... */);
    return { isThreat, threats, timeouts, /* ... */ };
  }
}
```

### 1.7 SecurityCheck (ABC) + SecurityCheckPipeline

```typescript
// core/checks/base.ts
export abstract class SecurityCheck {
  constructor(protected readonly middleware: GuardMiddlewareProtocol) {}

  abstract check(request: GuardRequest): Promise<GuardResponse | null>;
  abstract get checkName(): string;

  protected get config() { return this.middleware.config; }
  protected get logger() { return this.middleware.logger; }

  async sendEvent(type: string, request: GuardRequest, action: string, reason: string, meta?: Record<string, unknown>): Promise<void> {
    await this.middleware.eventBus.sendMiddlewareEvent(type, request, action, reason, meta);
  }

  async createErrorResponse(statusCode: number, message: string): Promise<GuardResponse> {
    return this.middleware.createErrorResponse(statusCode, message);
  }

  isPassiveMode(): boolean { return this.config.passiveMode; }
}

// core/checks/pipeline.ts
export class SecurityCheckPipeline {
  constructor(private checks: SecurityCheck[]) {}

  async execute(request: GuardRequest): Promise<GuardResponse | null> {
    for (const check of this.checks) {
      try {
        const response = await check.check(request);
        if (response !== null) return response;
      } catch (e) {
        // log + fail-secure if configured, otherwise continue
      }
    }
    return null;
  }

  add(check: SecurityCheck): void { this.checks.push(check); }
  insert(index: number, check: SecurityCheck): void { this.checks.splice(index, 0, check); }
  remove(name: string): boolean { /* ... */ return false; }
  getCheckNames(): string[] { return this.checks.map(c => c.checkName); }
}
```

### 1.8 Check Helpers

Shared utility functions used by multiple check implementations.
Source: `guard_core/core/checks/helpers.py`.

```typescript
// core/checks/helpers.ts
function isIpInBlacklist(clientIp: string, ipAddr: object, blacklist: string[]): boolean
function isIpInWhitelist(clientIp: string, ipAddr: object, whitelist: string[]): boolean | null
function checkCountryAccess(clientIp: string, routeConfig: RouteConfig, geoIpHandler: GeoIPHandler | null): boolean | null
async function checkRouteIpAccess(clientIp: string, routeConfig: RouteConfig, middleware: GuardMiddlewareProtocol): Promise<boolean | null>
async function checkUserAgentAllowed(userAgent: string, routeConfig: RouteConfig | null, config: ResolvedSecurityConfig): Promise<boolean>
function validateAuthHeader(authHeader: string, authType: string): [boolean, string]
function isReferrerDomainAllowed(referrer: string, allowedDomains: string[]): boolean
async function detectPenetrationPatterns(request: GuardRequest, routeConfig: RouteConfig | null, config: ResolvedSecurityConfig, shouldBypassCheckFn: (check: string, rc: RouteConfig | null) => boolean): Promise<[boolean, string]>
```

### 1.9 The 17 Check Implementations

Port in pipeline order:

| # | Check | Key logic |
|---|-------|-----------|
| 1 | `RouteConfigCheck` | Stamps `guardRouteId` + `guardEndpointId` onto `request.state` |
| 2 | `EmergencyModeCheck` | Block all unless IP is in `emergencyWhitelist` |
| 3 | `HttpsEnforcementCheck` | Redirect HTTP → HTTPS; respects trusted proxy + X-Forwarded-Proto |
| 4 | `RequestLoggingCheck` | Log at `logRequestLevel`; fires `request_logged` event |
| 5 | `RequestSizeContentCheck` | `Content-Length` header + body size + content type filtering |
| 6 | `RequiredHeadersCheck` | Per-route `requiredHeaders` map validation |
| 7 | `AuthenticationCheck` | Bearer token + API key auth; per-route and global |
| 8 | `ReferrerCheck` | Per-route `requireReferrer` list |
| 9 | `CustomValidatorsCheck` | Per-route `customValidators` function list |
| 10 | `TimeWindowCheck` | Per-route `timeRestrictions` (HH:MM start/end in UTC) |
| 11 | `CloudIpRefreshCheck` | Periodic refresh of AWS/GCP/Azure IP ranges |
| 12 | `IpSecurityCheck` | Whitelist, blacklist, CIDR, auto-ban lookup |
| 13 | `CloudProviderCheck` | Check IP against cached cloud provider ranges |
| 14 | `UserAgentCheck` | Global + per-route UA pattern matching |
| 15 | `RateLimitCheck` | Global + per-route + per-endpoint + geo rate limits |
| 16 | `SuspiciousActivityCheck` | Full detection: preprocessor → regex → semantic |
| 17 | `CustomRequestCheck` | Config-level `customRequestCheck` hook |

### 1.10 Supporting Subsystems

**`HandlerInitializer`** — async `initialize()` called once at startup. Creates all handlers
and returns a `HandlerRegistry`. Initializes Redis, agent, cloud handler, GeoIP, rate limiter,
dynamic rules. Idempotent. Gracefully skips Redis when running on edge runtimes.

**`SecurityEventBus`** — no-op when `agentHandler` is null. All methods are async and
never throw. Agent events include: `request_logged`, `https_enforced`, `path_excluded`,
`security_bypass`, `cloud_detection`, `decorator_violation`, `pattern_detected`, etc.

**`MetricsCollector`** — tracks response time, request count, error rate per endpoint.
No-op when `agentHandler` is null.

**`ErrorResponseFactory`** — applies security headers to every response (allowed + blocked),
CORS headers to error responses per origin (see Settled Decision #7), custom response modifier
hook, behavioral return-rule processing, metrics collection. Runs on every response without exception.

**`RouteConfigResolver`** — reads `request.state.guardRouteId`, looks up `RouteConfig`
from `BaseSecurityDecorator.routeConfigs`. Resolves effective cloud provider set for a route
(per-route takes priority over global).

**`BypassHandler`** — passthrough (no client host, excluded path) and security bypass
(`@bypass(['all'])` decorator). Both still apply custom response modifier.

**`BehavioralProcessor`** — post-response. Tracks usage counts and return patterns per
endpoint+IP. Applies ban/log/throttle/alert actions. Uses Redis when available.

**`RequestValidator`** — path exclusion check, HTTPS detection, trusted proxy logic.

### 1.11 Decorators

`BaseSecurityDecorator` stamps a unique route ID onto handler functions using a `WeakMap`
keyed by function reference — this avoids the fragility of relying on `fn.name` (which
fails for arrow functions and is destroyed by minification). Mixin composition via
TypeScript mixin pattern:

```typescript
// decorators/base.ts
const routeIdMap = new WeakMap<Function, string>();
let routeIdCounter = 0;

export class BaseSecurityDecorator {
  protected routeConfigs = new Map<string, RouteConfig>();
  behaviorTracker: BehaviorTracker;
  agentHandler: AgentHandlerProtocol | null = null;

  constructor(readonly config: ResolvedSecurityConfig) {
    this.behaviorTracker = new BehaviorTracker(config);
  }

  getRouteConfig(routeId: string): RouteConfig | undefined {
    return this.routeConfigs.get(routeId);
  }

  protected ensureRouteConfig(fn: Function): RouteConfig {
    const id = this.getRouteId(fn);
    if (!this.routeConfigs.has(id)) {
      const rc = new RouteConfig();
      rc.enableSuspiciousDetection = this.config.enablePenetrationDetection;
      this.routeConfigs.set(id, rc);
    }
    return this.routeConfigs.get(id)!;
  }

  protected applyRouteConfig(fn: Function): void {
    (fn as any)._guardRouteId = this.getRouteId(fn);
  }

  private getRouteId(fn: Function): string {
    if (!routeIdMap.has(fn)) {
      routeIdMap.set(fn, `guard_route_${++routeIdCounter}`);
    }
    return routeIdMap.get(fn)!;
  }

  async initializeBehaviorTracking(redisHandler?: RedisHandlerProtocol): Promise<void> {
    if (redisHandler) await this.behaviorTracker.initializeRedis(redisHandler);
  }

  async initializeAgent(agentHandler: AgentHandlerProtocol): Promise<void> {
    this.agentHandler = agentHandler;
    await this.behaviorTracker.initializeAgent(agentHandler);
  }

  async sendDecoratorEvent(eventType: string, request: GuardRequest, actionTaken: string, reason: string, decoratorType: string, meta?: Record<string, unknown>): Promise<void> {
    if (!this.agentHandler) return;
    await this.agentHandler.sendEvent({ eventType, actionTaken, reason, decoratorType, ...meta });
  }

  async sendAccessDeniedEvent(request: GuardRequest, reason: string, decoratorType: string, meta?: Record<string, unknown>): Promise<void> {
    await this.sendDecoratorEvent('access_denied', request, 'request_blocked', reason, decoratorType, meta);
  }

  async sendAuthenticationFailedEvent(request: GuardRequest, reason: string, authType: string, meta?: Record<string, unknown>): Promise<void> {
    await this.sendDecoratorEvent('authentication_failed', request, 'request_blocked', reason, 'authentication', { authType, ...meta });
  }

  async sendRateLimitEvent(request: GuardRequest, limit: number, window: number, meta?: Record<string, unknown>): Promise<void> {
    await this.sendDecoratorEvent('rate_limit_exceeded', request, 'request_blocked', `Rate limit ${limit}/${window}s exceeded`, 'rate_limit', { limit, window, ...meta });
  }

  async sendDecoratorViolationEvent(request: GuardRequest, violationType: string, reason: string, meta?: Record<string, unknown>): Promise<void> {
    await this.sendDecoratorEvent('decorator_violation', request, 'request_blocked', reason, violationType, meta);
  }
}

// Final composed decorator — same API as Python's SecurityDecorator
export class SecurityDecorator extends Advanced(
  ContentFiltering(Behavioral(Authentication(RateLimiting(AccessControl(BaseSecurityDecorator)))))
) {}
```

**Mixin decorator methods (20 total across 6 mixins):**

| Mixin | Methods |
|-------|---------|
| `AccessControlMixin` | `requireIp(whitelist?, blacklist?)`, `blockCountries(countries)`, `allowCountries(countries)`, `blockClouds(providers?)`, `bypass(checks)` |
| `RateLimitingMixin` | `rateLimit(requests, window)`, `geoRateLimit(limits)` |
| `AuthenticationMixin` | `requireHttps()`, `requireAuth(type)`, `apiKeyAuth(headerName)`, `requireHeaders(headers)` |
| `ContentFilteringMixin` | `blockUserAgents(patterns)`, `contentTypeFilter(allowedTypes)`, `maxRequestSize(sizeBytes)`, `requireReferrer(allowedDomains)`, `customValidation(validator)` |
| `BehavioralMixin` | `usageMonitor(maxCalls, window, action)`, `returnMonitor(pattern, maxOccurrences, window, action)`, `behaviorAnalysis(rules)`, `suspiciousFrequency(maxFrequency, window, action)` |
| `AdvancedMixin` | `timeWindow(startTime, endTime, timezone)`, `suspiciousDetection(enabled)`, `honeypotDetection(trapFields)` |

### 1.12 Utils

Full utility module. Python has 33 functions; all are ported (grouped by concern).

**IP extraction and spoofing detection:**
- `extractClientIp(request, config, agentHandler?): Promise<string>` — trusted proxy chain, X-Forwarded-For, spoofing detection
- `isTrustedProxy(connectingIp, trustedProxies): boolean` — CIDR-aware proxy check
- `extractFromForwardedHeader(forwardedFor, proxyDepth): string | null`
- `checkIpSpoofing(connectingIp, forwardedFor, config, request, agentHandler): Promise<void>`

**IP validation:**
- `isIpAllowed(ip, config, geoIpHandler?): Promise<boolean>` — composite check (blacklist, whitelist, country, cloud)
- `checkIpCountry(request, config, geoIpHandler): Promise<boolean>` — returns true if blocked

**User agent:**
- `isUserAgentAllowed(userAgent, config): Promise<boolean>`

**Content/threat detection:**
- `detectPenetrationAttempt(request): Promise<[boolean, string]>` — checks query params, URL path, headers, body
- `checkValueEnhanced(value, context, clientIp, correlationId): Promise<[boolean, string]>` — JSON-aware detection
- `checkRequestComponent(value, context, componentName, clientIp, correlationId): Promise<[boolean, string]>`
- `checkJsonFields(data, context, clientIp, correlationId): Promise<[boolean, string]>` — recursive JSON traversal

**Logging:**
- `setupCustomLogging(logFile?, logFormat?): Logger`
- `logActivity(request, logger, logType?, reason?, passiveMode?, triggerInfo?, level?): Promise<void>`
- `sanitizeForLog(value): string` — escapes newlines, control chars
- `JsonFormatter` class — structured JSON log output

**Agent events:**
- `sendAgentEvent(agentHandler, eventType, ip, action, reason, request?, ...meta): Promise<void>`

**Penetration detection excluded headers:**
Skip: `host`, `user-agent`, `accept`, `accept-encoding`, `connection`, `origin`, `referer`, all `sec-fetch-*`, all `sec-ch-ua*`.

---

## Implementation-Level Detail

### Redis Key Patterns

Must match Python for cross-language Redis compatibility.

| Handler | Key Pattern | Value Type | TTL |
|---------|------------|------------|-----|
| RateLimitManager | `{prefix}rate_limit:rate:{ip}:{endpoint}` | Sorted set (scores=timestamps) | window * 2 |
| IPBanManager | `{prefix}banned_ips:{ip}` | String (expiry timestamp) | ban duration |
| CloudHandler | `{prefix}cloud_ranges:{provider}` | String (CSV of CIDRs) | configurable |
| IPInfoManager | `{prefix}ipinfo:database` | String (latin-1 encoded DB) | 86400s |
| BehaviorTracker | `{prefix}behavior:usage:{endpoint}:{client_ip}` | Key-value | rule window |
| BehaviorTracker | `{prefix}behavior:return:{endpoint}:{client_ip}:{pattern}` | Key-value | rule window |
| SecurityHeadersManager | `{prefix}security_headers:{config_type}` | JSON string | 86400s |
| SusPatternsManager | `{prefix}patterns:custom` | String (CSV) | none |
| RedisManager general | `{prefix}{namespace}:{key}` | varies | varies |

### Rate Limit Lua Script

Port verbatim — Redis-side, language-agnostic. Source: `guard_core/scripts/rate_lua.py`.

```lua
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('EXPIRE', key, window * 2)

return count
```

Load via `ioredis` `defineCommand()` or `script('load', ...)` + `evalsha()`.

### Cache Strategies

| Python | TS Equivalent |
|--------|--------------|
| `TTLCache(maxsize=10000, ttl=3600)` (IPBanManager) | `lru-cache` with `{max: 10000, ttl: 3_600_000}` |
| `TTLCache(maxsize=1000, ttl=300)` (SecurityHeadersManager) | `lru-cache` with `{max: 1000, ttl: 300_000}` |
| SHA256-based cache keys for headers | `crypto.subtle.digest('SHA-256', ...)` or `node:crypto` |
| `defaultdict(deque)` (RateLimitManager in-memory) | `Map<string, number[]>` with sliding window cleanup |
| `dict` (PatternCompiler LRU cache) | `Map<string, RE2 \| RegExp>` with manual LRU tracking |

### Behavior Pattern Matching Formats

Source: `guard_core/handlers/behavior_handler.py`. The `BehaviorTracker` checks response
content against patterns in these formats:

- `status:{code}` — match response HTTP status code (e.g., `status:200`)
- `json:{path.to.field}` — match value at JSON path in response body (e.g., `json:item.rarity`)
- `regex:{pattern}` — regex match on response body text (e.g., `regex:rare_sword`)

---

## Phase 2 — Framework Adapters

Each adapter: `adapters.ts` + `middleware.ts` + `cors.ts`. The adapter is the entire diff
between frameworks. Core security logic is identical across all four.

Each adapter wraps its framework's request/response behind `GuardRequest`/`GuardResponse`.
All adapters delegate IP extraction to core's `extractClientIp` — adapters only provide
`clientHost` (the immediate connecting IP) and core handles trusted proxies, proxy depth,
and spoofing detection.

### `@guardcore/express`

```typescript
// adapters.ts
export class ExpressGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};
  private rawBody: Uint8Array | null = null;

  constructor(private req: Request) {
    if (req.rawBody) {
      this.rawBody = req.rawBody instanceof Uint8Array ? req.rawBody : new Uint8Array(req.rawBody);
    }
  }

  get urlPath() { return this.req.path; }
  get urlScheme() { return this.req.protocol; }
  get urlFull() { return `${this.req.protocol}://${this.req.get('host')}${this.req.originalUrl}`; }
  urlReplaceScheme(scheme: string) { return this.urlFull.replace(/^https?/, scheme); }
  get method() { return this.req.method; }
  get clientHost() { return this.req.socket.remoteAddress ?? null; }
  get headers() { return this.req.headers as Record<string, string>; }
  get queryParams() { return this.req.query as Record<string, string>; }
  async body() { return this.rawBody ?? new Uint8Array(0); }
  get state() { return this._state; }
}

// cors.ts
import cors from 'cors';

export function configureCors(app: Express, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;
  app.use(cors({
    origin: config.corsAllowOrigins,
    methods: config.corsAllowMethods,
    allowedHeaders: config.corsAllowHeaders,
    credentials: config.corsAllowCredentials,
    exposedHeaders: config.corsExposeHeaders,
    maxAge: config.corsMaxAge,
  }));
}
```

Post-response behavioral processing and `customResponseModifier` use response interception
(`res.write` / `res.end` override), internal to the adapter.

The Express adapter requires raw body preservation for accurate suspicious pattern detection.
Users must use a raw-body-preserving middleware (e.g., `express.json({ verify: (req, _, buf) => { req.rawBody = buf; } })`)
or the adapter provides a `guardBodyParser()` helper that handles this automatically.

### `@guardcore/fastify`

`onRequest` hook → pipeline. `onSend` hook → behavioral return rules + response modifier.

```typescript
export const guardPlugin = fp(async (fastify, config: SecurityConfig) => {
  const middleware = new SecurityMiddleware(config);
  await middleware.initialize();

  fastify.addHook('onRequest', async (request, reply) => {
    const guardReq = new FastifyGuardRequest(request);
    const block = await middleware.runPipeline(guardReq);
    if (block) {
      for (const [k, v] of Object.entries(block.headers)) reply.header(k, v);
      return reply.status(block.statusCode).send(block.bodyText);
    }
  });

  fastify.addHook('onSend', async (request, reply, payload) => {
    return middleware.processResponse(new FastifyGuardRequest(request), payload, reply.statusCode);
  });
}, { name: '@guardcore/fastify', fastify: '>=4' });

// cors.ts
export function configureCors(fastify: FastifyInstance, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;
  fastify.register(import('@fastify/cors'), {
    origin: config.corsAllowOrigins,
    methods: config.corsAllowMethods,
    allowedHeaders: config.corsAllowHeaders,
    credentials: config.corsAllowCredentials,
    exposedHeaders: config.corsExposeHeaders,
    maxAge: config.corsMaxAge,
  });
}
```

### `@guardcore/nestjs`

`NestMiddleware` for the security pipeline (runs earliest in the request lifecycle).
`NestInterceptor` for post-response behavioral processing.
`GuardModule.forRoot()` for DI registration.

```typescript
@Injectable()
export class SecurityMiddlewareNest implements NestMiddleware {
  constructor(@Inject(GUARD_MIDDLEWARE_TOKEN) private mw: SecurityMiddleware) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const guardReq = new NestGuardRequest(req);
    const block = await this.mw.runPipeline(guardReq);
    if (block) {
      for (const [k, v] of Object.entries(block.headers)) res.setHeader(k, v);
      res.status(block.statusCode).json({ detail: block.bodyText });
      return;
    }
    next();
  }
}

@Module({})
export class GuardModule {
  static forRoot(config: SecurityConfig): DynamicModule {
    return {
      module: GuardModule,
      providers: [
        { provide: GUARD_MIDDLEWARE_TOKEN, useFactory: async () => {
            const mw = new SecurityMiddleware(config);
            await mw.initialize();
            return mw;
          }
        },
        SecurityMiddlewareNest,
        SecurityInterceptor,
      ],
      exports: [SecurityMiddlewareNest, SecurityInterceptor, GUARD_MIDDLEWARE_TOKEN],
      global: true,
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(SecurityMiddlewareNest).forRoutes('*');
  }
}
```

### `@guardcore/hono`

Edge-safe. `geoResolver` replaces `maxmind` on non-Node runtimes.
Initialization is lazy + guarded (no top-level await on edge).
IP extraction delegated to core via adapter's `clientHost`, not hand-rolled.

```typescript
export class HonoGuardRequest implements GuardRequest {
  private _state: GuardRequestState = {};

  constructor(private req: HonoRequest, private connectingIp: string | null) {}

  get urlPath() { return new URL(this.req.url).pathname; }
  get urlScheme() { return new URL(this.req.url).protocol.replace(':', ''); }
  get urlFull() { return this.req.url; }
  urlReplaceScheme(scheme: string) { return this.urlFull.replace(/^https?/, scheme); }
  get method() { return this.req.method; }
  get clientHost() { return this.connectingIp; }
  get headers() { return Object.fromEntries(this.req.raw.headers.entries()); }
  get queryParams() { return Object.fromEntries(new URL(this.req.url).searchParams.entries()); }
  async body() { return new Uint8Array(await this.req.arrayBuffer()); }
  get state() { return this._state; }
}

export function createGuardMiddleware(config: SecurityConfig): MiddlewareHandler {
  const middleware = new SecurityMiddleware(config);
  let initialized = false;

  return async (c, next) => {
    if (!initialized) { await middleware.initialize(); initialized = true; }

    const connectingIp = c.env?.remoteAddr ?? null;
    const guardReq = new HonoGuardRequest(c.req, connectingIp);
    const block = await middleware.runPipeline(guardReq);

    if (block) {
      for (const [k, v] of Object.entries(block.headers)) c.header(k, v);
      return c.json({ detail: block.bodyText }, block.statusCode as StatusCode);
    }

    await next();
    await middleware.processResponseHono(c);
  };
}

// cors.ts
import { cors } from 'hono/cors';

export function configureCors(app: Hono, config: ResolvedSecurityConfig): void {
  if (!config.enableCors) return;
  app.use('*', cors({
    origin: config.corsAllowOrigins,
    allowMethods: config.corsAllowMethods,
    allowHeaders: config.corsAllowHeaders,
    credentials: config.corsAllowCredentials,
    exposeHeaders: config.corsExposeHeaders,
    maxAge: config.corsMaxAge,
  }));
}
```

---

## Phase 3 — Testing

### Core test structure

Mirror Python's test directory structure exactly:

```
packages/core/tests/
├── test-agent/
├── test-cloud-ips/
├── test-core/
│   ├── checks/           ← one file per check implementation
│   └── pipeline.test.ts
├── test-decorators/
├── test-detection-engine/
│   ├── compiler.test.ts
│   ├── preprocessor.test.ts
│   ├── semantic.test.ts
│   └── monitor.test.ts
├── test-handlers/
├── test-models/
├── test-redis/
├── test-security-headers/
├── test-sus-patterns/
└── test-utils/
```

Port Python test fixtures from `fixtures/*.json` (exported by pre-implementation script).
Same inputs → same expected outputs validates cross-language parity.

### Adapter tests

Each adapter test verifies only the translation layer:
- Correct IP extraction (direct + `X-Forwarded-For` + trusted proxy chain)
- Correct status code and body on block
- Security headers applied on both allowed and blocked responses
- CORS headers applied on error responses
- `next()` called only when pipeline allows
- Post-response behavioral hooks fire
- `configureCors()` wires framework-native CORS correctly

---

## Phase 4 — Publishing

```
@guardcore/core          → required peer of all adapters
@guardcore/express       → peerDep: express ^4 || ^5
@guardcore/fastify       → peerDep: fastify ^4
@guardcore/nestjs        → peerDep: @nestjs/core ^10
@guardcore/hono          → peerDep: hono ^4
```

Lock-step versioning. All packages release together at the same version number.

---

## Implementation Order

```
Phase 0   Monorepo bootstrap + RE2 validation script + test fixture export
          ↓
Phase 1a  Protocols (all 6) + SecurityConfig (Zod) + RouteConfig + BehaviorRule + DynamicRules
Phase 1b  Detection engine: PatternCompiler (re2-wasm + worker_threads fallback) →
          ContentPreprocessor → SemanticAnalyzer → PerformanceMonitor
Phase 1c  Handlers: RedisManager → IPBanManager → RateLimitManager (with Lua scripts) →
          CloudHandler → SusPatternsManager → SecurityHeadersManager → BehaviorTracker →
          DynamicRuleManager → IPInfoManager
Phase 1d  Core subsystems: EventBus → MetricsCollector → RequestValidator →
          RouteConfigResolver → BypassHandler → ErrorResponseFactory (with CORS on errors) →
          BehavioralProcessor → HandlerInitializer (returns HandlerRegistry)
Phase 1e  SecurityCheck ABC + SecurityCheckPipeline + check helpers
Phase 1f  All 17 check implementations (pipeline order)
Phase 1g  Decorators: BaseSecurityDecorator (WeakMap route IDs + 5 event methods) +
          6 mixins (20 decorator methods) → SecurityDecorator
Phase 1h  Utils: full module (IP extraction, detection, logging, agent events)
          ↓  [full test coverage before leaving Phase 1]
Phase 2a  @guardcore/express (adapters + middleware + configureCors + guardBodyParser)
Phase 2b  @guardcore/fastify (adapters + plugin + configureCors)
          ↓  [release 1.0.0 — real-world feedback]
Phase 2c  @guardcore/nestjs (adapters + NestMiddleware + interceptor + GuardModule + configureCors)
Phase 2d  @guardcore/hono (adapters + middleware factory + configureCors, edge-safe)
          ↓
Phase 3   Hardening + benchmarks
Phase 4   Publish + cross-link Python and TS repos in READMEs
```

---

## What Is NOT in v1 Scope

- ML inference (`onnxruntime`) — detection engine is regex + semantic only
- Live Guard Agent SaaS — event bus is wired and typed, but agent client is stubbed
- Dynamic rules from SaaS — `DynamicRuleManager` is stubbed
- `@guardcore/koa` / `@guardcore/bun` — add after Express + Fastify prove the pattern
- Upstash Redis (HTTP-based edge-compatible Redis) — future enhancement for edge distributed state

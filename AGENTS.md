# AGENTS.md

> 面向所有在本仓库工作的 agent（含人类协作者）。
> 目标：**任何 agent 的修改都不得偏离认证组件的核心架构、安全边界与验收口径。**
> 本文件与 README 冲突时，以本文件为准；涉及重大取舍先停下来问，不要自行发挥。

---

## 0. 项目定位

内部管理端嵌入式认证组件，Spring Boot Starter 形式：账号密码 + TOTP 双因素、会话、锁定、审计、
管理员生命周期；内置 5 个页面，可被宿主产品直接引入。

| 项 | 值 |
|---|---|
| 技术基线 | Java 21 / Spring Boot 3.5.6 / Spring Security 6.5 / Maven 3.9+ |
| 坐标 | `com.aseantec:admin-auth-*:0.1.0-SNAPSHOT` |
| 包根 | `com.aseantec.adminauth.core` / `.starter` / `.sample` |
| 数据库 | MySQL 8.0+（生产）；H2 `MODE=MySQL`（仅 demo） |
| 当前分支 | `main` |
| 形态 | 库（Starter），不是独立服务；不引入前端框架、不引入中间件 |

**明确不在范围内**：RBAC 权限引擎、OAuth2/OIDC/JWT/WebAuthn、注册/找回密码、Redis、多租户、
外部 OTP 供应商、业务表/业务权限建模。

---

## 1. 开工前必读

1. `README.md`（构建、运行、API、配置、生产检查清单）
2. 本文件（硬约束）
3. `admin-auth-spring-boot-starter/src/main/resources/db/migration/admin-auth/V1__admin_auth_init.sql`
   与 `V2__admin_auth_session.sql`（**权威表结构**）
4. `admin-auth-core/src/main/java/**`（领域契约，先看 `port/` 再改实现）

常用命令：

```bash
mvn -q test                 # 单测；无 Docker 时 Testcontainers IT 自动跳过
mvn -q -DskipTests package
mvn -q -DskipTests install  # 让 sample 能 spring-boot:run
mvn -pl admin-auth-sample spring-boot:run -Dspring-boot.run.profiles=demo
```

---

## 2. 模块与依赖方向（硬约束）

```
admin-auth-sample ──▶ admin-auth-spring-boot-starter ──▶ admin-auth-core
        │                        │
        └──── Spring Boot ───────┘

admin-auth-parent（聚合/属性/pluginManagement）
admin-auth-bom（版本 BOM）
```

**依赖方向只能从右向左；禁止反向依赖、禁止循环依赖。**

| 模块 | 允许 | 禁止 |
|---|---|---|
| `admin-auth-core` | 仅 `slf4j-api`（测试可用 `spring-boot-starter-test`） | 任何 Spring / JDBC / Servlet / Jackson / 第三方工具库 |
| `admin-auth-spring-boot-starter` | core + Spring Boot（web/security/jdbc/thymeleaf/validation）+ spring-session-jdbc + flyway + qrcodegen | 引入 JPA/Redis/Lombok/Zxing/OTP 库；把业务实体放进 core |
| `admin-auth-sample` | starter + H2/MySQL 驱动 | 反向依赖；把示例专用逻辑塞进 starter |

**依赖白名单**（新增依赖前必须确认）：`spring-boot-starter-{web,security,jdbc,thymeleaf,validation}`、
`spring-session-jdbc`、`flyway-core`、`flyway-mysql`、`io.nayuki:qrcodegen`、`mysql-connector-j`、
`h2`（sample）、`slf4j-api`。测试：`spring-boot-starter-test`、`spring-security-test`、
`testcontainers-{mysql,junit-jupiter}`（1.20.4，BOM 先于 Boot BOM 导入）。

**禁止**：Lombok、JPA/Hibernate、Redis、Zxing、第三方 OTP 库、OAuth2/OIDC/JWT、WebAuthn、外网调用、
前端框架/CDN。

---

## 3. 分层职责

### core（纯领域）
- 枚举/记录/异常：`domain/`
- 端口：`port/`（6 个仓储 + `AuditSink`/`PasswordVerifier`/`SecretCipher`/`ClockProvider`/
  `IdentityNormalizer`/`BlindIndexer`/`MfaPolicy`/`MfaChannelSender`）
- 算法与服务：`crypto/`、`util/`、`service/`（`LoginService`、`MfaService`、`MfaPolicyService`、
  `LockoutService`、`PasswordService`、`TotpService`）
- **不出现** Spring 注解、`@Transactional`、`JdbcTemplate`、HTTP 类型、JSON 序列化。
- **不出现最终文案**：异常只携带原因枚举 / 消息键与参数（`PasswordPolicyReason`、`MfaFailureReason`），
  翻译统一在 starter 的 `AdminAuthMessages` 完成。core 可以出现稳定键字符串，但不能出现给终端用户看的文案。

### starter（装配与适配）
- `AdminAuthAutoConfiguration` + `AdminAuthProperties` + `config/*` 装配
- `jdbc/*`：JdbcTemplate 仓储（唯一写 SQL 的地方）
- `security/*`：三种 Security 模式、会话、EntryPoint、过滤器
- `web/*`：REST 控制器、错误码、ticket、二维码、页面控制器
- `admin/*`：用户生命周期与事务边界
- `i18n/*`：`AdminAuthMessages`（SPI）+ `BundleAdminAuthMessages`（ResourceBundle 实现）
- `schema/*`、`bootstrap/*`、`startup/*`：迁移、引导、启动编排
- `src/main/resources`：迁移 SQL、模板、静态资源、`i18n/admin-auth-messages*.properties`、
  `META-INF/spring/...AutoConfiguration.imports`

### sample（示例宿主）
- 只做"如何接入"的示范；demo-only 的 H2 TCP/Console 仅 `@Profile("demo")`。

### 事务规则（重点）
- core 不加 `@Transactional`；多写操作必须在 starter 用 `TransactionTemplate` 包裹：
  - `AdminAuthTransactionalOperations`（TOTP 确认/校验/恢复码、改密、停用/重置 2FA）
  - `AdminAuthUserAdminService`（bootstrap、创建用户、重置密码、启停、解锁）
- 新增"多表写入"必须复用上述事务边界，或在 starter 新增同等事务方法。
- 登录主流程**不包事务**（BCrypt 耗时长，避免占用连接）。

---

## 4. 安全不变量（MUST）

1. **密码**：BCrypt（cost ≥ 12）；账号不存在也执行一次 dummy hash；失败文案统一为
   "账号或密码错误"（消息键 `admin-auth.error.auth-failed`，中英两份 bundle 同步）。
2. **盲索引**：`HMAC-SHA256(indexKey, "TYPE|normalized|v1")` → 32B；登录查询只走 `value_hash`。
3. **加密**：AES-256-GCM（`iv12 || ct || tag16`）；解密必须传 `key_version`，禁止只用当前密钥硬解。
4. **脱敏**：`value_mask`、审计 `channel_mask` 必须是脱敏值，禁止明文邮箱/手机号。
5. **TOTP**：±window、恒定时间比较、`last_used_step` 原子推进防重放；恢复码 HMAC 单次核销。
6. **会话**：登录成功 `changeSessionId`；写 `ADM_PRINCIPAL`、`PRINCIPAL_NAME_INDEX_NAME`、
   `SPRING_SECURITY_CONTEXT`；改密/停用/管理员重置时按 principal name 删除该用户全部会话。
7. **CSRF**：Cookie 仓储 + `X-XSRF-TOKEN`；**只豁免** `/api/login` 与 `/api/mfa/**`，其余 POST 必须校验。
8. **Security 模式**：`ISOLATED`（默认，链 order=`BASIC_AUTH_ORDER-20` + `securityMatcher`）、
   `INTEGRATED`（只导出 filter/EntryPoint）、`FILTER_ONLY`。不得破坏兜底链与可达性。
9. **管理接口**：`SUPER_ADMIN` + step-up（默认 5 分钟）；不能停用自己；不能停用最后一个 SUPER_ADMIN。
10. **时间**：UTC；Java `Instant` → `Timestamp.from`；MySQL 列 `DATETIME(3)`；不要用本地时区。
11. **生成列**：`adm_identity.active_hash` 是 MySQL 生成列，**任何 INSERT/UPDATE 都不得出现该列**。
12. **密钥**：32 字节；支持 `env:`/`base64:`；日志只打印来源与版本，绝不打印密钥；轮换依赖
    `data-kek-version` + `data-kek-history`。

---

## 5. 数据库与迁移

- `V1__admin_auth_init.sql`（7 张业务表）与 `V2__admin_auth_session.sql` 是**已发布迁移，禁止修改**；
  任何表结构变更只能新增 `V3__*.sql`，并同步：
  1. `admin-auth-sample/src/main/resources/schema-h2.sql`（H2 demo 映射）
  2. README 的表/索引说明
  3. 受影响的 row mapper / SQL 常量
- Flyway：独立 history `adm_schema_history`，locations `classpath:db/migration/admin-auth`，
  模式 `off/auto/validate`；MySQL `GET_LOCK` 防并发；**宿主必须 `spring.flyway.enabled=false`**。
- 表约定：InnoDB + utf8mb4_0900_ai_ci；状态 TINYINT；软删除；**不建物理外键**（会话属性表除外）。
- H2 映射：去 ENGINE/CHARSET/COMMENT/`ON UPDATE`/生成列（`active_hash` 改普通 `BINARY(32) NULL`）；
  `DATETIME(3)`→`TIMESTAMP(3)`；JSON→`VARCHAR(4000)`。
- 仅支持 MySQL 8.0+（`utf8mb4_0900_ai_ci`）；MariaDB 不支持。
- 时间列由应用显式写入 UTC；MySQL URL 建议 `connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true`。

---

## 6. 配置契约

- 前缀固定 `admin-auth.*`；`enabled=false` 必须零装配。
- 新增配置项必须：有安全默认值、写入 `AdminAuthProperties`、加 README 表格、考虑环境变量覆盖。
- 密钥必填且 32 字节，缺失/长度错误启动失败（fail-fast）。
- 安全默认值：`session.secure-cookie=true`、`mfa.mode=OPTIONAL`、`schema.mode=VALIDATE`。
- 示例工程（`admin-auth-sample`）是**演示配置**，不是生产默认；真实口令禁止进入仓库。
- 敏感项只能通过 `env:` / 环境变量提供；README 中保持"生产检查清单"同步。

---

## 7. API 契约

- 前缀 `admin-auth.endpoint-prefix`（默认 `/admin-auth`），REST 均在 `/api/**` 下。
- 错误统一 `{"code","message","messageKey"}`；错误码见 `ApiErrorCode`，不得新增同义码。
- **i18n 契约**：
  - `code` 与 `messageKey` 是稳定契约（前端按 `code` 分支），`message` 是本地化文本，**不属契约**；
  - 新增文案必须同时写 `i18n/admin-auth-messages.properties`（英文，基础）与
    `admin-auth-messages_zh_CN.properties`（中文），键集合由单测强制一致；
  - 语言来自 `Locale`（默认 `Accept-Language`）；`admin-auth.i18n.enabled=false` 时固定默认语言；
  - 禁止在代码里直接 `MessageSource` 解析本组件文案；禁止注册 `messageSource` Bean 覆盖宿主 i18n；
  - 日志、审计 `detail`、库内业务数据**不做 i18n**。
- 新增端点必须同时满足：
  1. README API 表登记；
  2. 鉴权（未登录/角色/step-up）与 CSRF 策略明确；
  3. 写操作有审计事件；
  4. 不返回明文 PII；临时密码/恢复码只返回一次；
  5. 不破坏既有端点/字段（只增不删）。
- 未登录接口：`/api/login`、`/api/password/change-initial`、`/api/mfa/**`、`/api/csrf`。
- 管理接口：`/api/admin/**`，要求 SUPER_ADMIN + step-up。

---

## 8. 关键链路 → 改哪里

| 需求 | 入口 |
|---|---|
| 登录编排/锁定/风险判定 | `core/service/LoginService`、`LockoutService` |
| 2FA 策略（OFF/ON_RISK/OPTIONAL/REQUIRED_BY_ROLE/REQUIRED_ALL） | `core/service/MfaPolicyService` + `MfaPolicyMode` |
| TOTP 绑定/校验/恢复码 | `core/service/MfaService` + `core/crypto/*` |
| 新 MFA 因素类型 | `MfaFactorType` + `MfaService` + `MfaChannelSender` SPI（不改表） |
| 会话/踢下线 | `starter/security/AdminSessionService` |
| Security 三模式 | `starter/config/AdminAuthSecurityConfiguration` + `SecurityMode` |
| 管理端用户生命周期 | `starter/admin/AdminAuthUserAdminService` + `AdminApiController` |
| 事务边界 | `AdminAuthTransactionalOperations` / `AdminAuthUserAdminService` |
| 启动顺序/迁移/引导 | `AdminAuthStartupCoordinator` + `schema/*` + `bootstrap/*` |
| 页面/JS | `resources/templates/admin-auth/*` + `static/admin-auth/app.js` + `AdminAuthPageController` |
| 审计事件 | `core/domain/AuditEvent` + 写入点（`AuditSink`） |
| 文案/多语言 | `starter/i18n/*` + `resources/i18n/admin-auth-messages*.properties` + 页面模板 `i18n[...]` |
| 新配置 | `AdminAuthProperties` + `config/*` + README |

---

## 9. 测试与验收

| 项 | 说明 |
|---|---|
| `mvn -q test` | 38 个 core 单测 + 13 个 starter 单测；`AdminAuthFlowIT` 无 Docker 时 Skipped |
| `scripts/api-test.ps1` | 67 项接口契约；**假设 `REQUIRED_ALL`** |
| `scripts/acceptance.ps1` | 13 步主链路；**假设 `REQUIRED_ALL`** |
| `scripts/demo-create-admin.ps1` | SUPER_ADMIN 登录 → 创建 admin（要求全新库） |
| `scripts/demo-risk-mfa.ps1` | `ON_RISK` 行为演示（示例默认模式） |

规则：
- 新增/修改核心逻辑必须补 core 单测；接口变化必须更新脚本或 IT。
- **禁止**通过删除测试、放宽断言、跳过用例来"过 CI"。
- 行为变化必须同步 README 与（必要时）本文件。
- 本地无 Docker 时，Testcontainers 跳过是预期行为，不是失败。

---

## 10. 常见坑（务必先看）

1. `AutoConfiguration.imports` 路径必须精确：
   `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`。
2. 宿主若开启 Boot 自带 Flyway，会与本组件迁移冲突 → 必须 `spring.flyway.enabled=false`。
3. Spring Session 表名必须是 `ADM_SESSION`，`initialize-schema=never`。
4. `AdminSessionPrincipal` 必须 `Serializable`；会话删除按 `PRINCIPAL_NAME`（= userId）。
5. 本地 HTTP 调试需 `secure-cookie=false`；生产必须 `true`。
6. `active_hash` 生成列不能进 INSERT/UPDATE（H2 demo 是普通 NULL 列）。
7. H2 兼容 SQL：不用 `ON DUPLICATE KEY`、JSON 函数；`updated_at` 显式传。
8. 页面不得引 CDN；二维码由服务端 qrcodegen 生成。
9. 登录/改密/审计的多写路径必须走 starter 的事务方法。
10. `ON_RISK` 与 `REQUIRED_ALL` 的测试前提不同；跑旧脚本要用 `--admin-auth.mfa.mode=REQUIRED_ALL`。
11. demo 的 H2 TCP 端口 9092 只能被一个实例占用；多实例需换端口或停掉旧实例。
12. 密钥/口令不得出现在日志、异常信息、提交历史中。
13. 不要注册 `messageSource` Bean：会顶掉宿主的 `messages.properties` / 自定义 MessageSource；
    本组件文案只走 `AdminAuthMessages`，页面走模型注入（`i18n`），不用 Thymeleaf `#{}`。
14. 中英两份 bundle 键集合必须一致（有单测）；只增文案、不改 `code`/`messageKey`；
    报错定位不要靠字符串匹配（例如"原密码"），一律用异常上的 reason 枚举。

---

## 11. 变更流程

- 小步提交；提交信息使用 `feat|fix|docs|refactor|test|chore: ...`。
- 不提交：`target/`、`.idea/`、`*.iml`、日志、H2 数据文件、`.env`、`application-local.yml`、真实口令。
- 修改行为时同步更新：README、本文件、脚本断言、单测。
- 破坏性变更（接口/配置/表结构）必须在 README 标注迁移方式。

提交前自检：

```bash
# core 不应出现 Spring/JDBC/Servlet
grep -rE "org\.springframework|jakarta\.servlet|javax\.sql|JdbcTemplate|@Transactional" \
  admin-auth-core/src/main/java || true

mvn -q test
```

---

## 12. 明确不做（scope guard）

- 不做通用 RBAC/权限引擎；业务权限归宿主（可加 `AdminAuthoritiesProvider` SPI 映射）。
- 不做 OAuth2/OIDC/JWT/WebAuthn/注册/找回密码。
- 不接 Redis/消息队列/外部 OTP 供应商。
- 不做多租户、组织树、数据范围（ABAC）。
- 不引入前端框架、不把业务实体/业务表放进本组件。
- 不把 `adm_user.role` 扩展成业务权限模型（保持粗粒度：SUPER_ADMIN/ADMIN/VIEWER）。

---

## 13. 需要先问人的情况

出现以下任一情况，先停下来询问，不要自行决定：

1. 修改数据库表结构、已发布迁移或 Flyway 策略；
2. 修改安全默认值（secure cookie、CSRF 豁免、MFA 默认模式、锁定阈值）；
3. 引入新的第三方依赖；
4. 修改公开 API 契约/错误码，或删除/重命名已有端点/类；
5. 调整事务边界、启动顺序、密钥管理方案；
6. 任何"为了省事"而绕过审计、脱敏、恒定耗时比较的改动。

---

## 14. 交付定义（Definition of Done）

- [ ] 依赖方向未反转；core 无 Spring 依赖
- [ ] 多写操作在 starter 事务边界内
- [ ] 未写 `active_hash`；时间仍为 UTC
- [ ] 新端点：鉴权/CSRF/审计/文档齐全
- [ ] 新配置：默认值/文档/密钥校验齐全
- [ ] 文案：中英两份 bundle 同步，`code`/`messageKey` 未变，页面/脚本无新增硬编码文案
- [ ] 单测通过；相关脚本/IT 通过
- [ ] H2 schema 与迁移同步
- [ ] README 与本文件已更新
- [ ] 无密钥、口令、内部地址进入提交

# admin-auth · 内部管理端嵌入式认证组件

Spring Boot Starter 形式的账号密码 + TOTP 双因素认证组件：提供登录、初始改密、TOTP 绑定、
恢复码、锁定、审计、会话管理与 Security 三模式集成，内置 5 个可直接使用的页面。

- **技术基线**：Java 21 / Spring Boot 3.5.6 / Spring Security（Boot BOM 管理）/ Maven 3.9+
- **坐标**：`com.aseantec:admin-auth-*:0.1.0-SNAPSHOT`
- **数据库**：MySQL 8（生产）/ H2（本地 demo）
- **不包含**：OAuth2/OIDC、JWT、Redis、WebAuthn、注册、第三方登录；OTP 通道只留 SPI

## 1. 模块结构

| 模块 | 说明 |
|---|---|
| `admin-auth-parent` | 聚合、版本属性、pluginManagement（Boot BOM + Testcontainers BOM） |
| `admin-auth-bom` | 管理 core / starter / sample / bom 共 4 个自研模块版本 |
| `admin-auth-core` | 纯 Java 领域层：枚举、记录、仓储端口、TOTP/AES-GCM/盲索引/策略/锁定，仅依赖 slf4j-api |
| `admin-auth-spring-boot-starter` | 自动装配、JdbcTemplate 仓储、REST API、Security 三模式、内置页面、Flyway V1/V2 |
| `admin-auth-sample` | 示例宿主：MySQL 配置占位（默认）+ H2 demo profile |

## 2. 快速开始

### 2.1 构建与测试

```bash
cd admin-auth
mvn -q clean test          # core 单测 + starter 集成测试（无 Docker 时 Testcontainers 自动跳过）
mvn -q -DskipTests package # 打包（sample 可执行 jar）
mvn -q -DskipTests install # 让 sample 能通过 spring-boot:run 解析兄弟模块
```

### 2.2 本机 demo（H2，无需数据库）

```bash
mvn -pl admin-auth-sample spring-boot:run -Dspring-boot.run.profiles=demo
```

- 登录页：<http://localhost:8080/admin-auth/login>
- 受保护页：<http://localhost:8080/admin/hello>（未登录 302 到登录页）
- 初始账号：`admin@corp.example` / `Admin@123456`
  - 首次登录强制改密（≥12 位，且不能与原密码相同）
  - 示例配置 `admin-auth.mfa.mode=REQUIRED_ALL`，改密后必须绑定 TOTP
  - 绑定成功一次性展示 10 个恢复码（仅此一次）
- **查看 H2 数据（仅 demo）**：demo profile 额外暴露
  - H2 TCP（仅本机）：`jdbc:h2:tcp://localhost:9092/mem:adminauth`，用户 `sa`、密码空
  - H2 Console：<http://localhost:8080/h2-console>（JDBC URL 同上）
  - 内存库随进程退出清空；生产使用 MySQL 时不启用这些入口

> 组件默认 `mfa.mode=OPTIONAL`；sample 用 `REQUIRED_ALL` 是为了让首次登录就能走完绑定链路。

### 2.3 MySQL（默认配置，先占位后修改）

`admin-auth-sample/src/main/resources/application.yml` 默认指向 MySQL，占位项：

```yaml
spring.datasource.url: jdbc:mysql://127.0.0.1:3306/admin_auth?...
spring.datasource.username: CHANGE_ME
spring.datasource.password: CHANGE_ME
```

改成你的连接后直接启动：

```bash
mvn -pl admin-auth-sample spring-boot:run
```

`schema.mode=auto` 会在启动时用组件自带的 Flyway 执行器建表（独立 history：`adm_schema_history`，
MySQL 下用 `GET_LOCK` 防并发）；生产建议改为 `validate`，由发布流程执行 SQL。

> **时区**：业务时间列是 `DATETIME(3)` 且由应用显式写入 UTC。若希望连 `CURRENT_TIMESTAMP`
> 默认值与 Flyway `installed_on` 也统一为 UTC，请在 JDBC URL 加
> `connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true`（示例已配置），
> 否则 MySQL 会话时区为 SYSTEM（UTC+8），仅影响服务端默认值/元数据的显示。
>
> **凭据**：`application-mysql.yml` 中的口令只作为本地模板默认值，建议改用
> `ADMIN_AUTH_DB_URL / ADMIN_AUTH_DB_USER / ADMIN_AUTH_DB_PASSWORD` 环境变量，避免把真实口令提交进仓库。

### 2.4 数据库表

- `V1__admin_auth_init.sql`：7 张业务表（`adm_user` / `adm_identity` / `adm_mfa_factor` /
  `adm_otp_code` / `adm_recovery_code` / `adm_audit_log` / `adm_login_attempt`）
- `V2__admin_auth_session.sql`：`ADM_SESSION` / `ADM_SESSION_ATTRIBUTES`
- `admin-auth-sample/src/main/resources/schema-h2.sql`：H2 demo 映射（去生成列/引擎/注释，JSON→VARCHAR）

> **重要**：迁移脚本位于 `classpath:db/migration/admin-auth`，在 Spring Boot 默认 Flyway 扫描路径内。
> 宿主若使用 Boot 自带 Flyway，必须设置 `spring.flyway.enabled=false`（示例已设置），否则会与本组件
> 的独立 history 冲突。组件初始化器检测到冲突会给出明确报错。

## 3. 登录链路

```
规范化标识 → HMAC 盲索引 → 查启用标识 → 查账号
→ 恒定耗时 BCrypt（账号不存在也跑 dummy hash）
→ 锁定检查（标识+IP / 账号双维度）
→ must_change_password 优先 → 2FA 策略
→ COMPLETE / CHANGE_PASSWORD / BIND_TOTP / SELECT_FACTOR
```

- pre-auth ticket：32B 随机 Base64Url，存 session，单次消费；TTL 300s（绑定 600s）；失败 5 次作废
- 改密 / 停用 / 管理员重置 2FA：按 principal name 删除该用户全部会话
- 会话：空闲 30m、绝对 8h；登录成功 `changeSessionId` 防会话固定
- TOTP 防重放：`last_used_step` 原子推进（`UPDATE ... WHERE last_used_step < ?`）

## 4. REST API

前缀 `/admin-auth`（`admin-auth.endpoint-prefix` 可配）。错误统一 `{"code","message"}`。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{identityType,identifier,password}` → `{next,ticket?,factors?,user?}` |
| POST | `/api/password/change-initial` | 初始改密（ticket） |
| POST | `/api/mfa/verify` | `{ticket,factorType,code}` |
| POST | `/api/mfa/recovery` | `{ticket,code}` |
| POST | `/api/mfa/totp/setup/init` | `{ticket}` → `{otpauthUri,qrSvg,manualSecret}` |
| POST | `/api/mfa/totp/setup/confirm` | `{ticket,code}` → `{recoveryCodes,next,user}`（成功即建会话） |
| POST | `/api/mfa/otp/send` | 无通道 Bean 时 501 |
| GET | `/api/csrf` | 返回 token（并种 `XSRF-TOKEN` Cookie） |
| GET | `/api/me` | 当前登录人 |
| GET | `/api/security/mfa` | 2FA 状态与因素列表 |
| POST | `/api/security/mfa/disable` | `{password}`（强制策略下 403） |
| POST | `/api/password/change` | `{oldPassword,newPassword}`（改完强制重登） |
| POST | `/api/logout` | 注销 |
| POST | `/api/admin/users` | 创建管理员（返回一次性临时密码 + STAFF_CODE） |
| GET | `/api/admin/users?page=0&size=20` | 管理员分页列表（含脱敏标识） |
| POST | `/api/admin/users/{id}/status` | `{enabled:true\|false}` 启用/停用（停用即踢下线） |
| POST | `/api/admin/users/{id}/unlock` | 清除该账号所有 IP 的失败计数 |
| POST | `/api/admin/users/{id}/password/reset` | 重置密码（返回一次性临时密码，强制下次改密） |
| POST | `/api/admin/users/{id}/mfa/reset` | SUPER_ADMIN + step-up |
| POST | `/api/admin/users/{id}/mfa/require` | `{value:-1\|0\|1}` |
| GET | `/api/admin/audit?limit=50` | SUPER_ADMIN + step-up |

错误码：`AUTH_FAILED(401)`、`TICKET_EXPIRED(401)`、`MFA_REQUIRED(401)`、`MFA_LOCKED(423)`、
`CHANNEL_FORBIDDEN(400)`、`MFA_REQUIRED_BY_POLICY(403)`、`STEP_UP_REQUIRED(403)`、`FORBIDDEN(403)`、
`NOT_IMPLEMENTED(501)`、`VALIDATION_FAILED(400)`、`PASSWORD_MISMATCH(400)`。

## 5. 配置参考（`admin-auth.*`）

| 配置 | 默认 | 说明 |
|---|---|---|
| `enabled` | true | false = 零装配 |
| `endpoint-prefix` | `/admin-auth` | 页面与 API 前缀 |
| `protected-paths` | `/admin/**` | 需要登录的路径 |
| `security.mode` | `ISOLATED` | `ISOLATED` / `INTEGRATED` / `FILTER_ONLY` |
| `security.provide-host-fallback` | true | 追加 LOWEST_PRECEDENCE permitAll 兜底链 |
| `schema.mode` | `VALIDATE` | `OFF` / `AUTO` / `VALIDATE` |
| `mfa.mode` | `OPTIONAL` | `OFF` / `OPTIONAL` / `REQUIRED_BY_ROLE` / `REQUIRED_ALL` |
| `mfa.required-roles` / `require-totp-roles` | 空 | 角色集合 |
| `mfa.forbid-same-channel` | true | 邮箱登录禁用 EMAIL_OTP，手机登录禁用 SMS_OTP |
| `mfa.step-up-ttl` | 5m | 管理接口 step-up 有效期 |
| `mfa.totp.*` | Admin Auth/6/30/1 | issuer / digits / period / window |
| `password.min-length` / `bcrypt-cost` | 12 / 12 | 密码策略 |
| `lockout.max-attempts` / `lock-duration` | 5 / 15m | 登录锁定 |
| `session.cookie-name/domain/secure/same-site` | JSESSIONID / 空 / true / Lax | Cookie |
| `session.idle` / `absolute` | 30m / 8h | 空闲 / 绝对有效期 |
| `keys.data-kek/index-key/otp-key` | 无 | **必须 32 字节**，支持 `env:NAME` / `base64:` |
| `keys.data-kek-version` | 1 | 当前数据密钥版本，写入 `key_version` 列 |
| `keys.data-kek-history` | 空 | 历史密钥 `{版本: 密钥}`，用于解密旧密文（轮换用） |
| `ui.enabled` | true | 内置页面 |
| `bootstrap.*` | enabled / 空账号 | 初始 SUPER_ADMIN（EMAIL + STAFF_CODE） |

密钥示例：

```yaml
admin-auth:
  keys:
    data-kek: env:ADMIN_AUTH_DATA_KEK
    index-key: env:ADMIN_AUTH_INDEX_KEY
    otp-key: env:ADMIN_AUTH_OTP_KEY
```

长度不是 32 字节会在启动时直接失败；启动日志只打印来源，不会打印密钥。

## 6. 接入宿主（三步）

1. **加依赖**（BOM 可选）：

   ```xml
   <dependency>
     <groupId>com.aseantec</groupId>
     <artifactId>admin-auth-spring-boot-starter</artifactId>
     <version>0.1.0-SNAPSHOT</version>
   </dependency>
   ```

2. **加配置**（最小集）：

   ```yaml
   spring:
     flyway:
       enabled: false          # 必须：迁移由组件执行器管理
     session:
       jdbc:
         initialize-schema: never
         table-name: ADM_SESSION
   admin-auth:
     keys:
       data-kek: env:ADMIN_AUTH_DATA_KEK
       index-key: env:ADMIN_AUTH_INDEX_KEY
       otp-key: env:ADMIN_AUTH_OTP_KEY
     schema:
       mode: auto               # 生产改 validate
     protected-paths:
       - /admin/**
   ```

   宿主已有自己的 `SecurityFilterChain` 时，把 `admin-auth.security.mode` 改为 `INTEGRATED`，
   并复用组件导出的 `AdminSessionAuthenticationFilter` 与 `AdminAuthEntryPoint`。

3. **验证**：访问 `/admin-auth/login` 能打开页面；`GET /admin-auth/api/csrf` 返回 token；
   未登录访问 `/admin/hello` 返回 302（API 返回 401 JSON）。

所有 Bean 均为 `@ConditionalOnMissingBean`，可覆盖的 SPI：
`PasswordVerifier`、`SecretCipher`、`AuditSink`、`MfaPolicy`、`MfaChannelSender`（v1 无实现）、
`AdminUserProvider`、`IdentityNormalizer`、`StaffCodeGenerator`、`ClockProvider`。

## 7. curl 验收（等价脚本见 `scripts/acceptance.ps1`）

```bash
BASE=http://localhost:8080
JAR=/tmp/aa.cookies

# 0) CSRF：拿 token（cookie 会自动带上）
TOKEN=$(curl -s -c $JAR -b $JAR $BASE/admin-auth/api/csrf | sed -E 's/.*"token":"([^"]+)".*/\1/')

# 1) 登录
curl -s -c $JAR -b $JAR -H 'Content-Type: application/json' \
  -d '{"identityType":"EMAIL","identifier":"admin@corp.example","password":"Admin@123456"}' \
  $BASE/admin-auth/api/login
# → {"next":"CHANGE_PASSWORD","ticket":"..."}

# 2) 初始改密（非豁免接口，需 X-XSRF-TOKEN）
curl -s -c $JAR -b $JAR -H 'Content-Type: application/json' -H "X-XSRF-TOKEN: $TOKEN" \
  -d '{"ticket":"<ticket>","oldPassword":"Admin@123456","newPassword":"Str0ng-Passw0rd!2026"}' \
  $BASE/admin-auth/api/password/change-initial
# → {"next":"BIND_TOTP","ticket":"..."}

# 3) TOTP 初始化
curl -s -c $JAR -b $JAR -H 'Content-Type: application/json' \
  -d '{"ticket":"<ticket>"}' $BASE/admin-auth/api/mfa/totp/setup/init
# → {"otpauthUri":"...","qrSvg":"<svg...>","manualSecret":"..."}

# 4) 用认证器/本地算法算出 6 位码后确认（成功即建会话）
curl -s -c $JAR -b $JAR -H 'Content-Type: application/json' \
  -d '{"ticket":"<ticket>","code":"123456"}' $BASE/admin-auth/api/mfa/totp/setup/confirm
# → {"recoveryCodes":[...],"next":"OK","user":{...}}

# 5) 会话与受保护接口
curl -s -c $JAR -b $JAR $BASE/admin-auth/api/me
curl -s -c $JAR -b $JAR -o /dev/null -w '%{http_code}\n' $BASE/admin/hello   # 200
```

本仓库的 `scripts/acceptance.ps1` 完整覆盖 13 步（含登出、重登、TOTP 校验、受保护页 200），
使用 .NET HMAC-SHA1 本地计算 TOTP，无需外部依赖：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/acceptance.ps1
```

## 8. 测试

- `admin-auth-core`：35 个单测
  - RFC 6238 官方 SHA1 向量（8 位 6 组）+ Base32 向量
  - 规范化 / 盲索引（固定向量）/ AES-GCM 篡改检测 / 脱敏 / STAFF_CODE
  - 2FA 策略矩阵（4 模式 × 用户覆盖 × 同源 × require-totp × priority）
  - 锁定双维度（5 次/15 分钟、换标识不可绕过、到期清零）
- `admin-auth-spring-boot-starter`：`AdminAuthFlowIT`（Testcontainers MySQL）
  - 登录 → 改密 → 绑 TOTP → `/api/me` → `/admin/hello` → 登出 → 重登 → TOTP → 200
  - `@Testcontainers(disabledWithoutDocker = true)`：无 Docker 自动跳过
- `scripts/acceptance.ps1`：13 步主链路验收
- `scripts/api-test.ps1`：**67 项接口契约测试**（匿名、登录、改密、2FA、恢复码、管理端、
  用户生命周期、CSRF、锁定、错误码、会话失效；跑完打印可用于 UI 登录的最终密码/TOTP 密钥）

  ```powershell
  $env:AA_BASE="http://localhost:8080"   # 可选，默认 8080
  powershell -ExecutionPolicy Bypass -File scripts/api-test.ps1
  ```

## 9. 生产前检查清单

- [ ] `admin-auth.keys.*` 全部走 `env:`，密钥不入库、不进镜像
- [ ] `admin-auth.bootstrap.enabled=false`（首次初始化完成后关闭）
- [ ] `admin-auth.session.secure-cookie=true` + HTTPS；跨域时 `SameSite=None`
- [ ] `admin-auth.schema.mode=validate`，建表由发布流程执行
- [ ] `spring.flyway.enabled=false`（宿主 Boot Flyway 不扫描本组件迁移）
- [ ] 反向代理场景配置真实客户端 IP（否则锁定维度全部落在代理 IP）
- [ ] 审计日志接入统一日志/归档（组件只写库）
- [ ] 多实例部署：共享 MySQL、共享密钥、时钟同步

## 10. 已知取舍

- 事务边界：Bootstrap、TOTP 绑定/恢复码、改密、用户创建/重置密码/启停/解锁均已包事务；
  登录本身不包事务（含 BCrypt，避免长时间占用连接）。
- 启动顺序：schema 迁移与初始账号在 Web 端口监听前完成；多实例 bootstrap 由激活标识唯一键兜底。
- 密钥轮换：`key_version` + `data-kek-history` 已支持"新数据新密钥、旧数据可解密"；
  尚未提供批量重加密任务。
- 用户管理：已提供创建/分页/启停/解锁/重置密码 API 与审计；未提供前端管理页面。
- 仍有意不做：RBAC（业务权限归宿主）、i18n/品牌化、审计过滤分页、metrics/health、CORS 自动配置。
- v1 仅实现 TOTP；EMAIL_OTP/SMS_OTP 只有接口、表结构与 501 占位。
- 恢复码登录成功后会删除全部因素并强制重新绑定（下次登录回到 `BIND_TOTP`）。
- Boot 启动日志里的 `Using generated security password` 是 Spring Boot 自身生成的默认用户提示，
  与本组件无关（本组件链已禁用 formLogin/httpBasic，且从不打印初始密码）。

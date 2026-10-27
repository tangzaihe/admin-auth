-- =============================================================================
-- admin-auth V1：7 张业务表（权威定义见 admin-auth-schema.sql / schema.sql）
-- 约定：InnoDB + utf8mb4；时间 UTC + DATETIME(3)；状态 TINYINT；无物理外键
-- 注意：active_hash 为生成列，应用层 INSERT/UPDATE 不得出现该列
-- =============================================================================

CREATE TABLE adm_user (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '账号主键；仅内部关联与审计引用，不对外暴露、不作登录凭据',
  display_name         VARCHAR(64)  NOT NULL DEFAULT ''
    COMMENT '显示名（员工姓名/花名）；仅展示用途，不参与登录与唯一性判断',
  role                 VARCHAR(32)  NOT NULL DEFAULT 'ADMIN'
    COMMENT '粗粒度角色：SUPER_ADMIN/ADMIN/VIEWER；只用于 2FA 策略与管理权限，业务 RBAC 归宿主系统',
  status               TINYINT      NOT NULL DEFAULT 1
    COMMENT '账号状态：1=正常 0=停用（离职/风险）；停用后所有会话失效，不物理删除以保留审计链',
  password_hash        VARCHAR(100) NOT NULL
    COMMENT '第一因素密码哈希（BCrypt cost>=12 / Argon2id）；禁止明文或可逆加密',
  password_algo        VARCHAR(16)  NOT NULL DEFAULT 'BCRYPT'
    COMMENT '密码哈希算法标识；用于算法升级时判断是否需要惰性重算（登录成功后升级）',
  must_change_password TINYINT      NOT NULL DEFAULT 1
    COMMENT '是否强制改密：1=下次登录必须先改密（初始密码/管理员重置后置 1）',
  mfa_state            TINYINT      NOT NULL DEFAULT 0
    COMMENT '2FA 绑定状态：0=未绑定 1=已绑定 2=重置中；仅作状态汇总，因素明细在 adm_mfa_factor',
  mfa_required         TINYINT      NOT NULL DEFAULT -1
    COMMENT '用户级 2FA 覆盖：-1=继承角色策略 0=强制关闭 1=强制开启；仅管理员可改并落审计',
  token_version        INT          NOT NULL DEFAULT 0
    COMMENT '令牌版本号；改密/停用/重置 2FA 时 +1，使已签发会话/令牌立即失效（避免逐条删 session 的竞态）',
  pwd_updated_at       DATETIME(3)  NULL
    COMMENT '最近一次改密时间（UTC）；用于密码有效期策略与安全审计',
  last_login_at        DATETIME(3)  NULL
    COMMENT '最近一次成功登录时间（UTC）；用于不活跃清理、安全看板与提醒策略',
  created_at           DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '创建时间（UTC）；审计字段，写入后不再修改',
  updated_at           DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
    COMMENT '最后更新时间（UTC）；由 MySQL 自动维护',
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='账号主体：一人一账号，承载密码与账号级状态；标识/因素拆表';

CREATE TABLE adm_identity (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '标识主键；内部关联用',
  user_id         BIGINT UNSIGNED NOT NULL
    COMMENT '归属账号 ID；一个账号可挂多个登录标识（邮箱/手机/STAFF_CODE）',
  identity_type   VARCHAR(16)  NOT NULL
    COMMENT '标识类型：EMAIL=公司邮箱 / PHONE=员工个人手机号 / STAFF_CODE=系统派发登录码；决定规范化规则与 2FA 同源判断',
  value_enc       VARBINARY(512) NOT NULL
    COMMENT '标识明文密文：AES-256-GCM(iv(12B)||ciphertext||tag(16B))；明文只存内存与展示层，绝不落库',
  key_version     SMALLINT     NOT NULL DEFAULT 1
    COMMENT '加密密钥版本号；支持 KEK 轮换（新旧版本并存，后台重加密后升版本）',
  value_hash      BINARY(32)   NOT NULL
    COMMENT '盲索引：HMAC-SHA256(INDEX_KEY, type|normalized|v1)；登录时先规范化再算哈希，等值查询与唯一约束都走此列',
  value_mask      VARCHAR(64)  NOT NULL DEFAULT ''
    COMMENT '脱敏展示值（如 138****1234 / a***@corp.com）；列表页默认返回它，查看明文需权限+审计',
  verified_at     DATETIME(3)  NULL
    COMMENT '标识验证通过时间（UTC）：邮箱由管理员导入/邮件验证，手机号由短信验证码，STAFF_CODE 创建即有效；NULL 表示未验证',
  consent_at      DATETIME(3)  NULL
    COMMENT '个人手机号告知同意时间（PIPL）；仅 PHONE 类型使用，未同意不允许绑定',
  consent_version VARCHAR(16)  NOT NULL DEFAULT ''
    COMMENT '同意文案版本号；用于合规举证时确认员工同意的是哪一版告知内容',
  is_primary      TINYINT      NOT NULL DEFAULT 0
    COMMENT '是否同类型主标识：1=主（默认展示/默认 OTP 通道）；每种类型至多一个 ACTIVE 主标识（应用层保证）',
  status          TINYINT      NOT NULL DEFAULT 1
    COMMENT '标识状态：1=启用 0=停用（换绑/离职，可释放给他人） 2=保留（STAFF_CODE 停用后保留，永不复用）',
  active_hash     BINARY(32) GENERATED ALWAYS AS (IF(status = 1, value_hash, NULL)) STORED
    COMMENT '唯一性辅助生成列：仅 status=1 时等于 value_hash，否则 NULL；配合唯一键实现"只约束启用行"，停用行不占用号码',
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '创建时间（UTC）',
  updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
    COMMENT '最后更新时间（UTC）',
  PRIMARY KEY (id),
  UNIQUE KEY uk_adm_identity_active (identity_type, active_hash),
  KEY idx_adm_identity_user (user_id, identity_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='登录标识表：邮箱/个人手机号/STAFF_CODE 三类登录凭据，密文+盲索引+脱敏';

CREATE TABLE adm_mfa_factor (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '因素主键；内部关联用',
  user_id        BIGINT UNSIGNED NOT NULL
    COMMENT '归属账号 ID；一个账号可同时绑定多个因素（TOTP + 备用 OTP）',
  factor_type    VARCHAR(16)  NOT NULL
    COMMENT '因素类型：TOTP=认证器动态码 / EMAIL_OTP=邮箱验证码 / SMS_OTP=短信验证码；预留 WEBAUTHN',
  identity_id    BIGINT UNSIGNED NOT NULL DEFAULT 0
    COMMENT 'OTP 类型的发送通道（指向 adm_identity.id）；TOTP 不适用填 0。用 0 哨兵而非 NULL，避免 MySQL 唯一键对 NULL 失效导致重复因素',
  secret_enc     VARBINARY(512) NULL
    COMMENT 'TOTP 共享密钥密文：AES-256-GCM(iv||ct||tag)；OTP/WebAuthn 类型为 NULL，禁止明文存储',
  key_version    SMALLINT     NOT NULL DEFAULT 1
    COMMENT 'secret 加密密钥版本号；支持 KEK 轮换',
  digits         TINYINT      NOT NULL DEFAULT 6
    COMMENT '验证码位数；TOTP 默认 6 位（与 otpauth URI 的 digits 参数一致）',
  period         SMALLINT     NOT NULL DEFAULT 30
    COMMENT 'TOTP 时间步长（秒）；默认 30s，与 otpauth URI 的 period 参数一致',
  last_used_step BIGINT       NOT NULL DEFAULT 0
    COMMENT '已成功使用的最大时间步；校验时只在 > 该值的时间步中匹配并原子推进，防止同一验证码重放',
  payload        JSON         NULL
    COMMENT '扩展载荷：预留给 WebAuthn（credential_id/public_key/sign_count）或未来因素类型，避免频繁改表',
  priority       SMALLINT     NOT NULL DEFAULT 100
    COMMENT '因素优先级（数值小优先）；登录时用于默认选择与排序，TOTP 建议 10、SMS 20、EMAIL 30',
  confirmed_at   DATETIME(3)  NULL
    COMMENT '绑定确认时间（UTC）；NULL 表示待确认（status=2），确认后才可参与登录校验',
  fail_count     INT          NOT NULL DEFAULT 0
    COMMENT '该因素连续校验失败次数；用于因素级限速/锁定，成功校验后清零',
  locked_until   DATETIME(3)  NULL
    COMMENT '因素级锁定截止时间（UTC）；NULL=未锁定，超限后置值，到期自动解锁（或管理员重置）',
  status         TINYINT      NOT NULL DEFAULT 1
    COMMENT '因素状态：1=启用 0=停用 2=待确认（已生成 secret 但用户尚未输码确认）',
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '创建时间（UTC）',
  updated_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
    COMMENT '最后更新时间（UTC）',
  PRIMARY KEY (id),
  UNIQUE KEY uk_adm_factor_user_type (user_id, factor_type, identity_id),
  KEY idx_adm_factor_user (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='第二因素表：TOTP/邮箱码/短信码可扩展；secret 密文+防重放步进+因素级锁定';

CREATE TABLE adm_otp_code (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '验证码记录主键',
  user_id     BIGINT UNSIGNED NOT NULL
    COMMENT '接收验证码的账号 ID；用于按账号限速与核销',
  factor_type VARCHAR(16) NOT NULL
    COMMENT '验证码通道类型：EMAIL_OTP / SMS_OTP；决定通过哪个 MfaChannelSender 发送',
  identity_id BIGINT UNSIGNED NOT NULL
    COMMENT '发送目标通道（指向 adm_identity.id）；记录实际发往哪个邮箱/手机号，换绑后旧码不应命新通道',
  scene       VARCHAR(16) NOT NULL
    COMMENT '使用场景：LOGIN_2FA=登录第二因素 / BIND=绑定或换绑通道 / RESET=重置 2FA；不同场景不可混用',
  code_hash   BINARY(32)  NOT NULL
    COMMENT '验证码哈希：HMAC-SHA256(OTP_KEY, code)；验证时对提交值重算比对，明文不落库不进日志',
  attempts    TINYINT     NOT NULL DEFAULT 0
    COMMENT '已尝试校验次数；超过上限（默认 5）置 LOCKED，防止 6 位码被枚举',
  status      VARCHAR(16) NOT NULL DEFAULT 'ISSUED'
    COMMENT '验证码状态：ISSUED=已签发 / VERIFIED=已验证 / EXPIRED=已过期 / LOCKED=尝试超限作废',
  expires_at  DATETIME(3) NOT NULL
    COMMENT '过期时间（UTC）；默认签发后 5 分钟，过期即不可用',
  created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '签发时间（UTC）；同时用于重发冷却（60s）与小时/日配额统计',
  verified_at DATETIME(3) NULL
    COMMENT '核销时间（UTC）；记录实际使用时间，便于审计与异常排查',
  PRIMARY KEY (id),
  KEY idx_adm_otp_user_scene (user_id, scene, status),
  KEY idx_adm_otp_expire (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='一次性验证码签发/核销记录；HMAC 哈希存储、场景隔离、尝试上限';

CREATE TABLE adm_recovery_code (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '恢复码主键',
  user_id    BIGINT UNSIGNED NOT NULL
    COMMENT '归属账号 ID；每个账号一次生成 10 个',
  code_hash  VARCHAR(100) NOT NULL
    COMMENT '恢复码哈希（HMAC-SHA256 十六进制）；明文仅在生成时展示一次，之后不可再次查看',
  used_at    DATETIME(3) NULL
    COMMENT '使用时间（UTC）；非 NULL 表示已用，单次有效不可重放',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '生成时间（UTC）；重新生成时旧码批量作废/删除',
  PRIMARY KEY (id),
  KEY idx_adm_recovery_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='一次性恢复码；哈希存储、单次使用、可整批重置';

CREATE TABLE adm_audit_log (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '审计记录主键；单调递增便于按时间回溯',
  user_id       BIGINT UNSIGNED NULL
    COMMENT '事件主体账号 ID；账号不存在（登录失败/枚举尝试）时为 NULL',
  actor_user_id BIGINT UNSIGNED NULL
    COMMENT '操作者账号 ID：管理员重置 2FA、改策略、停用账号等场景记录"谁操作的"；用户自操作时可为空',
  identity_type VARCHAR(16) NOT NULL DEFAULT ''
    COMMENT '本次事件使用的登录标识类型（EMAIL/PHONE/STAFF_CODE）；非登录类事件为空串',
  factor_type   VARCHAR(16) NOT NULL DEFAULT ''
    COMMENT '本次事件涉及的第二因素类型（TOTP/SMS_OTP/EMAIL_OTP/RECOVERY）；非 2FA 事件为空串',
  channel_mask  VARCHAR(64) NOT NULL DEFAULT ''
    COMMENT '涉及的通道脱敏值（如 138****1234）；禁止存明文手机号/邮箱',
  event         VARCHAR(48) NOT NULL
    COMMENT '事件类型：LOGIN_PASSWORD_OK/LOGIN_FAIL/MFA_BIND/MFA_VERIFY_OK/MFA_VERIFY_FAIL/MFA_RESET/PASSWORD_CHANGE/LOGOUT/LOCKED/BREAK_GLASS 等',
  result        VARCHAR(16) NOT NULL
    COMMENT '结果：SUCCESS / FAIL；与 event 组合表达"某事件成功/失败"',
  ip            VARCHAR(45) NOT NULL DEFAULT ''
    COMMENT '来源 IP（IPv4/IPv6，45 字符足够）；用于风控与溯源',
  user_agent    VARCHAR(255) NOT NULL DEFAULT ''
    COMMENT '客户端 UA（截断到 255）；用于识别异常设备，避免存超长头部',
  detail        JSON NULL
    COMMENT '扩展详情 JSON（如失败原因码、策略变更前后值）；必须脱敏，禁止放验证码/token/明文 PII',
  created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    COMMENT '事件发生时间（UTC）；审计表按此列归档/分区',
  PRIMARY KEY (id),
  KEY idx_adm_audit_user_time (user_id, created_at),
  KEY idx_adm_audit_event_time (event, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='认证与安全审计流水；只增不改、脱敏、按时间归档（留存≥180天）';

CREATE TABLE adm_login_attempt (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT
    COMMENT '计数记录主键',
  user_id       BIGINT UNSIGNED NULL
    COMMENT '命中的账号 ID（标识存在时回填）；用于 user 维度合并计数，防止换标识绕过锁定',
  identity_hash BINARY(32) NOT NULL
    COMMENT '标识盲索引（与 adm_identity.value_hash 同算法）；账号不存在时也能按标识计数，防枚举探测',
  ip            VARCHAR(45) NOT NULL
    COMMENT '来源 IP（IPv4/IPv6）；与标识/账号组合限速，避免单 IP 撞库',
  fail_count    INT NOT NULL DEFAULT 0
    COMMENT '连续失败次数；成功登录/解锁后清零',
  locked_until  DATETIME(3) NULL
    COMMENT '锁定截止时间（UTC）；NULL=未锁定，达到阈值写入，到期自动解锁',
  updated_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
    COMMENT '最后更新时间（UTC）；用于清理长期不活跃的计数行',
  PRIMARY KEY (id),
  UNIQUE KEY uk_adm_attempt (identity_hash, ip),
  KEY idx_adm_attempt_user (user_id, ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='登录失败计数与锁定；标识+账号双维度计数，防爆破与换标识绕过';

-- =============================================================================
-- admin-auth V2：Spring Session JDBC 会话表（表名带 ADM_ 前缀，避免与宿主冲突）
-- 与 V1 同样使用 InnoDB/utf8mb4；外键 ON DELETE CASCADE 保证属性随会话清理
-- =============================================================================

CREATE TABLE ADM_SESSION (
  PRIMARY_ID            CHAR(36) NOT NULL
    COMMENT '会话主键（UUID）',
  SESSION_ID            CHAR(36) NOT NULL
    COMMENT '会话 ID（Cookie 中携带的是它）',
  CREATION_TIME         BIGINT   NOT NULL
    COMMENT '创建时间（epoch millis）',
  LAST_ACCESS_TIME      BIGINT   NOT NULL
    COMMENT '最后访问时间（epoch millis）；用于空闲超时',
  MAX_INACTIVE_INTERVAL INT      NOT NULL
    COMMENT '最大空闲间隔（秒）；空闲超过它即过期',
  EXPIRY_TIME           BIGINT   NOT NULL
    COMMENT '过期时间（epoch millis）= lastAccess + maxInactive',
  PRINCIPAL_NAME        VARCHAR(100) NULL
    COMMENT '主体名（登录标识脱敏值或账号 ID）；用于按人查会话、强制下线',
  CONSTRAINT ADM_SESSION_PK PRIMARY KEY (PRIMARY_ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='Spring Session 会话表（可选）';

CREATE UNIQUE INDEX ADM_SESSION_IX1 ON ADM_SESSION (SESSION_ID);
CREATE INDEX ADM_SESSION_IX2 ON ADM_SESSION (EXPIRY_TIME);
CREATE INDEX ADM_SESSION_IX3 ON ADM_SESSION (PRINCIPAL_NAME);

CREATE TABLE ADM_SESSION_ATTRIBUTES (
  SESSION_PRIMARY_ID CHAR(36)     NOT NULL
    COMMENT '所属会话主键；外键关联 ADM_SESSION.PRIMARY_ID',
  ATTRIBUTE_NAME     VARCHAR(200) NOT NULL
    COMMENT '属性名（如登录态、step-up 时间戳、mfa ticket 等）',
  ATTRIBUTE_BYTES    BLOB         NOT NULL
    COMMENT '属性值序列化字节（Java 序列化）；严禁放入明文密码/secret',
  CONSTRAINT ADM_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
  CONSTRAINT ADM_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID)
    REFERENCES ADM_SESSION (PRIMARY_ID) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='Spring Session 会话属性表（可选）';

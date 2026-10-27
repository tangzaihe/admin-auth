package com.aseantec.adminauth.starter.schema;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.config.SchemaMode;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

/**
 * schema 执行器：独立 history 表 {@code adm_schema_history}，模式 off/auto/validate。
 *
 * <p><b>链路</b>：mode=OFF 直接返回 → AUTO 时 MySQL 先 {@code GET_LOCK} 防并发
 * → Flyway migrate（validateOnMigrate=true）→ VALIDATE 时只 {@code validate()} 并 fail-fast。</p>
 *
 * <p>由 {@code AdminAuthStartupCoordinator} 在 Web 端口开始监听前调用，避免"服务已启动但表未建好"。</p>
 */
public class AdminAuthSchemaInitializer {

    private static final Logger log = LoggerFactory.getLogger(AdminAuthSchemaInitializer.class);

    private final DataSource dataSource;
    private final AdminAuthProperties properties;

    public AdminAuthSchemaInitializer(DataSource dataSource, AdminAuthProperties properties) {
        this.dataSource = dataSource;
        this.properties = properties;
    }

    public void initialize() {
        SchemaMode mode = properties.getSchema().getMode();
        if (mode == SchemaMode.OFF) {
            log.info("admin-auth schema.mode=off，跳过迁移管理");
            return;
        }
        boolean mysql = isMySql();
        String lockName = properties.getSchema().getLockName();
        boolean locked = false;
        try {
            if (mysql) {
                locked = acquireLock(lockName);
                if (!locked) {
                    throw new IllegalStateException("获取 MySQL 迁移锁失败: " + lockName);
                }
            }
            Flyway flyway = buildFlyway();
            if (mode == SchemaMode.AUTO) {
                MigrateResult result = flyway.migrate();
                log.info("admin-auth schema auto 完成：{} 个迁移已应用（history={}）",
                        result.migrationsExecuted, properties.getSchema().getTable());
            } else {
                flyway.validate();
                log.info("admin-auth schema validate 通过（history={}）", properties.getSchema().getTable());
            }
        } catch (RuntimeException e) {
            String reason = rootMessage(e);
            log.error("admin-auth 数据库初始化失败（schema.mode={}）：{}", mode, reason);
            log.error("排查建议：检查 spring.datasource.url/username/password、目标库是否已创建；"
                    + "本机无 MySQL 可用 --spring.profiles.active=demo（H2）；生产建议 schema.mode=validate");
            throw new AdminAuthSchemaException(mode, reason, e);
        } finally {
            if (locked) {
                releaseLock(lockName);
            }
        }
    }

    private Flyway buildFlyway() {
        String locations = properties.getSchema().getLocations();
        return Flyway.configure()
                .dataSource(dataSource)
                .locations(locations.split("\\s*,\\s*"))
                .table(properties.getSchema().getTable())
                .baselineOnMigrate(false)
                .validateOnMigrate(true)
                .cleanDisabled(true)
                .load();
    }

    private boolean isMySql() {
        try (Connection connection = dataSource.getConnection()) {
            String product = connection.getMetaData().getDatabaseProductName();
            return product != null && product.toLowerCase(Locale.ROOT).contains("mysql");
        } catch (SQLException e) {
            return false;
        }
    }

    private boolean acquireLock(String lockName) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT GET_LOCK(?, 10)")) {
            ps.setString(1, lockName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getInt(1) == 1;
            }
        } catch (SQLException e) {
            log.warn("GET_LOCK 调用失败，继续执行迁移: {}", e.getMessage());
            return false;
        }
    }

    private void releaseLock(String lockName) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT RELEASE_LOCK(?)")) {
            ps.setString(1, lockName);
            ps.executeQuery().close();
        } catch (SQLException e) {
            log.warn("RELEASE_LOCK 调用失败: {}", e.getMessage());
        }
    }

    /** 取最深层原因的消息（Flyway/驱动会把根因包很多层），并截断避免日志刷屏。 */
    private String rootMessage(Throwable error) {
        Throwable current = error;
        String message = error.getMessage();
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
            if (current.getMessage() != null && !current.getMessage().isBlank()) {
                message = current.getMessage();
            }
        }
        if (message == null || message.isBlank()) {
            return error.getClass().getSimpleName();
        }
        return message.length() > 300 ? message.substring(0, 300) + "..." : message;
    }
}

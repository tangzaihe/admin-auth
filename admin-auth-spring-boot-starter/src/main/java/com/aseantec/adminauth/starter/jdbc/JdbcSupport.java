package com.aseantec.adminauth.starter.jdbc;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * JDBC 小工具：统一参数绑定（{@link Instant} → {@link Timestamp}）、生成主键读写、时间列读取。
 * <p>时间一律走 {@code Timestamp.from(Instant)}，避免时区漂移（第 8 段坑 ⑨）。</p>
 */
public final class JdbcSupport {

    private JdbcSupport() {
    }

    public static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    public static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp ts = rs.getTimestamp(column);
        return ts == null ? null : ts.toInstant();
    }

    public static Instant instantOrNow(Instant value) {
        return value == null ? Instant.now() : value;
    }

    public static long insert(JdbcTemplate jdbc, String sql, Object... args) {
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            bind(ps, args);
            return ps;
        }, keyHolder);
        // H2 会把行内所有默认列一起返回（多 key），因此按 key 列表取主键而不是 getKey()
        java.util.List<java.util.Map<String, Object>> keyList = keyHolder.getKeyList();
        if (keyList.isEmpty()) {
            return -1L;
        }
        java.util.Map<String, Object> keys = keyList.get(0);
        Object candidate = keys.get("id");
        if (candidate == null) {
            candidate = keys.get("ID");
        }
        if (candidate == null) {
            candidate = keys.get("GENERATED_KEY");
        }
        if (candidate == null) {
            for (Object value : keys.values()) {
                if (value instanceof Number) {
                    candidate = value;
                    break;
                }
            }
        }
        return candidate instanceof Number number ? number.longValue() : -1L;
    }

    public static void bind(PreparedStatement ps, Object... args) throws SQLException {
        for (int i = 0; i < args.length; i++) {
            Object value = args[i];
            int index = i + 1;
            if (value == null) {
                ps.setObject(index, null);
            } else if (value instanceof Instant instant) {
                ps.setTimestamp(index, Timestamp.from(instant));
            } else if (value instanceof byte[] bytes) {
                ps.setBytes(index, bytes);
            } else if (value instanceof Enum<?> enumValue) {
                ps.setString(index, enumValue.name());
            } else if (value instanceof Boolean bool) {
                ps.setBoolean(index, bool);
            } else {
                ps.setObject(index, value);
            }
        }
    }

    public static String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    public static String nullIfBlank(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}

package com.aseantec.adminauth.starter.info;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.AdminAuthVersion;
import com.aseantec.adminauth.starter.keys.KeyMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * 启动信息：组件版本、schema 版本、Security 模式、密钥来源（只打印来源，不打印密钥）。
 */
public class AdminAuthInfoLogger implements ApplicationRunner, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AdminAuthInfoLogger.class);

    private final AdminAuthProperties properties;
    private final KeyMaterial keyMaterial;
    private final JdbcTemplate jdbc;

    public AdminAuthInfoLogger(AdminAuthProperties properties, KeyMaterial keyMaterial, JdbcTemplate jdbc) {
        this.properties = properties;
        this.keyMaterial = keyMaterial;
        this.jdbc = jdbc;
    }

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    public void run(ApplicationArguments args) {
        log.info("admin-auth {} | endpoint={} | schema.mode={} | schema.version={} | security.mode={} | ui={}",
                AdminAuthVersion.VERSION,
                properties.getEndpointPrefix(),
                properties.getSchema().getMode(),
                schemaVersion(),
                properties.getSecurity().getMode(),
                properties.getUi().isEnabled());
        log.info("admin-auth keys: data-kek v{}={}, history={}, index-key={}, otp-key={}（仅来源，不输出密钥）",
                keyMaterial.dataKekVersion(), keyMaterial.dataKekSource(), keyMaterial.dataKekHistorySource(),
                keyMaterial.indexKeySource(), keyMaterial.otpKeySource());
        log.info("admin-auth mfa.mode={} | require-totp-roles={} | forbid-same-channel={}",
                properties.getMfa().getMode(),
                properties.getMfa().getRequireTotpRoles(),
                properties.getMfa().isForbidSameChannel());
    }

    private String schemaVersion() {
        try {
            String version = jdbc.queryForObject("SELECT MAX(version) FROM " + properties.getSchema().getTable(),
                    String.class);
            return version == null ? "empty" : version;
        } catch (RuntimeException e) {
            return "n/a";
        }
    }
}

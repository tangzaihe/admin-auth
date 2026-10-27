package com.aseantec.adminauth.starter;

import com.aseantec.adminauth.starter.config.AdminAuthCoreConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthInfoConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthJdbcConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthSchemaConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthSecurityConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthSessionConfiguration;
import com.aseantec.adminauth.starter.config.AdminAuthWebConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * admin-auth 自动装配入口。
 *
 * <p><b>零装配</b>：{@code admin-auth.enabled=false} 时整个自动配置不生效。
 * 所有 Bean 都标注 {@code @ConditionalOnMissingBean}，宿主可逐个覆盖。</p>
 *
 * <p><b>顺序</b>：在 DataSource/JdbcTemplate 之后装配，保证 {@code @ConditionalOnBean(DataSource)}
 * 判定可靠；组件自身不接管 Spring Boot 的 Flyway 自动配置（见 README 接入说明）。</p>
 */
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, JdbcTemplateAutoConfiguration.class})
@ConditionalOnProperty(prefix = "admin-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AdminAuthProperties.class)
@Import({
        AdminAuthCoreConfiguration.class,
        AdminAuthJdbcConfiguration.class,
        AdminAuthSecurityConfiguration.class,
        AdminAuthWebConfiguration.class,
        AdminAuthSchemaConfiguration.class,
        AdminAuthSessionConfiguration.class,
        AdminAuthInfoConfiguration.class
})
public class AdminAuthAutoConfiguration {
}

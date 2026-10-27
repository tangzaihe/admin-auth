package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.schema.AdminAuthSchemaInitializer;
import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/** schema 执行器装配（off 模式下执行器直接跳过）。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Flyway.class)
@ConditionalOnBean(DataSource.class)
public class AdminAuthSchemaConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthSchemaInitializer adminAuthSchemaInitializer(DataSource dataSource,
                                                                 AdminAuthProperties properties) {
        return new AdminAuthSchemaInitializer(dataSource, properties);
    }
}

package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.info.AdminAuthInfoLogger;
import com.aseantec.adminauth.starter.keys.KeyMaterial;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** 启动信息装配。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBean(JdbcTemplate.class)
public class AdminAuthInfoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthInfoLogger adminAuthInfoLogger(AdminAuthProperties properties,
                                                   KeyMaterial keyMaterial,
                                                   JdbcTemplate jdbcTemplate) {
        return new AdminAuthInfoLogger(properties, keyMaterial, jdbcTemplate);
    }
}

package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import com.aseantec.adminauth.starter.i18n.BundleAdminAuthMessages;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 文案解析装配。
 *
 * <p>只注册 {@link AdminAuthMessages}，<b>不注册 {@code messageSource}</b>：
 * 宿主如果已有自己的 i18n（{@code messages.properties} / 自定义 MessageSource），
 * 不会被本组件覆盖；需要统一翻译入口时，宿主声明自己的 {@link AdminAuthMessages} Bean 即可。</p>
 */
@Configuration(proxyBeanMethods = false)
public class AdminAuthI18nConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthMessages adminAuthMessages(AdminAuthProperties properties) {
        AdminAuthProperties.I18n i18n = properties.getI18n();
        return new BundleAdminAuthMessages(i18n.isEnabled(), i18n.getDefaultLocale(), i18n.getSupportedLocales());
    }
}

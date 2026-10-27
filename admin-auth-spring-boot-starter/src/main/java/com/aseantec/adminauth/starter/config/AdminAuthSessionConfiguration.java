package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.starter.AdminAuthProperties;
import jakarta.servlet.ServletContext;
import jakarta.servlet.SessionCookieConfig;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * 会话参数落地：Cookie 名/域/Secure/SameSite、空闲超时（Spring Session），
 * 以及 Servlet 容器 session cookie 兜底配置。
 *
 * <p>绝对有效期不在容器侧，由 {@code AdminSessionAuthenticationFilter} 按
 * principal.absoluteExpireAt 强制。</p>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass({DefaultCookieSerializer.class, JdbcIndexedSessionRepository.class})
public class AdminAuthSessionConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AdminAuthSessionConfiguration.class);

    @Bean
    @ConditionalOnMissingBean(name = "adminAuthSessionCustomizer")
    public org.springframework.beans.factory.SmartInitializingSingleton adminAuthSessionCustomizer(
            ObjectProvider<DefaultCookieSerializer> cookieSerializer,
            ObjectProvider<JdbcIndexedSessionRepository> sessionRepository,
            AdminAuthProperties properties) {
        return () -> {
            var session = properties.getSession();
            cookieSerializer.ifAvailable(serializer -> {
                serializer.setCookieName(session.getCookieName());
                serializer.setCookiePath("/");
                if (session.getDomain() != null && !session.getDomain().isBlank()) {
                    serializer.setDomainName(session.getDomain());
                }
                serializer.setUseSecureCookie(session.isSecureCookie());
                serializer.setSameSite(session.getSameSite());
            });
            sessionRepository.ifAvailable(repository ->
                    repository.setDefaultMaxInactiveInterval((int) session.getIdle().toSeconds()));
            log.debug("admin-auth 会话参数已应用: cookie={}, secure={}, sameSite={}, idle={}",
                    session.getCookieName(), session.isSecureCookie(), session.getSameSite(), session.getIdle());
        };
    }

    /** 非 Spring Session 场景：作用于 Servlet 容器原生 session cookie。 */
    @Bean
    @ConditionalOnMissingBean(name = "adminAuthServletSessionCookieConfigurer")
    public ServletContextInitializer adminAuthServletSessionCookieConfigurer(AdminAuthProperties properties) {
        return servletContext -> {
            try {
                applySessionCookie(servletContext, properties);
            } catch (IllegalStateException e) {
                log.debug("Servlet 会话 Cookie 配置忽略: {}", e.getMessage());
            }
        };
    }

    private void applySessionCookie(ServletContext servletContext, AdminAuthProperties properties) {
        var session = properties.getSession();
        SessionCookieConfig cookie = servletContext.getSessionCookieConfig();
        cookie.setName(session.getCookieName());
        cookie.setHttpOnly(true);
        cookie.setSecure(session.isSecureCookie());
        cookie.setPath("/");
        if (session.getDomain() != null && !session.getDomain().isBlank()) {
            cookie.setDomain(session.getDomain());
        }
    }
}

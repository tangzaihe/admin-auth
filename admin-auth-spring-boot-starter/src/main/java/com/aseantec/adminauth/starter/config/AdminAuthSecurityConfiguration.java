package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.security.AdminAuthAccessDeniedHandler;
import com.aseantec.adminauth.starter.security.AdminAuthEntryPoint;
import com.aseantec.adminauth.starter.security.AdminAuthProtectedPathFilter;
import com.aseantec.adminauth.starter.security.AdminSessionAuthenticationFilter;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * Security 三模式装配。
 *
 * <ul>
 *   <li><b>ISOLATED</b>（默认）：独立链 order={@code BASIC_AUTH_ORDER-20}；可选追加
 *       LOWEST_PRECEDENCE 的 permitAll 兜底链，压掉 Boot 默认链；</li>
 *   <li><b>INTEGRATED</b>：不建链，只导出 filter 与 EntryPoint 供宿主挂载；</li>
 *   <li><b>FILTER_ONLY</b>：permitAll 链 + Servlet Filter 保护 protected-paths。</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AdminAuthSecurityConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthEntryPoint adminAuthEntryPoint(AdminAuthProperties properties, ObjectMapper objectMapper) {
        return new AdminAuthEntryPoint(properties.getEndpointPrefix(), objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthAccessDeniedHandler adminAuthAccessDeniedHandler(AdminAuthProperties properties,
                                                                     ObjectMapper objectMapper) {
        return new AdminAuthAccessDeniedHandler(properties.getEndpointPrefix(), objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminSessionAuthenticationFilter adminSessionAuthenticationFilter(ClockProvider clock) {
        return new AdminSessionAuthenticationFilter(clock);
    }

    /** ISOLATED：组件自带完整 SecurityFilterChain。 */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "admin-auth.security", name = "mode", havingValue = "ISOLATED", matchIfMissing = true)
    static class IsolatedModeConfiguration {

        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 20)
        public SecurityFilterChain adminAuthIsolatedSecurityFilterChain(
                HttpSecurity http,
                AdminAuthProperties properties,
                AdminAuthEntryPoint entryPoint,
                AdminAuthAccessDeniedHandler accessDeniedHandler,
                AdminSessionAuthenticationFilter sessionFilter) throws Exception {
            String prefix = properties.getEndpointPrefix();
            String api = prefix + "/api";

            CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
            csrfRepository.setCookiePath("/");
            CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
            csrfHandler.setCsrfRequestAttributeName("_csrf");

            http
                    // 只接管本组件端点与受保护路径，其余交给兜底链/宿主链（避免 any-request 链互相不可达）
                    .securityMatcher(securityMatchers(properties))
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(csrfRepository)
                            .csrfTokenRequestHandler(csrfHandler)
                            // 登录与 2FA 接口豁免 CSRF（登录前还没有会话 token）
                            .ignoringRequestMatchers(api + "/login", api + "/mfa/**"))
                    .authorizeHttpRequests(auth -> auth
                            .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                            .requestMatchers("/error").permitAll()
                            .requestMatchers(HttpMethod.GET, api + "/csrf").permitAll()
                            .requestMatchers(HttpMethod.POST, api + "/login", api + "/password/change-initial",
                                    api + "/mfa/**").permitAll()
                            .requestMatchers(api + "/**").authenticated()
                            .requestMatchers(prefix + "/**").permitAll()
                            .requestMatchers(properties.getProtectedPaths().toArray(String[]::new)).authenticated()
                            .anyRequest().permitAll())
                    .exceptionHandling(ex -> ex
                            .authenticationEntryPoint(entryPoint)
                            .accessDeniedHandler(accessDeniedHandler))
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                            .sessionFixation(fixation -> fixation.changeSessionId()))
                    .requestCache(AbstractHttpConfigurer::disable)
                    .formLogin(AbstractHttpConfigurer::disable)
                    .httpBasic(AbstractHttpConfigurer::disable)
                    .logout(AbstractHttpConfigurer::disable)
                    .addFilterAfter(sessionFilter, SecurityContextHolderFilter.class);
            return http.build();
        }

        /** 本组件接管的路径：端点前缀、错误页、以及宿主声明的受保护路径。 */
        private String[] securityMatchers(AdminAuthProperties properties) {
            java.util.List<String> matchers = new java.util.ArrayList<>();
            matchers.add(properties.getEndpointPrefix() + "/**");
            matchers.add("/error");
            matchers.addAll(properties.getProtectedPaths());
            return matchers.toArray(String[]::new);
        }

        /** 兜底链：仅当宿主未提供自己的链时，压掉 Boot 默认链（默认开启）。 */
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnProperty(prefix = "admin-auth.security", name = "provide-host-fallback",
                havingValue = "true", matchIfMissing = true)
        public SecurityFilterChain adminAuthHostFallbackSecurityFilterChain(HttpSecurity http) throws Exception {
            http.securityMatcher("/**")
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(AbstractHttpConfigurer::disable)
                    .formLogin(AbstractHttpConfigurer::disable)
                    .httpBasic(AbstractHttpConfigurer::disable)
                    .logout(AbstractHttpConfigurer::disable)
                    .requestCache(AbstractHttpConfigurer::disable)
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
            return http.build();
        }
    }

    /** FILTER_ONLY：permitAll 链 + Servlet Filter 保护 protected-paths。 */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "admin-auth.security", name = "mode", havingValue = "FILTER_ONLY")
    static class FilterOnlyModeConfiguration {

        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        public SecurityFilterChain adminAuthFilterOnlySecurityFilterChain(
                HttpSecurity http, AdminAuthProperties properties) throws Exception {
            String api = properties.getEndpointPrefix() + "/api";
            CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
            csrfRepository.setCookiePath("/");
            http
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(csrfRepository)
                            .ignoringRequestMatchers(api + "/login", api + "/mfa/**"))
                    .formLogin(AbstractHttpConfigurer::disable)
                    .httpBasic(AbstractHttpConfigurer::disable)
                    .logout(AbstractHttpConfigurer::disable)
                    .requestCache(AbstractHttpConfigurer::disable)
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
            return http.build();
        }

        @Bean
        public FilterRegistrationBean<AdminAuthProtectedPathFilter> adminAuthProtectedPathFilter(
                AdminAuthProperties properties,
                AdminSessionService sessions,
                AdminAuthEntryPoint entryPoint) {
            FilterRegistrationBean<AdminAuthProtectedPathFilter> registration = new FilterRegistrationBean<>(
                    new AdminAuthProtectedPathFilter(properties.getProtectedPaths(), sessions, entryPoint));
            registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 1);
            registration.setName("adminAuthProtectedPathFilter");
            return registration;
        }
    }
}

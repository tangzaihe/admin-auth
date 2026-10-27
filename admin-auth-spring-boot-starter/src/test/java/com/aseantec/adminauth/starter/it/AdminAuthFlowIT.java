package com.aseantec.adminauth.starter.it;

import com.aseantec.adminauth.core.service.TotpService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实 MySQL（Testcontainers）端到端集成测试。
 *
 * <p>流程：登录 → 初始改密 → 绑定 TOTP → /api/me → /admin/hello → 登出
 * → 重登（要求第二因素）→ TOTP 校验 → /admin/hello 200。</p>
 *
 * <p>无 Docker 环境自动跳过（{@code @Testcontainers(disabledWithoutDocker = true)}）。</p>
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = AdminAuthFlowIT.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdminAuthFlowIT {

    private static final String INITIAL_PASSWORD = "Admin@123456";
    private static final String NEW_PASSWORD = "Str0ng-Passw0rd!2026";

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.0")
            .withDatabaseName("admin_auth")
            .withUsername("admin_auth")
            .withPassword("admin_auth");

    @DynamicPropertySource
    static void datasourceProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("spring.sql.init.mode", () -> "never");
        registry.add("spring.session.jdbc.initialize-schema", () -> "never");
        registry.add("spring.session.jdbc.table-name", () -> "ADM_SESSION");

        registry.add("admin-auth.schema.mode", () -> "auto");
        registry.add("admin-auth.session.secure-cookie", () -> "false");
        registry.add("admin-auth.mfa.mode", () -> "REQUIRED_ALL");
        registry.add("admin-auth.mfa.totp.period", () -> "1");
        registry.add("admin-auth.mfa.totp.window", () -> "0");
        registry.add("admin-auth.password.bcrypt-cost", () -> "4");
        registry.add("admin-auth.keys.data-kek", () -> "base64:POKbxwe2t8jynIsNN/p6K7ACzxbtPJ1p8P4xojQw8+Y=");
        registry.add("admin-auth.keys.index-key", () -> "base64:jDEnLohFN31dFWAABDr13ddDyUWMDFyP702qIYfNkS8=");
        registry.add("admin-auth.keys.otp-key", () -> "base64:4LVWTtuXh/xs9o1SIit4BCxlp/PmhYFmwDcjAhaKukw=");
        registry.add("admin-auth.bootstrap.email", () -> "admin@corp.example");
        registry.add("admin-auth.bootstrap.password", () -> INITIAL_PASSWORD);
    }

    @LocalServerPort
    int port;

    private final ObjectMapper mapper = new ObjectMapper();
    private final TotpService totp = new TotpService();

    @Test
    void loginChangePasswordBindTotpReloginAndAccessProtectedPage() throws Exception {
        HttpClient client = newClient();
        String base = "http://127.0.0.1:" + port;

        // 1) CSRF（同时种下 XSRF-TOKEN Cookie）
        JsonNode csrf = getJson(client, base, "/admin-auth/api/csrf");
        assertThat(csrf.get("token").asText()).isNotBlank();

        // 2) 初始登录 → 强制改密
        JsonNode login = postJson(client, base, "/admin-auth/api/login", Map.of(
                "identityType", "EMAIL",
                "identifier", "admin@corp.example",
                "password", INITIAL_PASSWORD), false);
        assertThat(login.get("next").asText()).isEqualTo("CHANGE_PASSWORD");
        String changeTicket = login.get("ticket").asText();

        // 3) 初始改密 → 要求绑定 TOTP
        JsonNode changed = postJson(client, base, "/admin-auth/api/password/change-initial", Map.of(
                "ticket", changeTicket,
                "oldPassword", INITIAL_PASSWORD,
                "newPassword", NEW_PASSWORD), true);
        assertThat(changed.get("next").asText()).isEqualTo("BIND_TOTP");
        String bindTicket = changed.get("ticket").asText();

        // 4) 绑定初始化 → 服务端二维码 SVG + 手动密钥
        JsonNode setup = postJson(client, base, "/admin-auth/api/mfa/totp/setup/init",
                Map.of("ticket", bindTicket), false);
        String secret = setup.get("manualSecret").asText();
        assertThat(secret).isNotBlank();
        assertThat(setup.get("otpauthUri").asText()).startsWith("otpauth://totp/");
        assertThat(setup.get("qrSvg").asText()).contains("<svg");

        // 5) 用本地 TOTP 算法确认绑定 → 一次性恢复码
        JsonNode confirm = postJson(client, base, "/admin-auth/api/mfa/totp/setup/confirm", Map.of(
                "ticket", bindTicket,
                "code", code(secret)), false);
        assertThat(confirm.get("recoveryCodes").size()).isEqualTo(10);
        assertThat(confirm.get("next").asText()).isEqualTo("OK");

        // 6) 会话已建立
        JsonNode me = getJson(client, base, "/admin-auth/api/me");
        assertThat(me.get("role").asText()).isEqualTo("SUPER_ADMIN");
        assertThat(me.get("mfaVerified").asBoolean()).isTrue();

        // 7) 受保护接口
        assertThat(get(client, base, "/admin/hello").statusCode()).isEqualTo(200);

        // 8) 登出（需要 CSRF）
        assertThat(post(client, base, "/admin-auth/api/logout", Map.of(), true).statusCode()).isEqualTo(200);

        // 9) 重登：必须走第二因素
        JsonNode secondLogin = postJson(client, base, "/admin-auth/api/login", Map.of(
                "identityType", "EMAIL",
                "identifier", "admin@corp.example",
                "password", NEW_PASSWORD), false);
        assertThat(secondLogin.get("next").asText()).isEqualTo("SELECT_FACTOR");
        String mfaTicket = secondLogin.get("ticket").asText();

        // 10) TOTP 校验（period=1，等待下一个时间步避免重放）
        Thread.sleep(1500L);
        JsonNode verified = postJson(client, base, "/admin-auth/api/mfa/verify", Map.of(
                "ticket", mfaTicket,
                "factorType", "TOTP",
                "code", code(secret)), false);
        assertThat(verified.get("next").asText()).isEqualTo("OK");

        // 11) 再次访问受保护接口
        assertThat(get(client, base, "/admin/hello").statusCode()).isEqualTo(200);
    }

    // ---------- helpers ----------

    private String code(String secretBase32) {
        long epochSeconds = System.currentTimeMillis() / 1000L;
        return totp.generate(totp.decodeBase32(secretBase32), epochSeconds, 6, 1);
    }

    private HttpClient newClient() {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return HttpClient.newBuilder()
                .cookieHandler(cookies)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    private String csrfToken(HttpClient client) {
        CookieManager manager = (CookieManager) client.cookieHandler().orElseThrow();
        return manager.getCookieStore().getCookies().stream()
                .filter(cookie -> "XSRF-TOKEN".equals(cookie.getName()))
                .map(HttpCookie::getValue)
                .findFirst()
                .orElse("");
    }

    private HttpResponse<String> get(HttpClient client, String base, String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + path)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode getJson(HttpClient client, String base, String path) throws Exception {
        HttpResponse<String> response = get(client, base, path);
        assertThat(response.statusCode()).as("GET %s -> %s", path, response.body()).isEqualTo(200);
        return mapper.readTree(response.body());
    }

    private HttpResponse<String> post(HttpClient client, String base, String path,
                                      Object body, boolean withCsrf) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
        if (withCsrf) {
            builder.header("X-XSRF-TOKEN", csrfToken(client));
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode postJson(HttpClient client, String base, String path,
                              Object body, boolean withCsrf) throws Exception {
        HttpResponse<String> response = post(client, base, path, body, withCsrf);
        assertThat(response.statusCode()).as("POST %s -> %s", path, response.body()).isEqualTo(200);
        return mapper.readTree(response.body());
    }

    // ---------- test application ----------

    @SpringBootApplication
    static class TestApp {

        @Bean
        TestController testController() {
            return new TestController();
        }
    }

    @RestController
    static class TestController {

        @GetMapping("/admin/hello")
        Map<String, Object> hello() {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("message", "hello, admin");
            return body;
        }
    }
}

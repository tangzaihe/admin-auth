package com.aseantec.adminauth.starter;

import com.aseantec.adminauth.core.domain.MfaPolicyMode;
import com.aseantec.adminauth.core.service.StaffCodeGenerator;
import com.aseantec.adminauth.starter.config.SchemaMode;
import com.aseantec.adminauth.starter.config.SecurityMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code admin-auth.*} 配置。
 *
 * <p>除 {@code enabled} 外所有项都有安全默认值；密钥必须显式配置（32 字节），
 * 支持 {@code env:NAME} / {@code base64:...} / 明文（按 UTF-8 解释）。</p>
 */
@ConfigurationProperties(prefix = "admin-auth")
public class AdminAuthProperties {

    /** 总开关：false 时零装配（不创建任何 Bean）。 */
    private boolean enabled = true;

    /** 端点前缀（页面与 /api 均挂在其下）。 */
    private String endpointPrefix = "/admin-auth";

    /** 需要登录才能访问的路径（Ant 风格）。 */
    private List<String> protectedPaths = new ArrayList<>(List.of("/admin/**"));

    private Identity identity = new Identity();
    private Mfa mfa = new Mfa();
    private Password password = new Password();
    private Lockout lockout = new Lockout();
    private Session session = new Session();
    private Keys keys = new Keys();
    private Schema schema = new Schema();
    private Security security = new Security();
    private Ui ui = new Ui();
    private Bootstrap bootstrap = new Bootstrap();
    private Audit audit = new Audit();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getEndpointPrefix() {
        return endpointPrefix;
    }

    public void setEndpointPrefix(String endpointPrefix) {
        this.endpointPrefix = endpointPrefix;
    }

    public List<String> getProtectedPaths() {
        return protectedPaths;
    }

    public void setProtectedPaths(List<String> protectedPaths) {
        this.protectedPaths = protectedPaths;
    }

    public Identity getIdentity() {
        return identity;
    }

    public void setIdentity(Identity identity) {
        this.identity = identity;
    }

    public Mfa getMfa() {
        return mfa;
    }

    public void setMfa(Mfa mfa) {
        this.mfa = mfa;
    }

    public Password getPassword() {
        return password;
    }

    public void setPassword(Password password) {
        this.password = password;
    }

    public Lockout getLockout() {
        return lockout;
    }

    public void setLockout(Lockout lockout) {
        this.lockout = lockout;
    }

    public Session getSession() {
        return session;
    }

    public void setSession(Session session) {
        this.session = session;
    }

    public Keys getKeys() {
        return keys;
    }

    public void setKeys(Keys keys) {
        this.keys = keys;
    }

    public Schema getSchema() {
        return schema;
    }

    public void setSchema(Schema schema) {
        this.schema = schema;
    }

    public Security getSecurity() {
        return security;
    }

    public void setSecurity(Security security) {
        this.security = security;
    }

    public Ui getUi() {
        return ui;
    }

    public void setUi(Ui ui) {
        this.ui = ui;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    public void setBootstrap(Bootstrap bootstrap) {
        this.bootstrap = bootstrap;
    }

    public Audit getAudit() {
        return audit;
    }

    public void setAudit(Audit audit) {
        this.audit = audit;
    }

    /** STAFF_CODE 生成配置。 */
    public static class Identity {

        private StaffCode staffCode = new StaffCode();

        public StaffCode getStaffCode() {
            return staffCode;
        }

        public void setStaffCode(StaffCode staffCode) {
            this.staffCode = staffCode;
        }

        public static class StaffCode {

            private String prefix = "EMP";
            private int digits = 6;
            private long startOffset = 1000;
            private StaffCodeGenerator.Strategy strategy = StaffCodeGenerator.Strategy.SEQUENTIAL;

            public String getPrefix() {
                return prefix;
            }

            public void setPrefix(String prefix) {
                this.prefix = prefix;
            }

            public int getDigits() {
                return digits;
            }

            public void setDigits(int digits) {
                this.digits = digits;
            }

            public long getStartOffset() {
                return startOffset;
            }

            public void setStartOffset(long startOffset) {
                this.startOffset = startOffset;
            }

            public StaffCodeGenerator.Strategy getStrategy() {
                return strategy;
            }

            public void setStrategy(StaffCodeGenerator.Strategy strategy) {
                this.strategy = strategy;
            }
        }
    }

    /** 2FA 策略配置。 */
    public static class Mfa {

        /** 默认 OPTIONAL：已绑定即校验；host 可按需改为 ON_RISK / REQUIRED_BY_ROLE / REQUIRED_ALL。 */
        private MfaPolicyMode mode = MfaPolicyMode.OPTIONAL;
        private Set<String> requiredRoles = new LinkedHashSet<>();
        private Set<String> requireTotpRoles = new LinkedHashSet<>();
        private boolean forbidSameChannel = true;
        private Duration stepUpTtl = Duration.ofMinutes(5);
        /** ON_RISK：窗口期内有密码失败才要求 TOTP。 */
        private Duration riskWindow = Duration.ofMinutes(30);
        /** ON_RISK：窗口期内至少失败几次才触发（默认 1）。 */
        private int riskMinFailures = 1;
        private Totp totp = new Totp();

        public Duration getRiskWindow() {
            return riskWindow;
        }

        public void setRiskWindow(Duration riskWindow) {
            this.riskWindow = riskWindow;
        }

        public int getRiskMinFailures() {
            return riskMinFailures;
        }

        public void setRiskMinFailures(int riskMinFailures) {
            this.riskMinFailures = riskMinFailures;
        }

        public MfaPolicyMode getMode() {
            return mode;
        }

        public void setMode(MfaPolicyMode mode) {
            this.mode = mode;
        }

        public Set<String> getRequiredRoles() {
            return requiredRoles;
        }

        public void setRequiredRoles(Set<String> requiredRoles) {
            this.requiredRoles = requiredRoles;
        }

        public Set<String> getRequireTotpRoles() {
            return requireTotpRoles;
        }

        public void setRequireTotpRoles(Set<String> requireTotpRoles) {
            this.requireTotpRoles = requireTotpRoles;
        }

        public boolean isForbidSameChannel() {
            return forbidSameChannel;
        }

        public void setForbidSameChannel(boolean forbidSameChannel) {
            this.forbidSameChannel = forbidSameChannel;
        }

        public Duration getStepUpTtl() {
            return stepUpTtl;
        }

        public void setStepUpTtl(Duration stepUpTtl) {
            this.stepUpTtl = stepUpTtl;
        }

        public Totp getTotp() {
            return totp;
        }

        public void setTotp(Totp totp) {
            this.totp = totp;
        }

        public static class Totp {

            private String issuer = "Admin Auth";
            private int digits = 6;
            private int period = 30;
            private int window = 1;

            public String getIssuer() {
                return issuer;
            }

            public void setIssuer(String issuer) {
                this.issuer = issuer;
            }

            public int getDigits() {
                return digits;
            }

            public void setDigits(int digits) {
                this.digits = digits;
            }

            public int getPeriod() {
                return period;
            }

            public void setPeriod(int period) {
                this.period = period;
            }

            public int getWindow() {
                return window;
            }

            public void setWindow(int window) {
                this.window = window;
            }
        }
    }

    /** 密码策略。 */
    public static class Password {

        private int minLength = 12;
        private int bcryptCost = 12;

        public int getMinLength() {
            return minLength;
        }

        public void setMinLength(int minLength) {
            this.minLength = minLength;
        }

        public int getBcryptCost() {
            return bcryptCost;
        }

        public void setBcryptCost(int bcryptCost) {
            this.bcryptCost = bcryptCost;
        }
    }

    /** 登录锁定。 */
    public static class Lockout {

        private int maxAttempts = 5;
        private Duration lockDuration = Duration.ofMinutes(15);

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(Duration lockDuration) {
            this.lockDuration = lockDuration;
        }
    }

    /** 会话与 Cookie。 */
    public static class Session {

        private String cookieName = "JSESSIONID";
        private String domain = "";
        private boolean secureCookie = true;
        private String sameSite = "Lax";
        private Duration idle = Duration.ofMinutes(30);
        private Duration absolute = Duration.ofHours(8);

        public String getCookieName() {
            return cookieName;
        }

        public void setCookieName(String cookieName) {
            this.cookieName = cookieName;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public boolean isSecureCookie() {
            return secureCookie;
        }

        public void setSecureCookie(boolean secureCookie) {
            this.secureCookie = secureCookie;
        }

        public String getSameSite() {
            return sameSite;
        }

        public void setSameSite(String sameSite) {
            this.sameSite = sameSite;
        }

        public Duration getIdle() {
            return idle;
        }

        public void setIdle(Duration idle) {
            this.idle = idle;
        }

        public Duration getAbsolute() {
            return absolute;
        }

        public void setAbsolute(Duration absolute) {
            this.absolute = absolute;
        }
    }

    /** 密钥（必须 32 字节）。 */
    public static class Keys {

        private String dataKek;
        /** 当前数据密钥版本号，写入 key_version 列。 */
        private int dataKekVersion = 1;
        /** 历史数据密钥：版本号 -> 密钥，用于解密旧密文（轮换时配置）。 */
        private Map<Integer, String> dataKekHistory = new LinkedHashMap<>();
        private String indexKey;
        private String otpKey;

        public String getDataKek() {
            return dataKek;
        }

        public void setDataKek(String dataKek) {
            this.dataKek = dataKek;
        }

        public int getDataKekVersion() {
            return dataKekVersion;
        }

        public void setDataKekVersion(int dataKekVersion) {
            this.dataKekVersion = dataKekVersion;
        }

        public Map<Integer, String> getDataKekHistory() {
            return dataKekHistory;
        }

        public void setDataKekHistory(Map<Integer, String> dataKekHistory) {
            this.dataKekHistory = dataKekHistory;
        }

        public String getIndexKey() {
            return indexKey;
        }

        public void setIndexKey(String indexKey) {
            this.indexKey = indexKey;
        }

        public String getOtpKey() {
            return otpKey;
        }

        public void setOtpKey(String otpKey) {
            this.otpKey = otpKey;
        }
    }

    /** 数据库 schema 管理。 */
    public static class Schema {

        private SchemaMode mode = SchemaMode.VALIDATE;
        private String table = "adm_schema_history";
        private String locations = "classpath:db/migration/admin-auth";
        private String lockName = "admin_auth_schema_migration";

        public SchemaMode getMode() {
            return mode;
        }

        public void setMode(SchemaMode mode) {
            this.mode = mode;
        }

        public String getTable() {
            return table;
        }

        public void setTable(String table) {
            this.table = table;
        }

        public String getLocations() {
            return locations;
        }

        public void setLocations(String locations) {
            this.locations = locations;
        }

        public String getLockName() {
            return lockName;
        }

        public void setLockName(String lockName) {
            this.lockName = lockName;
        }
    }

    /** Security 集成模式。 */
    public static class Security {

        private SecurityMode mode = SecurityMode.ISOLATED;
        private boolean provideHostFallback = true;

        public SecurityMode getMode() {
            return mode;
        }

        public void setMode(SecurityMode mode) {
            this.mode = mode;
        }

        public boolean isProvideHostFallback() {
            return provideHostFallback;
        }

        public void setProvideHostFallback(boolean provideHostFallback) {
            this.provideHostFallback = provideHostFallback;
        }
    }

    /** 内置页面。 */
    public static class Ui {

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /** 初始超级管理员。 */
    public static class Bootstrap {

        private boolean enabled = true;
        private String email = "";
        private String password = "";
        private String displayName = "超级管理员";
        private String role = "SUPER_ADMIN";
        private String staffCode = "";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getStaffCode() {
            return staffCode;
        }

        public void setStaffCode(String staffCode) {
            this.staffCode = staffCode;
        }
    }

    /** 审计。 */
    public static class Audit {

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}

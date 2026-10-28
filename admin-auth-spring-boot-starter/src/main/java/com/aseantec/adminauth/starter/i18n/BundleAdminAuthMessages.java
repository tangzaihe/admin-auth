package com.aseantec.adminauth.starter.i18n;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 基于 {@link ResourceBundle} 的默认实现：{@code i18n/admin-auth-messages[_zh_CN].properties}。
 *
 * <ul>
 *   <li>基名 {@code i18n/admin-auth-messages}，基础文件为英文，{@code _zh_CN} 为中文；</li>
 *   <li>只做「语言 → 受支持语言」协商，不做系统默认语言兜底，避免不同机器表现不一致；</li>
 *   <li>占位符用自实现的 {@code {n}} 替换，不用 {@link java.text.MessageFormat}，
 *       以免文案里的英文单引号被当成转义而吞字符。</li>
 * </ul>
 */
public class BundleAdminAuthMessages implements AdminAuthMessages {

    /** bundle 基名（classpath 相对路径）。 */
    public static final String BUNDLE_BASENAME = "i18n/admin-auth-messages";

    /** 所有键的统一前缀。 */
    public static final String KEY_PREFIX = "admin-auth.";

    private static final String UI_PAGE_PREFIX = KEY_PREFIX + "page.";
    private static final String UI_JS_PREFIX = KEY_PREFIX + "js.";
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{(\\d+)}");

    /**
     * 关掉 ResourceBundle 的"系统默认语言兜底"。
     *
     * <p>否则 JVM 默认语言是 zh_CN 时，{@code en} 找不到 {@code _en} 文件会先落到
     * {@code _zh_CN}，表现为"英文请求返回中文"。关掉后直接回落到基础文件（英文）。</p>
     */
    private static final ResourceBundle.Control NO_SYSTEM_FALLBACK = new ResourceBundle.Control() {
        @Override
        public Locale getFallbackLocale(String baseName, Locale locale) {
            return null;
        }
    };

    private final boolean negotiationEnabled;
    private final Locale fallback;
    private final List<Locale> supported;

    public BundleAdminAuthMessages(boolean negotiationEnabled, String defaultLocaleTag, List<String> supportedTags) {
        this.fallback = parseTag(defaultLocaleTag, Locale.SIMPLIFIED_CHINESE);
        List<Locale> locales = new ArrayList<>();
        if (supportedTags != null) {
            for (String tag : supportedTags) {
                Locale parsed = parseTag(tag, null);
                if (parsed != null && !locales.contains(parsed)) {
                    locales.add(parsed);
                }
            }
        }
        if (locales.isEmpty()) {
            locales.add(fallback);
        }
        this.supported = List.copyOf(locales);
        this.negotiationEnabled = negotiationEnabled;
    }

    /** 测试与「未装配 Spring 的宿主」用的最小实例：只认默认语言。 */
    public static BundleAdminAuthMessages singleLocale(String defaultLocaleTag) {
        return new BundleAdminAuthMessages(false, defaultLocaleTag, List.of(defaultLocaleTag));
    }

    @Override
    public Locale defaultLocale() {
        return fallback;
    }

    @Override
    public Locale resolve(Locale requested) {
        if (!negotiationEnabled || requested == null) {
            return fallback;
        }
        Locale matched = match(requested);
        return matched == null ? fallback : matched;
    }

    @Override
    public Locale resolve(List<Locale> requested) {
        if (!negotiationEnabled || requested == null) {
            return fallback;
        }
        for (Locale locale : requested) {
            Locale matched = match(locale);
            if (matched != null) {
                return matched;
            }
        }
        return fallback;
    }

    @Override
    public String message(Locale locale, String key, Object... args) {
        if (key == null || key.isEmpty()) {
            return "";
        }
        ResourceBundle bundle = bundle(resolve(locale));
        if (bundle == null) {
            return key;
        }
        String pattern;
        try {
            pattern = bundle.getString(key);
        } catch (MissingResourceException missing) {
            return key;
        }
        return args == null || args.length == 0 ? pattern : fill(pattern, args);
    }

    @Override
    public boolean contains(Locale locale, String key) {
        if (key == null || key.isEmpty()) {
            return false;
        }
        ResourceBundle bundle = bundle(resolve(locale));
        return bundle != null && bundle.containsKey(key);
    }

    @Override
    public Map<String, String> uiMessages(Locale locale) {
        Map<String, String> messages = new LinkedHashMap<>();
        // 先取当前语言，再用基础文件补齐缺失键（en 是兜底语言）
        collect(bundle(resolve(locale)), messages);
        collect(rootBundle(), messages);
        return messages;
    }

    // ---------- internals ----------

    private Locale match(Locale requested) {
        if (requested == null || requested.getLanguage().isEmpty()) {
            return null;
        }
        for (Locale candidate : supported) {
            if (candidate.getLanguage().equalsIgnoreCase(requested.getLanguage())
                    && candidate.getCountry().equalsIgnoreCase(requested.getCountry())) {
                return candidate;
            }
        }
        for (Locale candidate : supported) {
            if (candidate.getLanguage().equalsIgnoreCase(requested.getLanguage())) {
                return candidate;
            }
        }
        return null;
    }

    private void collect(ResourceBundle bundle, Map<String, String> target) {
        if (bundle == null) {
            return;
        }
        for (String key : bundle.keySet()) {
            if ((key.startsWith(UI_PAGE_PREFIX) || key.startsWith(UI_JS_PREFIX)) && !target.containsKey(strip(key))) {
                target.put(strip(key), bundle.getString(key));
            }
        }
    }

    private String strip(String key) {
        return key.startsWith(KEY_PREFIX) ? key.substring(KEY_PREFIX.length()) : key;
    }

    private ResourceBundle bundle(Locale locale) {
        try {
            return ResourceBundle.getBundle(BUNDLE_BASENAME, locale, classLoader(), NO_SYSTEM_FALLBACK);
        } catch (MissingResourceException missing) {
            return null;
        }
    }

    private ResourceBundle rootBundle() {
        return bundle(Locale.ROOT);
    }

    private ClassLoader classLoader() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader != null ? loader : BundleAdminAuthMessages.class.getClassLoader();
    }

    private static String fill(String pattern, Object[] args) {
        Matcher matcher = PLACEHOLDER.matcher(pattern);
        StringBuilder builder = new StringBuilder();
        while (matcher.find()) {
            int index = Integer.parseInt(matcher.group(1));
            String value = index < args.length ? String.valueOf(args[index]) : matcher.group();
            matcher.appendReplacement(builder, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(builder);
        return builder.toString();
    }

    private static Locale parseTag(String tag, Locale fallback) {
        if (tag == null || tag.isBlank()) {
            return fallback;
        }
        Locale parsed = Locale.forLanguageTag(tag.trim().replace('_', '-'));
        return parsed.getLanguage().isEmpty() ? fallback : parsed;
    }
}

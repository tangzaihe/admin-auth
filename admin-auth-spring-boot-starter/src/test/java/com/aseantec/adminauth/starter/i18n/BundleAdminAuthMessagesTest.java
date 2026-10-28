package com.aseantec.adminauth.starter.i18n;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import static org.assertj.core.api.Assertions.assertThat;

/** 文案解析：键集合一致性、语言协商、占位符、兜底语义。 */
class BundleAdminAuthMessagesTest {

    private static final List<String> SUPPORTED = List.of("zh-CN", "en");

    private final BundleAdminAuthMessages messages =
            new BundleAdminAuthMessages(true, "zh-CN", SUPPORTED);

    @Test
    @DisplayName("中英文 bundle 的键集合必须完全一致（漏翻即失败）")
    void bundlesDeclareIdenticalKeys() {
        ResourceBundle en = ResourceBundle.getBundle(BundleAdminAuthMessages.BUNDLE_BASENAME, Locale.ROOT);
        ResourceBundle zh = ResourceBundle.getBundle(BundleAdminAuthMessages.BUNDLE_BASENAME,
                Locale.SIMPLIFIED_CHINESE);

        assertThat(en.keySet()).isNotEmpty();
        assertThat(zh.keySet()).isEqualTo(en.keySet());
    }

    @Test
    @DisplayName("协商：en 命中英文、fr 回落到默认中文、多语言按顺序取第一个支持项")
    void negotiatesLocale() {
        assertThat(messages.resolve(Locale.ENGLISH).getLanguage()).isEqualTo("en");
        assertThat(messages.resolve(Locale.US).getLanguage()).isEqualTo("en");
        assertThat(messages.resolve(Locale.FRENCH).getLanguage()).isEqualTo("zh");
        assertThat(messages.resolve(List.of(Locale.FRENCH, Locale.UK)).getLanguage()).isEqualTo("en");
        assertThat(messages.resolve(List.of(Locale.JAPAN))).isEqualTo(messages.defaultLocale());
    }

    @Test
    @DisplayName("关闭协商后固定使用默认语言")
    void disabledNegotiationPinsDefaultLocale() {
        BundleAdminAuthMessages pinned = new BundleAdminAuthMessages(false, "zh-CN", SUPPORTED);

        assertThat(pinned.resolve(Locale.ENGLISH).getLanguage()).isEqualTo("zh");
    }

    @Test
    @DisplayName("按语言取文案，{0} 占位符被参数替换")
    void resolvesMessageWithPlaceholder() {
        assertThat(messages.message(Locale.ENGLISH, "admin-auth.password.too-short", 12))
                .contains("at least 12");
        assertThat(messages.message(Locale.SIMPLIFIED_CHINESE, "admin-auth.password.too-short", 12))
                .isEqualTo("密码长度至少 12 位");
        assertThat(messages.message(Locale.SIMPLIFIED_CHINESE, "admin-auth.error.auth-failed"))
                .isEqualTo("账号或密码错误");
    }

    @Test
    @DisplayName("未命中键时原样返回（宿主传入的历史文案因此仍能回显）")
    void returnsKeyWhenMissing() {
        assertThat(messages.message(Locale.ENGLISH, "admin-auth.not-exists")).isEqualTo("admin-auth.not-exists");
        assertThat(messages.message(Locale.ENGLISH, "账号或密码错误")).isEqualTo("账号或密码错误");
        assertThat(messages.contains(Locale.ENGLISH, "admin-auth.error.auth-failed")).isTrue();
        assertThat(messages.contains(Locale.ENGLISH, "admin-auth.not-exists")).isFalse();
    }

    @Test
    @DisplayName("页面文案表：去掉 admin-auth. 前缀，且不下发错误码文案")
    void uiMessagesStripPrefixAndExcludeErrors() {
        Map<String, String> ui = messages.uiMessages(Locale.ENGLISH);

        assertThat(ui).containsEntry("page.login.submit", "Sign in")
                .containsKey("js.requestFailed");
        assertThat(ui.keySet()).noneMatch(key -> key.startsWith("error."));
    }
}

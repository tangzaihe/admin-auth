package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.starter.i18n.BundleAdminAuthMessages;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ui.ExtendedModelMap;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** 页面控制器：把当前语言的文案表与 lang 放进模型。 */
class AdminAuthPageControllerTest {

    private final AdminAuthPageController controller =
            new AdminAuthPageController(new BundleAdminAuthMessages(true, "zh-CN", List.of("zh-CN", "en")));

    @Test
    @DisplayName("英文请求渲染英文文案表")
    @SuppressWarnings("unchecked")
    void exposesEnglishMessages() {
        ExtendedModelMap model = new ExtendedModelMap();

        String view = controller.login(Locale.ENGLISH, model);

        assertThat(view).isEqualTo("admin-auth/login");
        assertThat(model.get("lang")).isEqualTo("en");
        assertThat((Map<String, String>) model.get("i18n"))
                .containsEntry("page.login.title", "Admin Console · Sign in")
                .containsEntry("page.login.submit", "Sign in");
    }

    @Test
    @DisplayName("中文请求渲染中文文案表；不支持的语言回落到默认中文")
    @SuppressWarnings("unchecked")
    void fallsBackToChinese() {
        ExtendedModelMap model = new ExtendedModelMap();

        controller.twoFactor(Locale.JAPAN, model);

        assertThat(model.get("lang")).isEqualTo("zh-CN");
        assertThat((Map<String, String>) model.get("i18n"))
                .containsEntry("page.mfa.submit", "验 证");
    }
}

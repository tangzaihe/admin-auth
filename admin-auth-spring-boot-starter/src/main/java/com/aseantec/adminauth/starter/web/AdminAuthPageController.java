package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Locale;

/**
 * 内置页面（外壳 + 原生 JS，数据全部走 /api/**）。
 *
 * <p>页面本身不需要登录态：数据接口会返回 401，前端据此跳转登录页。</p>
 *
 * <p><b>i18n</b>：文案表以 {@code i18n} 模型属性注入（键去掉 {@code admin-auth.} 前缀），
 * 模板用 {@code th:text="${i18n['page.xxx']}"}，脚本用 {@code window.AA_I18N}。
 * 不依赖宿主是否配置 {@code messageSource}。</p>
 */
@Controller
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}")
public class AdminAuthPageController {

    /** 模板里使用的模型属性名。 */
    public static final String MODEL_MESSAGES = "i18n";

    /** 页面 {@code lang} 属性。 */
    public static final String MODEL_LANG = "lang";

    private final AdminAuthMessages messages;

    public AdminAuthPageController(AdminAuthMessages messages) {
        this.messages = messages;
    }

    @GetMapping({"/", "", "/login"})
    public String login(Locale locale, Model model) {
        return render("admin-auth/login", locale, model);
    }

    @GetMapping("/2fa")
    public String twoFactor(Locale locale, Model model) {
        return render("admin-auth/2fa", locale, model);
    }

    @GetMapping("/totp-setup")
    public String totpSetup(Locale locale, Model model) {
        return render("admin-auth/totp-setup", locale, model);
    }

    @GetMapping("/password-change")
    public String passwordChange(Locale locale, Model model) {
        return render("admin-auth/password-change", locale, model);
    }

    @GetMapping("/recovery-codes")
    public String recoveryCodes(Locale locale, Model model) {
        return render("admin-auth/recovery-codes", locale, model);
    }

    private String render(String view, Locale locale, Model model) {
        Locale target = messages.resolve(locale);
        model.addAttribute(MODEL_MESSAGES, messages.uiMessages(target));
        model.addAttribute(MODEL_LANG, target.toLanguageTag());
        return view;
    }
}

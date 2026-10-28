package com.aseantec.adminauth.starter.i18n;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 文案解析 SPI：把「消息键」翻译成「当前请求语言的文案」。
 *
 * <p><b>设计约束</b>（见 AGENTS.md）：本组件<b>不注册 {@code messageSource} Bean</b>，
 * 避免覆盖宿主的 i18n 配置；文案只通过本接口解析，宿主可声明同名 Bean 整体替换。</p>
 *
 * <p>找不到键时返回键本身（而不是 {@code ??key??}），因此宿主传入的历史中文文案
 * 会原样回显，改造期间保持向后兼容。</p>
 */
public interface AdminAuthMessages {

    /** 默认语言（请求语言不受支持时使用）。 */
    Locale defaultLocale();

    /** 把单个语言协商为受支持的语言。 */
    Locale resolve(Locale requested);

    /** 按客户端语言偏好（Accept-Language 的顺序）协商。 */
    Locale resolve(List<Locale> requested);

    /** 取文案；{@code args} 对应文案中的 {@code {0}} / {@code {1}} 占位符。 */
    String message(Locale locale, String key, Object... args);

    /** 该语言下是否存在该键（用于字段标签等可选文案）。 */
    boolean contains(Locale locale, String key);

    /**
     * 页面与前端脚本可用的文案表：键去掉 {@code admin-auth.} 前缀，
     * 只包含 {@code page.*} 与 {@code js.*}（不含错误码文案，避免把错误表下发给浏览器）。
     */
    Map<String, String> uiMessages(Locale locale);
}

package com.aseantec.adminauth.starter.config;

/**
 * 与宿主 Security 的集成模式。
 * <ul>
 *   <li>{@link #ISOLATED}：组件自带 SecurityFilterChain（默认），独立生效；</li>
 *   <li>{@link #INTEGRATED}：不建链，只导出 filter 与 EntryPoint，由宿主自行挂载；</li>
 *   <li>{@link #FILTER_ONLY}：不建鉴权链，用 servlet filter 保护 protected-paths，其余 permitAll。</li>
 * </ul>
 */
public enum SecurityMode {
    ISOLATED,
    INTEGRATED,
    FILTER_ONLY
}

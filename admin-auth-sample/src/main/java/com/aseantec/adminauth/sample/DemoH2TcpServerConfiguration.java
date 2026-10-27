package com.aseantec.adminauth.sample;

import org.h2.tools.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.sql.SQLException;

/**
 * 仅 demo profile：把进程内的 H2 内存库以 TCP 暴露给本机数据库工具，便于查看表数据。
 *
 * <p>连接串：{@code jdbc:h2:tcp://localhost:9092/mem:adminauth}，用户 {@code sa}，密码留空。
 * 默认只监听本机（未开启 -tcpAllowOthers），生产环境不会启用。</p>
 */
@Configuration(proxyBeanMethods = false)
@Profile("demo")
public class DemoH2TcpServerConfiguration {

    @Bean(initMethod = "start", destroyMethod = "stop")
    public Server demoH2TcpServer() throws SQLException {
        return Server.createTcpServer("-tcpPort", "9092", "-tcpDaemon");
    }
}

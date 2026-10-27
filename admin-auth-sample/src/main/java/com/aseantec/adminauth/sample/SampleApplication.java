package com.aseantec.adminauth.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** 示例宿主：引入 starter 即可获得登录 / 改密 / 2FA / 会话保护能力。 */
@SpringBootApplication
public class SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleApplication.class, args);
    }
}

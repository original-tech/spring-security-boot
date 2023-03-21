package com.original.frame;

import com.original.cloud.configuration.EnableAlibabaCloud;
import com.original.security.configuration.EnableFrameResourceServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

@SpringBootApplication
//@EnableDiscoveryClient
//@EnableFeignClients
@EnableOAuth2Sso
//@EnableResourceServer
@EnableFrameResourceServer
@EnableAlibabaCloud
public class ConfigApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConfigApplication.class, args);
    }

}

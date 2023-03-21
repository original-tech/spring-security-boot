package com.original.frame;

import com.original.cloud.configuration.EnableAlibabaCloud;
import com.original.security.configuration.EnableFrameAuthorizationServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//@EnableDiscoveryClient
//@EnableFeignClients
@SpringBootApplication
@EnableFrameAuthorizationServer
@EnableAlibabaCloud
//@EnableCaching
public class AuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}

# SpringSecurity 原理解析【5】——Spring Security核心组件

## SecurityContextHolder

SecurityContextHolder是存放安全上下文（security context）的位置，当前用户身份，权限都在里面，默认采用本地线程（ThreadLocal）储存。

可以通过它获取当前认证信息 Authentication。

通过 Authentication 可以获取到用户信息 UserDetails。

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
Object principal = auth.getPrincipal();
if (principal instanceof UserDetails) {
    String username = ((UserDetails)principal).getUsername();
} else {
    String username = principal.toString();
}
```

## SecurityContext

安全上下文，主要持有Authentication对象，如果用户未鉴权，那Authentication对象将会是空的。该实例可以通过SecurityContextHolder.getContext静态方法获取。

## Authentication

Authentication 是认证信息的接口，可以通过它获取到用户的权限，密码，用户名，身份等等。

```java
package org.springframework.security.core;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;

public interface Authentication extends Principal, Serializable {
    
    Collection<? extends GrantedAuthority> getAuthorities();

    Object getCredentials();

    Object getDetails();

    Object getPrincipal();

    boolean isAuthenticated();

    void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

解释说明：

1）getAuthorities()，权限信息列表，未经过身份验证则为空集合。

2）getCredentials()，密码信息，在认证过后通常会被移除。

3）getDetails()，细节信息，默认实现接口为 WebAuthenticationDetails，它记录了访问者的ip地址和sessionId，项目中我们做了修改，增加了登陆方式的判断。

```java
public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {
    
    private static final long serialVersionUID = -2135894122511996600L;
    
    /**
     * 登录方式，phone：手机验证码登录，其他：用户名密码登录
     */
    private String type;
    
    /**
     * 是否为门户前端登录 0 否 1 是
     */
    private String front;
    
    /**
     * 是否移动端登录，用来控制设备信息
     */
    private String device;

    public CustomWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        type = request.getParameter("type");
        front = request.getParameter("front");
        device = request.getParameter("device");
    }

    public String gettype() {
        return type;
    }
    
    public String getFront() {
        return front;
    }

    public String getDevice() {
        return device;
    }
    
}
```

4）getPrincipal()，用户身份信息，默认返回的是UserDetails接口的实现类，可以获取用户名，密码，是否过期，是否锁定等信息。

```java
package org.springframework.security.core.userdetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

public interface UserDetails extends Serializable {
    
    String getPassword();

    String getUsername();

    boolean isAccountNonExpired();

    boolean isAccountNonLocked();

    boolean isCredentialsNonExpired();

    boolean isEnabled();
}
```

## AuthenticationManager

顾名思义 AuthenticationManager 就是用来管理 Authentication 的，它将来验证 Authentication 是否正确。

那么它是如何验证的呢，首先 AuthenticationManager 是一个接口，而 ProviderManager 是它的实现类，在 ProviderManager 中维护了一个 List 的集合，这个集合中保存的就是真正的验证器，存放了多种验证方式，实际上是设计模式中的委托模式的应用。

> 项目中目前用到了jwt，用户名密码，手机短信，移动设备识别码这四种验证方式，在 spring security 的配置类中重写 authenticationManager 配置将 AuthenticationProvider 注册进去。

```java
@Override
protected AuthenticationManager authenticationManager() throws Exception {
    //这里会轮询符合条件的AuthenticationProvider，如果成功就终止，不成功就下一个
    ProviderManager authenticationManager = new ProviderManager(
        Arrays.asList(jwtAuthenticationProvider(), daoAuthenticationProvider(), 
        phoneAuthenticationProvider(), mobileDeviceAuthenticationProvider()));
    return authenticationManager;
}
```

## AuthenticationProvider

AuthenticationProvider 最常用的一个实现便是 DaoAuthenticationProvider ，也是 spring security 默认提供的，DaoAuthenticationProvider 会通过 retrieveUser 取回 UserDetails 然后与 UsernamePasswordAuthenticationToken 做对比，交给additionalAuthenticationChecks方法完成的。

```java
/**
  * 用户名密码的数据库验证器
  *
  * @return
  */
@Bean
DaoAuthenticationProvider daoAuthenticationProvider() {
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setPasswordEncoder(new PasswordEncoder() {
        @Override
        public String encode(CharSequence rawPassword) {
            return MD5Util.encode((String) rawPassword);
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return encodedPassword.equals(MD5Util.encode((String) rawPassword));
        }
    });
    daoAuthenticationProvider.setUserDetailsService(customUserService());
    return daoAuthenticationProvider;
}
```

## UserDetailsService

UserDetailsService 负责从数据库中加载用户信息，UserDetailsService 常见的实现类有JdbcDaoImpl，InMemoryUserDetailsManager，前者从数据库加载用户，后者从内存中加载用户。

在项目中我们自己实现 UserDetailsService，重写了 loadUserByUsername 方法，根据登录名读取整个用户信息，还设置了用户对应的权限项。

```java
package org.springframework.security.core.userdetails;

public interface UserDetailsService {
    
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

## PasswordEncoder

密码加密器。通常是自定义指定。

BCryptPasswordEncoder：哈希算法加密

NoOpPasswordEncoder：不使用加密

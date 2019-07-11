package com.wmc.springboot.config;

import com.sun.org.apache.xpath.internal.operations.And;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author: WangMC
 * @date: 2019/7/11 11:57
 * @description:
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 定制请求的授权规则
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3")
                .and()
                // 开启自动配置的登录功能 效果：如果没有登录，没有权限就会来到登录页面
                .formLogin().loginPage("/userlogin").usernameParameter("user").passwordParameter("pwd");
                //1、/login来到登录页
                //2、重定向到/login?error表示登录失败
                //3、更多详细规定
                //4、默认post形式的 /Login代表处理登录
                //5、一旦定制了LoginPage，那么LoginPage的post请求就是登录了。

        http.logout().logoutSuccessUrl("/");  // 注销成功后返回首页
        //1、访问/Logout 表示用户注销，清空了session
        //2、注销成功会返回，/Login?Logout 页面

        //开启记住我功能
        http.rememberMe().rememberMeParameter("remember");
        // 登录成功后，将cookie发给浏览器保存，以后登录带上cookie，只要通过检查就可以免登录
    }

    /**
     * 定义认证规则
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("zhangsan").password("123456").roles("VIP1", "VIP2")
                .and()
                .withUser("lisi").password("123456").roles("VIP2", "VIP3")
                .and()
                .withUser("wangwu").password("123456").roles("VIP1", "VIP3");

    }
}

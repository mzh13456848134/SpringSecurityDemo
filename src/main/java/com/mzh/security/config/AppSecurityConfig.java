package com.mzh.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import com.mzh.security.service.impl.AppPasswordEncoder;


@EnableWebSecurity //开启SpringSecurity功能
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Configuration		//标记该类是配置类
public class AppSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	DataSource dataSource;
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/index.jsp","/layui/**","/").permitAll() //设置匹配的资源放行
		//.antMatchers("/level1/**").hasAnyRole("MANAGER") //拥有该角色的用户才能访问
		//.antMatchers("/level2/**").hasAuthority("USER:ADD") //拥有该权限的用户才能访问
		.anyRequest().authenticated(); //剩下任何资源必须认证
		
		http.formLogin() //未授权的访问路径，跳转默认登录页面
			.loginPage("/index.jsp") //跳转到指定的页面
			.loginProcessingUrl("/doLogin") //处理登录请求的映射路径，此路径需要与表单提交的路径一致
			.defaultSuccessUrl("/main.html"); //默认登录成功后的页面
		
		
		http.csrf().disable();//禁用csrf功能
		
		
		http.logout() //默认的注销方式
			.logoutUrl("/user-logout") //自定义请求注销路径，请求路径需要与注销路径一致
			.logoutSuccessUrl("/index.jsp");
		
		
		//异常处理器，禁止访问用户会跳到该页面
		http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
			
			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException) throws IOException, ServletException {
				request.setAttribute("error", accessDeniedException.getMessage()); //获取异常信息
				request.setAttribute("resource", request.getServletPath()); //获取请求路径
				request.getRequestDispatcher("/WEB-INF/error/error.jsp").forward(request, response); //跳转到错误显示的页面
			}
		});
		
		//记住我功能表单版本
		//http.rememberMe();
		
		//记住我数据库版本
		JdbcTokenRepositoryImpl ptr = new JdbcTokenRepositoryImpl();
		ptr.setDataSource(dataSource);
		http.rememberMe().tokenRepository(ptr);
		
	}
	
	@Autowired
	UserDetailsService userDetailsService;
	
	/*@Autowired
	AppPasswordEncoder passwordEncoder;*/
	
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//内存层面的低级别
		/*auth.inMemoryAuthentication() //内存层面的验证
			.withUser("zhangsan").password("123456") //一个用户对应一个密码
			.roles("MANAGER","ADMIN") //给用户添加角色
			.and() 
			.withUser("lisi").password("123456")
			.authorities("USER:ADD","USER:DELETE");*/ //给用户添加权限
		
		//数据库层面的企业版
		//推荐使用密码加密器用这个BCryptPasswordEncoder 将同一个字符串加密成一个永不重复的密文
		//加盐+加随机数
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder()); //测试:分析源码(验证密码不一致)
		
	}
	
	
	
}

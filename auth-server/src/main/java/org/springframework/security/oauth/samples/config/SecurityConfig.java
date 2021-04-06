/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * http
 * .authorizeRequests()            1
 * .antMatchers( "/resources/**", "/signup" , "/about").permitAll()  2
 * .antMatchers( "/admin/**").hasRole("ADMIN" )                    3
 * .antMatchers( "/db/**").access("hasRole('ADMIN') and hasRole('DBA')")  4
 * .anyRequest().authenticated()        5
 * 1、http.authorizeRequests()方法有很多子方法，每个子匹配器将会按照声明的顺序起作用。
 * 2、指定用户可以访问的多个url模式。特别的，任何用户可以访问以"/resources"开头的url资源，或者等于"/signup"或about
 * 3、任何以"/admin"开头的请求限制用户具有 "ROLE_ADMIN"角色。你可能已经注意的，尽管我们调用的hasRole方法，但是不用传入"ROLE_"前缀
 * 4、任何以"/db"开头的请求同时要求用户具有"ROLE_ADMIN"和"ROLE_DBA"角色。
 * 5、任何没有匹配上的其他的url请求，只需要用户被验证。
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/oauth2/keys").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin();
	}
	// @formatter:on

	@Bean
	public UserDetailsService users() throws Exception {
		User.UserBuilder users = User.withDefaultPasswordEncoder();
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(users.username("user1").password("password").roles("USER").build());
		manager.createUser(users.username("admin").password("password").roles("USER", "ADMIN").build());
		return manager;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
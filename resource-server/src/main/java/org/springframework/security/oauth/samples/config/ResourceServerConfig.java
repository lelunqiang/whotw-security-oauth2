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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

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
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	private static final String RESOURCE_ID = "messages-resource";

	@Autowired
	private TokenStore tokenStore;

	@Override
	public void configure(ResourceServerSecurityConfigurer security) throws Exception {
		security
			.resourceId(RESOURCE_ID)
			.tokenStore(this.tokenStore);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/messages/**")
			.authorizeRequests()
				//有读的权限才可访问/messages/**
				.antMatchers("/messages/**").access("#oauth2.hasScope('message.read')");
	}
}
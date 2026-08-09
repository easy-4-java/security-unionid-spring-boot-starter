package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.unionid.authentication.UnionIDAuthenticationProvider;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationSuccessHandler;

/**
 * Auto-configuration for UnionID-based security authentication.
 * <p>Registers UnionID authentication provider, entry point, success and failure handlers.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityUnionIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityUnionIDProperties.class })
public class SecurityUnionIDAutoConfiguration {

	/**
	 * Creates the UnionID authentication entry point.
	 * @return the entry point
	 */
	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationEntryPoint unionidMatchedAuthenticationEntryPoint() {
		return new UnionIDMatchedAuthenticationEntryPoint();
	}

	/**
	 * Creates the UnionID authentication failure handler.
	 * @return the failure handler
	 */
	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationFailureHandler unionidMatchedAuthenticationFailureHandler() {
		return new UnionIDMatchedAuthenticationFailureHandler();
	}
	
	/**
	 * Creates the UnionID authentication success handler.
	 * @param payloadRepository the JWT payload repository
	 * @return the success handler
	 */
	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationSuccessHandler unionidMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new UnionIDMatchedAuthenticationSuccessHandler(payloadRepository);
	}
	
	/**
	 * Creates the UnionID authentication provider.
	 * @param userDetailsService the user details service
	 * @return the authentication provider
	 */
	@Bean
	@ConditionalOnMissingBean
	public UnionIDAuthenticationProvider unionidAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new UnionIDAuthenticationProvider(userDetailsService);
	}

}

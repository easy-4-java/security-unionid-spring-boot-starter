package org.springframework.security.boot.unionid.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

/**
 * <p>Provider for Union I D Authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class UnionIDAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    /**
     * Constructs a new union i d authentication provider instance.
     *
     * @param userDetailsService the user details service
     */
    public UnionIDAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Determines whether supports.
     *
     * @param authentication the authentication
     * @return the result
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (UnionIDAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author <a href="https://github.com/loong10k">Loong Wan</a>
     * @param authentication  {@link UnionIDAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
        
    	UnionIDLoginRequest loginRequest = (UnionIDLoginRequest) authentication.getPrincipal();
        
    	UnionIDAuthenticationToken authcToken = (UnionIDAuthenticationToken) authentication;
    	authcToken.setPlatform(loginRequest.getPlatform());
    	authcToken.setUnionid(loginRequest.getUnionid());
		authcToken.setToken(loginRequest.getToken());
		
		
        // load user details by face info
		UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        UnionIDAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new UnionIDAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new UnionIDAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }


	/**
	 * Sets the user details checker.
	 *
	 * @param userDetailsChecker the user details checker
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Returns the user details checker.
	 *
	 * @return the user details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}
	
	/**
	 * Returns the user details service.
	 *
	 * @return the user details service
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}

package org.springframework.security.boot.unionid.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;

import com.alibaba.fastjson.JSONObject;

/**
 * UnionID 认证 (authentication)成功回调器：讲认证信息写回前端
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class UnionIDMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {
   
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private JwtPayloadRepository payloadRepository;
	private boolean checkExpiry = false;
	
	/**
	 * Constructs a new union i d matched authentication success handler instance.
	 *
	 * @param payloadRepository the payload repository
	 */
	public UnionIDMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}
	
	/**
	 * Determines whether supports.
	 *
	 * @param authentication the authentication
	 * @return the result
	 */
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), UnionIDAuthenticationToken.class);
	}

    /**
     * on Authentication Success.
     *
     * @param request the request
     * @param response the response
     * @param authentication the authentication
     * @throws IOException if an error occurs
     * @throws ServletException if an error occurs
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
    	
    	// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey());
		// 用户信息
		SecurityPrincipal principal = (SecurityPrincipal) authentication.getPrincipal();
		UserProfilePayload profilePayload = null;
		if(principal.isBound()){
			profilePayload = getPayloadRepository().getProfilePayload((AbstractAuthenticationToken) authentication, isCheckExpiry());
		} else {
			profilePayload = principal.toPayload();
		}
		JSONObject.writeJSONString(response.getWriter(), AuthResponse.success(message, profilePayload));
    }
    
	/**
	 * Returns the payload repository.
	 *
	 * @return the payload repository
	 */
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	/**
	 * Sets the payload repository.
	 *
	 * @param payloadRepository the payload repository
	 */
	public void setPayloadRepository(JwtPayloadRepository payloadRepository) {
		this.payloadRepository = payloadRepository;
	}

	/**
	 * Returns the check expiry.
	 *
	 * @return the check expiry
	 */
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	/**
	 * Sets the check expiry.
	 *
	 * @param checkExpiry the check expiry
	 */
	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

}

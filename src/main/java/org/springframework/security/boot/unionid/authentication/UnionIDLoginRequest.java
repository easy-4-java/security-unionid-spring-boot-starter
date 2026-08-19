package org.springframework.security.boot.unionid.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * UnionID登录认证绑定的参数对象Model
 * 
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class UnionIDLoginRequest {

	/**
	 * 第三方平台类型
	 */
	private String platform;
	/**
	 * 第三方平台 UnionID
	 */
	private String unionid;
	/**
	 * 第三方平台 Token（部分平台需要进行安全验证）
	 */
	private String token;

	/**
	 * Constructs a new union i d login request instance.
	 *
	 */
	@JsonCreator
	public UnionIDLoginRequest(@JsonProperty("platform") String platform, @JsonProperty("unionid") String unionid,
			@JsonProperty("token") String token) {
		this.platform = platform;
		this.unionid = unionid;
		this.token = token;
	}

	/**
	 * Returns the platform.
	 *
	 * @return the platform
	 */
	public String getPlatform() {
		return platform;
	}

	/**
	 * Sets the platform.
	 *
	 * @param platform the platform
	 */
	public void setPlatform(String platform) {
		this.platform = platform;
	}

	/**
	 * Returns the unionid.
	 *
	 * @return the unionid
	 */
	public String getUnionid() {
		return unionid;
	}

	/**
	 * Sets the unionid.
	 *
	 * @param unionid the unionid
	 */
	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	/**
	 * Returns the token.
	 *
	 * @return the token
	 */
	public String getToken() {
		return token;
	}

	/**
	 * Sets the token.
	 *
	 * @param token the token
	 */
	public void setToken(String token) {
		this.token = token;
	}

}

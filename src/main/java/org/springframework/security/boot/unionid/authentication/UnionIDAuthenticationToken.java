/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.unionid.authentication;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * <p>Token for Union I D Authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class UnionIDAuthenticationToken extends AbstractAuthenticationToken {
    
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;
    private Object credentials;
    
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
	 * 登录的客户端应用ID
	 */
	private String appId;
	/**
	 * 登录的客户端应用渠道编码
	 */
	private String appChannel;
	/**
	 *登录的客户端版本
	 */
	private String appVersion;

    /**
     * Constructs a new union i d authentication token instance.
     *
     * @param principal the principal
     */
    public UnionIDAuthenticationToken(Object principal) {
        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        setAuthenticated(false);
    }
    
    /**
     * Constructs a new union i d authentication token instance.
     *
     * @param principal the principal
     * @param credentials the credentials
     * @param authorities the authorities
     */
    public UnionIDAuthenticationToken( Object principal,  Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * Returns the credentials.
     *
     * @return the credentials
     */
    public Object getCredentials() {
        return this.credentials;
    }

    /**
     * Returns the principal.
     *
     * @return the principal
     */
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * Sets the authenticated.
     *
     * @param isAuthenticated the is authenticated
     * @throws IllegalArgumentException if an error occurs
     */
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    /**
     * erase Credentials.
     *
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
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

	/**
	 * Returns the app id.
	 *
	 * @return the app id
	 */
	public String getAppId() {
		return appId;
	}

	/**
	 * Sets the app id.
	 *
	 * @param appId the app id
	 */
	public void setAppId(String appId) {
		this.appId = appId;
	}

	/**
	 * Returns the app channel.
	 *
	 * @return the app channel
	 */
	public String getAppChannel() {
		return appChannel;
	}

	/**
	 * Sets the app channel.
	 *
	 * @param appChannel the app channel
	 */
	public void setAppChannel(String appChannel) {
		this.appChannel = appChannel;
	}

	/**
	 * Returns the app version.
	 *
	 * @return the app version
	 */
	public String getAppVersion() {
		return appVersion;
	}

	/**
	 * Sets the app version.
	 *
	 * @param appVersion the app version
	 */
	public void setAppVersion(String appVersion) {
		this.appVersion = appVersion;
	}

}

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link UnionIDAuthenticationProvider }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("UnionIDAuthenticationProvider Tests")
class UnionIDAuthenticationProviderTest {

    private UserDetailsServiceAdapter userDetailsService;
    private UnionIDAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        provider = new UnionIDAuthenticationProvider(userDetailsService);
    }

    @Test
    @DisplayName("Instance can be created and exposes collaborators")
    void testInstantiation() {
        assertThat(provider).isNotNull();
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports() returns true only for UnionIDAuthenticationToken")
    void testSupports() {
        assertThat(provider.supports(UnionIDAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("setUserDetailsChecker updates state")
    void testSetUserDetailsChecker() {
        UserDetailsChecker checker = mock(UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }

    @Test
    @DisplayName("authenticate() throws when authentication is null")
    void testAuthenticateNull() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("authenticate() returns authenticated token with SecurityPrincipal principal")
    void testAuthenticateWithSecurityPrincipal() {
        UnionIDLoginRequest loginRequest = new UnionIDLoginRequest("wechat", "uid-1", "token-1");
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken(loginRequest);
        token.setDetails("details");

        SecurityPrincipal principal = new SecurityPrincipal("admin", "pwd", "ROLE_USER");
        when(userDetailsService.loadUserDetails(token)).thenReturn(principal);

        Authentication result = provider.authenticate(token);

        assertThat(result).isInstanceOf(UnionIDAuthenticationToken.class);
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isSameAs(principal);
        assertThat(result.getCredentials()).isEqualTo("pwd");
        // platform/unionid/token should have been copied onto the input token
        assertThat(token.getPlatform()).isEqualTo("wechat");
        assertThat(token.getUnionid()).isEqualTo("uid-1");
        assertThat(token.getToken()).isEqualTo("token-1");
        assertThat(result.getDetails()).isEqualTo("details");

        verify(userDetailsService).loadUserDetails(token);
    }

    @Test
    @DisplayName("authenticate() returns authenticated token with plain UserDetails principal")
    void testAuthenticateWithPlainUserDetails() {
        UnionIDLoginRequest loginRequest = new UnionIDLoginRequest("wechat", "uid-1", "token-1");
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken(loginRequest);

        org.springframework.security.core.userdetails.User plainUser =
                new org.springframework.security.core.userdetails.User("user", "pwd", java.util.Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(plainUser);

        Authentication result = provider.authenticate(token);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isEqualTo("user");
        assertThat(result.getCredentials()).isEqualTo("pwd");
    }
}

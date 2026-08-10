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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {{ @link UnionIDAuthenticationToken }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("UnionIDAuthenticationToken Tests")
class UnionIDAuthenticationTokenTest {

    @Test
    @DisplayName("Single-arg constructor stores principal and is unauthenticated")
    void testSingleArgConstructor() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal");
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isNull();
        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Three-arg constructor with authorities is authenticated")
    void testThreeArgConstructorAuthenticated() {
        Collection<? extends GrantedAuthority> authorities =
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal", "credentials", authorities);
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isEqualTo("credentials");
        assertThat(token.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) keeps token unauthenticated")
    void testSetAuthenticatedFalse() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials() clears credentials")
    void testEraseCredentials() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal", "credentials",
                java.util.Collections.emptyList());
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    @DisplayName("getName() returns principal string when principal is not UserDetails")
    void testGetName() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal");
        assertThat(token.getName()).isEqualTo("principal");
    }

    @Test
    @DisplayName("All property setters and getters round-trip")
    void testPropertyAccessors() {
        UnionIDAuthenticationToken token = new UnionIDAuthenticationToken("principal");
        token.setPlatform("wechat");
        token.setUnionid("uid-1");
        token.setToken("token-1");
        token.setAppId("app-1");
        token.setAppChannel("channel-1");
        token.setAppVersion("v1.0");
        assertThat(token.getPlatform()).isEqualTo("wechat");
        assertThat(token.getUnionid()).isEqualTo("uid-1");
        assertThat(token.getToken()).isEqualTo("token-1");
        assertThat(token.getAppId()).isEqualTo("app-1");
        assertThat(token.getAppChannel()).isEqualTo("channel-1");
        assertThat(token.getAppVersion()).isEqualTo("v1.0");
    }
}

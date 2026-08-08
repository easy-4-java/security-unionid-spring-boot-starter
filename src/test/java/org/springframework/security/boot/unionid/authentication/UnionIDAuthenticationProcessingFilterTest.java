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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link UnionIDAuthenticationProcessingFilter }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("UnionIDAuthenticationProcessingFilter Tests")
class UnionIDAuthenticationProcessingFilterTest {

    private UnionIDAuthenticationProcessingFilter filter;
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        filter = new UnionIDAuthenticationProcessingFilter(new ObjectMapper());
        authenticationManager = mock(AuthenticationManager.class);
        filter.setAuthenticationManager(authenticationManager);
    }

    @Test
    @DisplayName("Instance can be created via constructor with default constants")
    void testInstantiation() {
        assertThat(filter).isNotNull();
        assertThat(filter.getPlatformParameter()).isEqualTo(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PLATFORM_KEY);
        assertThat(filter.getUnionidParameter()).isEqualTo(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_UNIONID_KEY);
        assertThat(filter.getTokenParameter()).isEqualTo(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY);
    }

    @Test
    @DisplayName("Parameter setters and getters round-trip")
    void testSettersGetters() {
        filter.setPlatformParameter("p");
        filter.setUnionidParameter("u");
        filter.setTokenParameter("t");
        assertThat(filter.getPlatformParameter()).isEqualTo("p");
        assertThat(filter.getUnionidParameter()).isEqualTo("u");
        assertThat(filter.getTokenParameter()).isEqualTo("t");
    }

    @Test
    @DisplayName("doAttemptAuthentication() builds token from form parameters and delegates to manager")
    void testDoAttemptAuthenticationForm() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PLATFORM_KEY, "wechat");
        request.addParameter(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_UNIONID_KEY, "uid-1");
        request.addParameter(UnionIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY, "token-1");
        request.addHeader("X-App-Id", "app-1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authResult = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UnionIDAuthenticationToken.class))).thenReturn(authResult);

        Authentication result = filter.doAttemptAuthentication(request, response);

        assertThat(result).isSameAs(authResult);
        verify(authenticationManager).authenticate(any());
    }

    @Test
    @DisplayName("doAttemptAuthentication() parses JSON body when content type is application/json")
    void testDoAttemptAuthenticationJson() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent("{\"platform\":\"alipay\",\"unionid\":\"uid-2\",\"token\":\"token-2\"}".getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authResult = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UnionIDAuthenticationToken.class))).thenReturn(authResult);

        Authentication result = filter.doAttemptAuthentication(request, response);

        assertThat(result).isSameAs(authResult);
        verify(authenticationManager).authenticate(any());
    }
}

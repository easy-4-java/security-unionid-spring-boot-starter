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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.core.Authentication;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link UnionIDMatchedAuthenticationSuccessHandler }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("UnionIDMatchedAuthenticationSuccessHandler Tests")
class UnionIDMatchedAuthenticationSuccessHandlerTest {

    private JwtPayloadRepository payloadRepository;
    private UnionIDMatchedAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        payloadRepository = mock(JwtPayloadRepository.class);
        handler = new UnionIDMatchedAuthenticationSuccessHandler(payloadRepository);
    }

    @Test
    @DisplayName("Instance can be created and exposes collaborators")
    void testInstantiation() {
        assertThat(handler).isNotNull();
        assertThat(handler.getPayloadRepository()).isSameAs(payloadRepository);
        assertThat(handler.isCheckExpiry()).isFalse();
    }

    @Test
    @DisplayName("supports() returns true only for UnionIDAuthenticationToken")
    void testSupports() {
        assertThat(handler.supports(new UnionIDAuthenticationToken("p"))).isTrue();
        assertThat(handler.supports(mock(Authentication.class))).isFalse();
    }

    @Test
    @DisplayName("setCheckExpiry / setPayloadRepository update state")
    void testSetters() {
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();

        JwtPayloadRepository another = mock(JwtPayloadRepository.class);
        handler.setPayloadRepository(another);
        assertThat(handler.getPayloadRepository()).isSameAs(another);
    }

    @Test
    @DisplayName("onAuthenticationSuccess() uses payloadRepository when principal is bound")
    void testOnAuthenticationSuccessBound() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = newResponseWithWriter();

        SecurityPrincipal principal = new SecurityPrincipal("admin", "pwd", "ROLE_USER");
        principal.setBound(true);
        UnionIDAuthenticationToken authentication = new UnionIDAuthenticationToken(principal, "pwd",
                java.util.Collections.emptySet());

        UserProfilePayload profilePayload = new UserProfilePayload();
        when(payloadRepository.getProfilePayload(authentication, false)).thenReturn(profilePayload);

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(response).setStatus(200);
        verify(response).setContentType("application/json");
        verify(payloadRepository).getProfilePayload(authentication, false);
    }

    @Test
    @DisplayName("onAuthenticationSuccess() uses principal.toPayload() when principal is not bound")
    void testOnAuthenticationSuccessUnbound() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = newResponseWithWriter();

        SecurityPrincipal principal = new SecurityPrincipal("admin", "pwd", "ROLE_USER");
        principal.setBound(false);
        UnionIDAuthenticationToken authentication = new UnionIDAuthenticationToken(principal, "pwd",
                java.util.Collections.emptySet());

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(response).setStatus(200);
        // payloadRepository must NOT be consulted when principal is not bound
        org.mockito.Mockito.verifyNoInteractions(payloadRepository);
    }

    private HttpServletResponse newResponseWithWriter() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));
        return response;
    }
}

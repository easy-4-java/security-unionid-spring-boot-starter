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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link UnionIDLoginRequest }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("UnionIDLoginRequest Tests")
class UnionIDLoginRequestTest {

    @Test
    @DisplayName("Constructor populates all three fields")
    void testConstructor() {
        UnionIDLoginRequest request = new UnionIDLoginRequest("wechat", "uid-1", "token-1");
        assertThat(request.getPlatform()).isEqualTo("wechat");
        assertThat(request.getUnionid()).isEqualTo("uid-1");
        assertThat(request.getToken()).isEqualTo("token-1");
    }

    @Test
    @DisplayName("Constructor accepts null values")
    void testConstructorNulls() {
        UnionIDLoginRequest request = new UnionIDLoginRequest(null, null, null);
        assertThat(request.getPlatform()).isNull();
        assertThat(request.getUnionid()).isNull();
        assertThat(request.getToken()).isNull();
    }

    @Test
    @DisplayName("Setters update fields")
    void testSetters() {
        UnionIDLoginRequest request = new UnionIDLoginRequest("a", "b", "c");
        request.setPlatform("alipay");
        request.setUnionid("uid-2");
        request.setToken("token-2");
        assertThat(request.getPlatform()).isEqualTo("alipay");
        assertThat(request.getUnionid()).isEqualTo("uid-2");
        assertThat(request.getToken()).isEqualTo("token-2");
    }
}

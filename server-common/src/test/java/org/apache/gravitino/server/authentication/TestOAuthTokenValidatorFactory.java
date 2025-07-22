/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.gravitino.server.authentication;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.gravitino.Config;
import org.junit.jupiter.api.Test;

public class TestOAuthTokenValidatorFactory {

  @Test
  public void testCreateDefaultValidator() {
    Config config = new Config(false) {};
    config.set(OAuthConfig.SERVICE_AUDIENCE, "test-audience");
    config.set(OAuthConfig.DEFAULT_SIGN_KEY, "dGVzdC1rZXk="); // base64 encoded "test-key"
    config.set(OAuthConfig.SIGNATURE_ALGORITHM_TYPE, "HS256");
    config.set(OAuthConfig.DEFAULT_TOKEN_PATH, "/token");
    config.set(OAuthConfig.DEFAULT_SERVER_URI, "http://localhost:8080");

    OAuthTokenValidator validator = OAuthTokenValidatorFactory.createValidator(null, config);
    assertNotNull(validator);
    assertTrue(validator instanceof DefaultJwtTokenValidator);
  }

  @Test
  public void testCreateValidatorForUnsupportedProvider() {
    Config config = new Config(false) {};
    config.set(OAuthConfig.SERVICE_AUDIENCE, "test-audience");
    config.set(OAuthConfig.DEFAULT_SIGN_KEY, "dGVzdC1rZXk=");
    config.set(OAuthConfig.SIGNATURE_ALGORITHM_TYPE, "HS256");
    config.set(OAuthConfig.DEFAULT_TOKEN_PATH, "/token");
    config.set(OAuthConfig.DEFAULT_SERVER_URI, "http://localhost:8080");

    assertThrows(
        IllegalArgumentException.class,
        () -> OAuthTokenValidatorFactory.createValidator("unsupported", config));
  }
}

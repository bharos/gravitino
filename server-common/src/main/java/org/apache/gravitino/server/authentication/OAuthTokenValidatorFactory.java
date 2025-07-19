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

import java.util.HashMap;
import java.util.Map;
import org.apache.gravitino.Config;
import org.apache.gravitino.auth.OAuthTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Factory for creating OAuth token validators based on provider type. */
public class OAuthTokenValidatorFactory {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthTokenValidatorFactory.class);

  /**
   * Create and initialize a token validator for the specified provider.
   *
   * @param provider The OAuth provider name (e.g., "azure")
   * @param config The configuration object
   * @return An initialized OAuthTokenValidator
   * @throws IllegalArgumentException if no suitable validator is found
   */
  public static OAuthTokenValidator createValidator(String provider, Config config) {
    LOG.info("Creating OAuth token validator for provider: {}", provider);

    // Convert Config to Map for the interface
    Map<String, String> configMap = new HashMap<>();
    configMap.put("service.audience", config.get(OAuthConfig.SERVICE_AUDIENCE));
    configMap.put("default.sign.key", config.get(OAuthConfig.DEFAULT_SIGN_KEY));
    configMap.put("signature.algorithm.type", config.get(OAuthConfig.SIGNATURE_ALGORITHM_TYPE));
    configMap.put("allow.skew.seconds", String.valueOf(config.get(OAuthConfig.ALLOW_SKEW_SECONDS)));
    configMap.put("azure.jwks.uri", config.get(OAuthConfig.AZURE_JWKS_URI));

    OAuthTokenValidator validator;

    if ("azure".equalsIgnoreCase(provider)) {
      validator = createAzureValidator();
    } else {
      // Default validator for all other providers
      validator = new DefaultJwtTokenValidator();
      LOG.info("Using default JWT token validator");
    }

    validator.initialize(configMap);
    return validator;
  }

  /**
   * Create Azure validator using reflection to avoid hard dependency. Falls back to default
   * validator if Azure classes are not available.
   */
  private static OAuthTokenValidator createAzureValidator() {
    try {
      Class<?> azureValidatorClass =
          Class.forName("org.apache.gravitino.bundles.azure.oauth.AzureTokenValidator");
      OAuthTokenValidator validator =
          (OAuthTokenValidator) azureValidatorClass.getDeclaredConstructor().newInstance();
      LOG.info("Using Azure token validator");
      return validator;
    } catch (Exception e) {
      LOG.warn("Azure token validator not available, falling back to default: {}", e.getMessage());
      return new DefaultJwtTokenValidator();
    }
  }
}

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
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.Config;
import org.apache.gravitino.auth.OAuthTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating appropriate OAuth token validators based on configuration.
 *
 * <p>Supports two validation approaches:
 *
 * <ul>
 *   <li><strong>Shared Key Validation</strong> - For providers like Keycloak that use symmetric
 *       keys
 *   <li><strong>JWKS Validation</strong> - For providers like Azure, Google, Auth0 that expose JWKS
 *       endpoints
 * </ul>
 */
public class OAuthTokenValidatorFactory {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthTokenValidatorFactory.class);

  /**
   * Create and initialize a token validator for the specified provider.
   *
   * @param provider The OAuth provider name (e.g., "default", "azure", "google")
   * @param config The configuration object
   * @return An initialized OAuthTokenValidator
   * @throws IllegalArgumentException if configuration is invalid
   */
  public static OAuthTokenValidator createValidator(String provider, Config config) {
    if (config == null) {
      throw new IllegalArgumentException("Configuration cannot be null");
    }

    LOG.info("Creating OAuth token validator for provider: {}", provider);

    // Convert Config to Map for the validator interface
    Map<String, String> configMap = new HashMap<>();

    // Always add base configs needed by existing validators
    configMap.put(
        "gravitino.authenticator.oauth.serviceAudience", config.get(OAuthConfig.SERVICE_AUDIENCE));
    configMap.put(
        "gravitino.authenticator.oauth.defaultSignKey", config.get(OAuthConfig.DEFAULT_SIGN_KEY));
    configMap.put(
        "gravitino.authenticator.oauth.signAlgorithmType",
        config.get(OAuthConfig.SIGNATURE_ALGORITHM_TYPE));
    configMap.put(
        "gravitino.authenticator.oauth.allowSkewSecs",
        String.valueOf(config.get(OAuthConfig.ALLOW_SKEW_SECONDS)));

    String jwksUri = config.get(OAuthConfig.JWKS_URI);
    String defaultSignKey = configMap.get("gravitino.authenticator.oauth.defaultSignKey");

    LOG.debug("JWKS URI configured: {}", StringUtils.isNotBlank(jwksUri));
    LOG.debug("Default sign key configured: {}", StringUtils.isNotBlank(defaultSignKey));

    // Validate that at least one authentication method is configured
    if (StringUtils.isBlank(jwksUri) && StringUtils.isBlank(defaultSignKey)) {
      throw new IllegalArgumentException(
          "Either JWKS URI or default sign key must be configured for OAuth authentication");
    }

    // Choose validator based on configuration
    OAuthTokenValidator validator;

    if (StringUtils.isNotBlank(jwksUri)) {
      // Add JWKS-specific configs only when using JWKS validator
      configMap.put("gravitino.authenticator.oauth.jwks-uri", jwksUri);
      configMap.put("gravitino.authenticator.oauth.authority", config.get(OAuthConfig.AUTHORITY));
      configMap.put("gravitino.authenticator.oauth.provider", config.get(OAuthConfig.PROVIDER));
      configMap.put("gravitino.authenticator.oauth.client-id", config.get(OAuthConfig.CLIENT_ID));
      configMap.put("gravitino.authenticator.oauth.scope", config.get(OAuthConfig.SCOPE));
      configMap.put(
          "gravitino.authenticator.oauth.principal-field", config.get(OAuthConfig.PRINCIPAL_FIELD));

      // Use JWKS-based validation for external OAuth providers
      LOG.info("Using JWKS-based token validator");
      validator = new JwksTokenValidator();
    } else {
      // Use shared key validation for default/legacy scenarios
      LOG.info("Using shared key token validator (DefaultJwtTokenValidator)");
      validator = new DefaultJwtTokenValidator();
    }

    validator.initialize(configMap);
    return validator;
  }

  /**
   * Determine if the configuration is set up for JWKS-based validation.
   *
   * @param config Configuration object
   * @return true if JWKS URI is configured, false otherwise
   */
  public static boolean isJwksBasedValidation(Config config) {
    String jwksUri = config.get(OAuthConfig.JWKS_URI);
    return StringUtils.isNotBlank(jwksUri);
  }

  /**
   * Determine if the configuration is set up for shared key validation.
   *
   * @param config Configuration object
   * @return true if default sign key is configured, false otherwise
   */
  public static boolean isSharedKeyValidation(Config config) {
    String defaultSignKey = config.get(OAuthConfig.DEFAULT_SIGN_KEY);
    return StringUtils.isNotBlank(defaultSignKey);
  }
}

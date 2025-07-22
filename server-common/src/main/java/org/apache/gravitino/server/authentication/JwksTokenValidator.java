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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.UserPrincipal;
import org.apache.gravitino.auth.OAuthTokenValidator;
import org.apache.gravitino.exceptions.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generic JWKS-based OAuth token validator that uses Nimbus JOSE + JWT library to validate JWT
 * tokens from any OAuth provider that exposes a JWKS endpoint.
 */
public class JwksTokenValidator implements OAuthTokenValidator {
  private static final Logger LOG = LoggerFactory.getLogger(JwksTokenValidator.class);

  private String jwksUri;
  private String expectedIssuer;
  private String principalField;
  private long allowSkewSeconds;

  @Override
  public void initialize(Map<String, String> config) {
    this.jwksUri = config.get("gravitino.authenticator.oauth.jwks-uri");
    this.expectedIssuer = config.get("gravitino.authenticator.oauth.authority");
    this.principalField = config.get("gravitino.authenticator.oauth.principal-field");
    this.allowSkewSeconds =
        Long.parseLong(config.get("gravitino.authenticator.oauth.allowSkewSecs"));

    LOG.info("Initializing JWKS token validator with config:");
    LOG.info("  JWKS URI: {}", jwksUri);
    LOG.info("  Expected issuer: {}", expectedIssuer);
    LOG.info("  Principal field: {}", principalField);
    LOG.info("  Clock skew tolerance: {} seconds", allowSkewSeconds);

    if (StringUtils.isBlank(jwksUri)) {
      throw new IllegalArgumentException(
          "JWKS URI must be configured when using JWKS-based OAuth providers");
    }

    // Validate JWKS URI format
    try {
      new java.net.URL(jwksUri);
      LOG.info("JWKS URI format validation successful");
    } catch (Exception e) {
      LOG.error("Invalid JWKS URI format: {}", jwksUri, e);
      throw new IllegalArgumentException("Invalid JWKS URI format: " + jwksUri, e);
    }
  }

  @Override
  public Principal validateToken(String token, String serviceAudience) {
    LOG.info("Starting JWKS token validation");
    LOG.debug(
        "Token to validate (first 50 chars): {}...",
        token.length() > 50 ? token.substring(0, 50) : token);
    LOG.info("Service audience: {}", serviceAudience);

    try {
      SignedJWT signedJWT = SignedJWT.parse(token);
      LOG.info("Successfully parsed JWT token");
      LOG.debug("Token header: {}", signedJWT.getHeader().toJSONObject());

      // Set up JWKS source and processor
      LOG.info("Setting up JWKS source from URI: {}", jwksUri);
      JWKSource<SecurityContext> jwkSource;
      try {
        jwkSource =
            com.nimbusds.jose.jwk.source.JWKSourceBuilder.create(new java.net.URL(jwksUri)).build();
        LOG.info("JWKS source created successfully");
      } catch (Exception e) {
        LOG.error("Failed to create JWKS source from URI: {}", jwksUri, e);
        throw e;
      }

      JWSAlgorithm algorithm = JWSAlgorithm.parse(signedJWT.getHeader().getAlgorithm().getName());
      LOG.info("Token uses algorithm: {}", algorithm);
      LOG.info("Token key ID (kid): {}", signedJWT.getHeader().getKeyID());

      JWSKeySelector<SecurityContext> keySelector =
          new JWSVerificationKeySelector<>(algorithm, jwkSource);

      // Test JWKS connectivity
      try {
        LOG.info("Testing JWKS connectivity...");
        com.nimbusds.jose.jwk.JWKSelector selector =
            new com.nimbusds.jose.jwk.JWKSelector(
                new com.nimbusds.jose.jwk.JWKMatcher.Builder()
                    .keyType(com.nimbusds.jose.jwk.KeyType.RSA)
                    .algorithm(algorithm)
                    .build());
        List<com.nimbusds.jose.jwk.JWK> keys = jwkSource.get(selector, null);
        LOG.info("Found {} keys from JWKS endpoint for algorithm {}", keys.size(), algorithm);
        for (com.nimbusds.jose.jwk.JWK key : keys) {
          LOG.info(
              "Available key - ID: {}, Type: {}, Use: {}, Algorithm: {}",
              key.getKeyID(),
              key.getKeyType(),
              key.getKeyUse(),
              key.getAlgorithm());
        }

        // Check if token's key ID matches any available keys
        String tokenKeyId = signedJWT.getHeader().getKeyID();
        if (tokenKeyId != null) {
          boolean keyFound = keys.stream().anyMatch(k -> tokenKeyId.equals(k.getKeyID()));
          LOG.info("Token key ID '{}' found in JWKS: {}", tokenKeyId, keyFound);
        }
      } catch (Exception e) {
        LOG.error("Failed to fetch keys from JWKS endpoint: {}", e.getMessage(), e);
      }

      DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
      jwtProcessor.setJWSKeySelector(
          keySelector); // Configure claims verification - let Nimbus handle all validations
      JWTClaimsSet.Builder expectedClaimsBuilder = new JWTClaimsSet.Builder();

      // Set expected issuer if configured
      if (StringUtils.isNotBlank(expectedIssuer)) {
        expectedClaimsBuilder.issuer(expectedIssuer);
        LOG.info("Setting expected issuer: {}", expectedIssuer);
      }

      // Set expected audience if provided
      if (StringUtils.isNotBlank(serviceAudience)) {
        expectedClaimsBuilder.audience(serviceAudience);
        LOG.info("Setting expected audience: {}", serviceAudience);
      }

      com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
          new com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier<SecurityContext>(
              expectedClaimsBuilder.build(), null); // No required claims

      // Set clock skew tolerance
      claimsVerifier.setMaxClockSkew((int) allowSkewSeconds);
      LOG.info("Set clock skew tolerance to {} seconds", allowSkewSeconds);

      jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

      // Process and validate the token (signature, time, issuer, audience all handled here)
      LOG.info("Processing JWT token with full validation (signature, time, issuer, audience)");

      JWTClaimsSet validatedClaims;
      try {
        validatedClaims = jwtProcessor.process(signedJWT, null);
        LOG.info("JWT token validation successful!");

        // Log some key claims for debugging
        LOG.info("Token claims - Subject: {}", validatedClaims.getSubject());
        LOG.info("Token claims - Issuer: {}", validatedClaims.getIssuer());
        LOG.info("Token claims - Audience: {}", validatedClaims.getAudience());
        LOG.info("Token claims - Expiration: {}", validatedClaims.getExpirationTime());
        LOG.info("Token claims - Issued at: {}", validatedClaims.getIssueTime());
        LOG.info("All token claims: {}", validatedClaims.toJSONObject());
      } catch (Exception validationException) {
        LOG.error("JWT validation failed: {}", validationException.getMessage());
        LOG.info("Attempting to parse token claims without full validation for debugging...");

        // Try to extract claims without validation to see what's in the token
        try {
          JWTClaimsSet unvalidatedClaims = signedJWT.getJWTClaimsSet();
          LOG.info("Unvalidated token claims for debugging:");
          LOG.info("  Subject: {}", unvalidatedClaims.getSubject());
          LOG.info("  Issuer: {}", unvalidatedClaims.getIssuer());
          LOG.info("  Audience: {}", unvalidatedClaims.getAudience());
          LOG.info("  All claims: {}", unvalidatedClaims.toJSONObject());
        } catch (Exception parseException) {
          LOG.error("Could not parse token claims: {}", parseException.getMessage());
        }

        throw validationException;
      }

      // Extract principal with smart fallback logic
      String principal = null;
      LOG.info("Attempting to extract principal from field: {}", principalField);

      // Try the configured principal field first
      if (StringUtils.isNotBlank(principalField)) {
        principal = (String) validatedClaims.getClaim(principalField);
        if (principal != null) {
          LOG.info(
              "Successfully extracted principal from configured field '{}': {}",
              principalField,
              principal);
        } else {
          LOG.info("Principal field '{}' not found in token, trying fallbacks", principalField);
        }
      }

      // Fallback to common user identity fields
      if (principal == null) {
        String[] fallbackFields = {"unique_name", "upn", "email", "preferred_username", "sub"};
        for (String field : fallbackFields) {
          principal = (String) validatedClaims.getClaim(field);
          if (principal != null) {
            LOG.info("Using fallback field '{}' for principal: {}", field, principal);
            break;
          }
        }
      }

      if (principal == null) {
        LOG.error(
            "No valid principal found in token - tried field '{}' and fallbacks [unique_name, upn, email, preferred_username, sub]",
            principalField);
        throw new UnauthorizedException("No valid principal found in token");
      }

      LOG.info("Successfully extracted principal: {}", principal);
      UserPrincipal userPrincipal = new UserPrincipal(principal);
      LOG.info("JWKS token validation completed successfully for user: {}", principal);

      return userPrincipal;

    } catch (Exception e) {
      LOG.error("JWKS JWT validation error: {}", e.getMessage(), e);
      throw new UnauthorizedException(e, "JWKS JWT validation error");
    }
  }
}

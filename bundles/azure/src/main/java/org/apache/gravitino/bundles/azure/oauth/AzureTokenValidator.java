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

package org.apache.gravitino.bundles.azure.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.security.Principal;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.UserPrincipal;
import org.apache.gravitino.auth.OAuthTokenValidator;
import org.apache.gravitino.exceptions.UnauthorizedException;

/**
 * Azure-specific OAuth token validator that uses Nimbus JOSE + JWT library to validate Azure AD JWT
 * tokens.
 */
public class AzureTokenValidator implements OAuthTokenValidator {
  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(AzureTokenValidator.class);

  private String azureJwksUri;

  @Override
  public void initialize(Map<String, String> config) {
    String jwksUriValue = config.get("azure.jwks.uri");
    this.azureJwksUri = StringUtils.isNotBlank(jwksUriValue) ? jwksUriValue : null;

    if (StringUtils.isBlank(azureJwksUri)) {
      throw new IllegalArgumentException(
          "Azure JWKS URI must be configured when using Azure provider");
    }
  }

  @Override
  public boolean supportsProvider(String provider) {
    return "azure".equalsIgnoreCase(provider);
  }

  @Override
  public Principal validateToken(String token, String serviceAudience) {
    try {
      // Parse the JWT to extract claims and header information
      SignedJWT signedJWT = SignedJWT.parse(token);
      JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

      // Log token details for debugging
      LOG.info("Token header: {}", signedJWT.getHeader().toJSONObject());
      LOG.info("Token algorithm: {}", signedJWT.getHeader().getAlgorithm());
      LOG.info("Token key ID (kid): {}", signedJWT.getHeader().getKeyID());
      LOG.info("Token issuer: {}", claims.getIssuer());
      LOG.info("Token audience: {}", claims.getAudience());
      LOG.info("Token subject: {}", claims.getSubject());
      LOG.info("Service audience: {}", serviceAudience);

      String iss = claims.getIssuer();

      // Extract tenant ID from issuer
      String tenantId = extractTenantId(iss);
      if (tenantId == null) {
        LOG.error("Could not extract tenant ID from iss: {}", iss);
        throw new UnauthorizedException("Could not extract tenant ID from iss");
      }

      // Build JWKS URI for this tenant based on token version
      String jwksUri;
      if (iss.contains("sts.windows.net")) {
        // v1.0 token - use v1.0 JWKS endpoint
        jwksUri = "https://login.microsoftonline.com/" + tenantId + "/discovery/keys";
        LOG.info("Detected v1.0 token, using v1.0 JWKS endpoint");
      } else if (iss.contains("login.microsoftonline.com")) {
        // v2.0 token - use v2.0 JWKS endpoint
        jwksUri = "https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys";
        LOG.info("Detected v2.0 token, using v2.0 JWKS endpoint");
      } else {
        // Fallback to configured JWKS URI
        jwksUri = azureJwksUri;
        if (jwksUri.contains("{tenant_id}")) {
          jwksUri = jwksUri.replace("{tenant_id}", tenantId);
        }
        LOG.info("Using configured JWKS endpoint");
      }

      LOG.info("Fetching JWKS from URI: {}", jwksUri);

      // Create JWK source and verify the token
      JWKSource<SecurityContext> jwkSource =
          com.nimbusds.jose.jwk.source.JWKSourceBuilder.create(new java.net.URL(jwksUri)).build();

      // Use the algorithm from the token header instead of hardcoding RS256
      JWSAlgorithm algorithm = JWSAlgorithm.parse(signedJWT.getHeader().getAlgorithm().getName());
      LOG.info("Using algorithm: {}", algorithm);

      JWSKeySelector<SecurityContext> keySelector =
          new JWSVerificationKeySelector<>(algorithm, jwkSource);

      DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
      jwtProcessor.setJWSKeySelector(keySelector);

      // For debugging, let's check what audience we expect vs what we get
      LOG.info("Expected service audience: {}", serviceAudience);

      String tokenAudience = null;
      if (claims.getAudience() != null && !claims.getAudience().isEmpty()) {
        tokenAudience = claims.getAudience().get(0);
      }

      LOG.info("Token audience from claims: {}", tokenAudience);

      // Validate audience - should match the service audience
      if (serviceAudience != null && !serviceAudience.equals(tokenAudience)) {
        // Also check if token audience matches the expected API format
        String expectedApiAudience = "api://" + serviceAudience;
        if (!expectedApiAudience.equals(tokenAudience)) {
          LOG.error(
              "Audience mismatch - Expected: {} or {}, Got: {}",
              serviceAudience,
              expectedApiAudience,
              tokenAudience);
          throw new UnauthorizedException("Token audience mismatch");
        }
      }

      LOG.info("Audience validation successful");

      // Set a minimal claims verifier that only checks issuer
      jwtProcessor.setJWTClaimsSetVerifier(
          new com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier<SecurityContext>(
              null, // Skip audience verification in Nimbus (we check manually above)
              new JWTClaimsSet.Builder().issuer(iss).build(),
              java.util.Collections.<String>emptySet(),
              java.util.Collections.<String>emptySet()));

      // Process and validate the token
      JWTClaimsSet validatedClaims = jwtProcessor.process(signedJWT, null);

      // Extract meaningful user identity based on token type
      String userIdentity = extractUserIdentity(validatedClaims);

      LOG.info("Token validation successful for user: {}", userIdentity);
      return new UserPrincipal(userIdentity);
    } catch (Exception e) {
      LOG.error("Azure JWT validation error: {}", e.getMessage(), e);
      throw new UnauthorizedException(e, "Azure JWT validation error");
    }
  }

  /**
   * Extract meaningful user identity from JWT claims. For human users: email or upn For service
   * principals: app display name or app id
   */
  private String extractUserIdentity(JWTClaimsSet claims) {
    try {
      // Check if this is a service principal (client credentials flow)
      String idType = (String) claims.getClaim("idtyp");
      if ("app".equals(idType)) {
        // Service Principal - try app display name first, fallback to app id
        String appDisplayName = (String) claims.getClaim("app_displayname");
        if (appDisplayName != null && !appDisplayName.trim().isEmpty()) {
          LOG.info("Service principal identified by app display name: {}", appDisplayName);
          return appDisplayName;
        }

        String appId = (String) claims.getClaim("appid");
        if (appId != null) {
          LOG.info("Service principal identified by app id: {}", appId);
          return "sp:" + appId; // Prefix to distinguish service principals
        }
      }

      // Human user - try different identity claims in order of preference
      String[] identityClaims = {"email", "upn", "preferred_username", "unique_name"};

      for (String claimName : identityClaims) {
        String identity = (String) claims.getClaim(claimName);
        if (identity != null && !identity.trim().isEmpty()) {
          LOG.info("Human user identified by {}: {}", claimName, identity);
          return identity;
        }
      }

      // Fallback to subject if no better identity found
      String subject = claims.getSubject();
      LOG.warn("Using subject as identity fallback: {}", subject);
      return subject;

    } catch (Exception e) {
      LOG.error("Error extracting user identity, using subject: {}", e.getMessage());
      return claims.getSubject();
    }
  }

  /**
   * Extract tenant ID from Azure issuer URL. Supports both login.microsoftonline.com and
   * sts.windows.net formats.
   */
  private String extractTenantId(String iss) {
    if (iss == null) {
      return null;
    }

    if (iss.contains("login.microsoftonline.com/")) {
      // Format: https://login.microsoftonline.com/<tenant_id>/v2.0
      String[] issParts = iss.split("/");
      for (int i = 0; i < issParts.length; i++) {
        if ("login.microsoftonline.com".equals(issParts[i]) && i + 1 < issParts.length) {
          return issParts[i + 1];
        }
      }
    } else if (iss.contains("sts.windows.net/")) {
      // Format: https://sts.windows.net/<tenant_id>/
      String[] issParts = iss.split("/");
      for (int i = 0; i < issParts.length; i++) {
        if ("sts.windows.net".equals(issParts[i]) && i + 1 < issParts.length) {
          return issParts[i + 1];
        }
      }
    }

    return null;
  }
}

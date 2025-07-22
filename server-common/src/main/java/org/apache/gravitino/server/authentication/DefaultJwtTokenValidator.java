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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.apache.gravitino.UserPrincipal;
import org.apache.gravitino.auth.OAuthTokenValidator;
import org.apache.gravitino.auth.SignatureAlgorithmFamilyType;
import org.apache.gravitino.exceptions.UnauthorizedException;

/**
 * Default JWT token validator that supports standard JWT validation using JJWT library. This
 * validator is used for non-provider-specific OAuth implementations.
 */
public class DefaultJwtTokenValidator implements OAuthTokenValidator {
  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(DefaultJwtTokenValidator.class);

  private long allowSkewSeconds;
  private Key defaultSigningKey;

  @Override
  public void initialize(Map<String, String> config) {
    this.allowSkewSeconds =
        Long.parseLong(config.getOrDefault("gravitino.authenticator.oauth.allowSkewSecs", "0"));
    String configuredSignKey = config.get("gravitino.authenticator.oauth.defaultSignKey");
    String algType = config.get("gravitino.authenticator.oauth.signAlgorithmType");

    LOG.debug("Initializing DefaultJwtTokenValidator with allowSkewSeconds: {}", allowSkewSeconds);
    LOG.debug("Configured sign key present: {}", configuredSignKey != null);
    LOG.debug("Algorithm type: {}", algType);

    if (configuredSignKey == null) {
      throw new IllegalArgumentException("Default sign key is required but not configured");
    }

    this.defaultSigningKey = decodeSignKey(Base64.getDecoder().decode(configuredSignKey), algType);
  }

  @Override
  public Principal validateToken(String token, String serviceAudience) {
    try {
      JwtParser parser =
          Jwts.parserBuilder()
              .setAllowedClockSkewSeconds(allowSkewSeconds)
              .setSigningKey(defaultSigningKey)
              .build();

      Jwt<?, Claims> jwt = parser.parseClaimsJws(token);

      // Validate audience
      Object audienceObject = jwt.getBody().get(Claims.AUDIENCE);
      if (audienceObject == null) {
        LOG.warn("Found null Audience in token");
        throw new UnauthorizedException("Found null Audience in token");
      }

      if (audienceObject instanceof String) {
        if (!serviceAudience.equals(audienceObject)) {
          LOG.warn("Audience mismatch: token [{}], expected [{}]", audienceObject, serviceAudience);
          throw new UnauthorizedException(
              "Audience in the token [%s] doesn't contain %s", audienceObject, serviceAudience);
        }
      } else if (audienceObject instanceof List<?>) {
        @SuppressWarnings("unchecked")
        List<Object> audiences = (List<Object>) audienceObject;
        if (audiences.stream()
            .noneMatch(audienceInToken -> serviceAudience.equals(audienceInToken))) {
          LOG.warn(
              "Audiences mismatch: token audiences [{}], expected [{}]",
              audiences,
              serviceAudience);
          throw new UnauthorizedException(
              "Audiences in the token %s don't contain %s", audienceObject, serviceAudience);
        }
      } else {
        LOG.warn("Audiences in token is not in expected format: {}", audienceObject);
        throw new UnauthorizedException(
            "Audiences in token is not in expected format: %s", audienceObject);
      }

      return new UserPrincipal(jwt.getBody().getSubject());
    } catch (Exception e) {
      LOG.error("JWT validation error: {}", e.getMessage(), e);
      throw new UnauthorizedException(e, "JWT validation error");
    }
  }

  private static Key decodeSignKey(byte[] key, String algType) {
    try {
      SignatureAlgorithmFamilyType algFamilyType =
          SignatureAlgorithmFamilyType.valueOf(SignatureAlgorithm.valueOf(algType).getFamilyName());

      if (SignatureAlgorithmFamilyType.HMAC == algFamilyType) {
        return Keys.hmacShaKeyFor(key);
      } else if (SignatureAlgorithmFamilyType.RSA == algFamilyType
          || SignatureAlgorithmFamilyType.ECDSA == algFamilyType) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance(algFamilyType.name());
        return kf.generatePublic(spec);
      }
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to decode key", e);
    }
    throw new IllegalArgumentException("Unsupported signature algorithm type: " + algType);
  }
}

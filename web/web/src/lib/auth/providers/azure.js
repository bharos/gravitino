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

import { PublicClientApplication } from '@azure/msal-browser'
import { MsalProvider } from '@azure/msal-react'
import { BaseOAuthProvider } from './base'

export class AzureOAuthProvider extends BaseOAuthProvider {
  constructor() {
    super()
    this.providerType = 'azure'
    this.msalInstance = null
    this.msalConfig = null
  }

  async initialize(config) {
    console.log('[AzureOAuthProvider] Initializing with config:', config)

    this.config = config
    this.msalConfig = {
      auth: {
        clientId: config['gravitino.authenticator.oauth.client-id'],
        authority: config['gravitino.authenticator.oauth.authority'],
        redirectUri: window.location.origin + '/ui/oauth/callback'
      },
      cache: {
        cacheLocation: 'localStorage',
        storeAuthStateInCookie: false
      },
      scopes: config['gravitino.authenticator.oauth.scope']
    }

    console.log('[AzureOAuthProvider] Created MSAL config:', this.msalConfig)

    this.msalInstance = new PublicClientApplication(this.msalConfig)
    await this.msalInstance.initialize()

    console.log('[AzureOAuthProvider] MSAL instance initialized successfully')
  }

  async getAccessToken() {
    if (!this.msalInstance || !this.msalConfig) {
      console.warn('[AzureOAuthProvider] Provider not initialized')

      return null
    }

    const accounts = this.msalInstance.getAllAccounts()
    if (accounts.length === 0) {
      console.warn('[AzureOAuthProvider] No accounts found. User may not be logged in.')

      return null
    }

    // Use scopes from backend configuration
    const configuredScopes = this.msalConfig.scopes || 'User.Read'
    const apiScopes = configuredScopes.split(' ').filter(scope => scope.trim())

    console.info('[AzureOAuthProvider] Requesting token with scopes:', apiScopes)

    const request = {
      scopes: apiScopes,
      account: accounts[0]
    }

    try {
      // Try silent token acquisition first
      const response = await this.msalInstance.acquireTokenSilent(request)

      return response.accessToken
    } catch (silentError) {
      // Fallback to interactive login if silent acquisition fails
      console.warn(
        '[AzureOAuthProvider] Silent token acquisition failed, acquiring token interactively...',
        silentError
      )
      try {
        const response = await this.msalInstance.acquireTokenPopup(request)

        return response.accessToken
      } catch (interactiveError) {
        console.error('[AzureOAuthProvider] Interactive token acquisition failed', interactiveError)

        return null
      }
    }
  }

  requiresWrapper() {
    return true
  }

  getWrapperComponent() {
    if (!this.msalInstance) {
      console.error('[AzureOAuthProvider] MSAL instance not initialized')

      return null
    }

    // Return a wrapper component that provides MSAL context
    return ({ children }) => <MsalProvider instance={this.msalInstance}>{children}</MsalProvider>
  }

  getMsalInstance() {
    return this.msalInstance
  }

  getMsalConfig() {
    return this.msalConfig
  }
}

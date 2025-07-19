'use client'

import { PublicClientApplication } from '@azure/msal-browser'

let msalConfig = null
let configPromise = null
let msalInstance = null

export async function initMsal() {
  if (msalInstance) {
    console.log('[MSAL] Reusing existing instance')

    return msalInstance
  }

  if (configPromise) {
    console.log('[MSAL] Config fetch in progress...')
    await configPromise

    return msalInstance
  }

  configPromise = (async () => {
    try {
      console.log('[MSAL] Fetching /configs...')
      const response = await fetch('/configs')
      if (!response.ok) throw new Error(`Failed to fetch configs: ${response.status}`)

      const configs = await response.json()
      console.log('[MSAL] Received config:', configs)

      if (configs['gravitino.authenticator.oauth.provider'] !== 'azure') {
        console.warn('[MSAL] Provider is not azure. Skipping MSAL initialization.')
        msalConfig = null
        msalInstance = null

        return null
      }

      msalConfig = {
        auth: {
          clientId: configs['gravitino.authenticator.oauth.azure.client-id'],
          authority: configs['gravitino.authenticator.oauth.azure.authority'],
          redirectUri: configs['gravitino.authenticator.oauth.azure.redirect-uri']
        },
        cache: {
          cacheLocation: 'localStorage',
          storeAuthStateInCookie: false
        }
      }

      msalInstance = new PublicClientApplication(msalConfig)
      await msalInstance.initialize()

      localStorage.setItem('oauthProvider', configs['gravitino.authenticator.oauth.provider'])

      return msalInstance
    } catch (err) {
      configPromise = null // allow retry
      throw err
    }
  })()

  await configPromise

  return msalInstance
}

export function getMsalInstance() {
  if (!msalInstance) {
    console.error('[MSAL] Instance not initialized. Call initMsal() first.')

    return null
  }

  return msalInstance
}

export function getMsalConfig() {
  if (!msalConfig) {
    console.warn('[MSAL] Config not yet loaded. Call initMsal() first.')
  }

  return msalConfig
}

export async function getGravitinoAccessToken() {
  const config = getMsalConfig()
  if (!config) {
    console.error('[MSAL] Config not available.')

    return null
  }

  // Use the API scope created by networking admin
  const apiScopes = [`api://${config.auth.clientId}/access_as_user`]
  console.info('[MSAL] Requesting token for Gravitino API with scope:', apiScopes[0])

  return await getAccessToken(apiScopes)
}

export async function getAccessToken(scopes = ['User.Read']) {
  const instance = getMsalInstance()
  if (!instance) {
    console.error('[MSAL] Instance not available.')

    return null
  }

  const accounts = instance.getAllAccounts()

  if (accounts.length === 0) {
    console.warn('[MSAL] No accounts found. User may not be logged in.')

    return null
  }

  const request = {
    scopes: scopes,
    account: accounts[0]
  }

  try {
    // Try silent token acquisition first
    const response = await instance.acquireTokenSilent(request)

    return response.accessToken
  } catch (silentError) {
    // Fallback to interactive login if silent acquisition fails (optional)
    console.warn('Silent token acquisition failed, acquiring token interactively...', silentError)
    try {
      const response = await instance.acquireTokenPopup(request)

      return response.accessToken
    } catch (interactiveError) {
      console.error('Interactive token acquisition failed', interactiveError)

      return null
    }
  }
}

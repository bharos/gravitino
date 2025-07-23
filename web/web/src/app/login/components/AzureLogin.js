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

'use client'

import { Box, Button, Typography } from '@mui/material'
import { useMsal, AuthenticatedTemplate, UnauthenticatedTemplate } from '@azure/msal-react'
import { getMsalConfig, initMsal } from '@/lib/auth/msal'
import { useAuth } from '@/lib/provider/session'

function AzureLogin({ oauthConfig }) {
  const { authError } = useAuth()

  return (
    <>
      {/* Auth error display */}
      {authError && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'error.light', borderRadius: 1 }}>
          <Typography variant='body2' color='error'>
            Authentication Error: {authError}
          </Typography>
        </Box>
      )}

      <AuthenticatedTemplate>
        <AzureProfile />
        <AzureLogoutButton />
      </AuthenticatedTemplate>
      <UnauthenticatedTemplate>
        <AzureLoginButton oauthConfig={oauthConfig} />
      </UnauthenticatedTemplate>
    </>
  )
}

function AzureLoginButton({ oauthConfig }) {
  const { instance } = useMsal()

  const handleLogin = async () => {
    try {
      await initMsal()

      const config = getMsalConfig()
      if (!config) {
        console.error('[Azure Login] MSAL config not available')

        return
      }

      console.log('[Azure Login] Using config:', config)

      // Get scopes from backend config
      const configuredScopes = config.scopes || 'openid profile email'
      const scopeArray = configuredScopes.split(' ').filter(scope => scope.trim())
      const scopes = ['openid', 'email', 'offline_access', ...scopeArray]

      console.info('[Azure Login] Requesting login with scopes:', scopes)

      instance.loginRedirect({ scopes })
    } catch (error) {
      console.error('[Azure Login] Error during login:', error)
    }
  }

  return (
    <Button fullWidth size='large' variant='contained' onClick={handleLogin} sx={{ mb: 3, mt: 4 }}>
      Login with Microsoft
    </Button>
  )
}

function AzureLogoutButton() {
  const { instance } = useMsal()

  return (
    <Button fullWidth size='large' variant='outlined' onClick={() => instance.logoutRedirect()} sx={{ mb: 3, mt: 4 }}>
      Logout
    </Button>
  )
}

function AzureProfile() {
  const { accounts } = useMsal()
  const account = accounts[0]

  return account ? (
    <Typography variant='body2' sx={{ textAlign: 'center', my: 2 }}>
      Welcome, {account.username}
    </Typography>
  ) : null
}

export default AzureLogin

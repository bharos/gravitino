'use client'

import { useMsal } from '@azure/msal-react'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function OAuthCallbackPage() {
  const router = useRouter()
  const { instance, accounts } = useMsal()

  useEffect(() => {
    async function handleAuth() {
      console.log('[OAuthCallbackPage] useEffect triggered. Accounts:', accounts)
      if (accounts.length > 0) {
        console.log('[OAuthCallbackPage] Found accounts:', accounts)
        try {
          console.log('[OAuthCallbackPage] Attempting to acquire token silently...')

          const response = await instance.acquireTokenSilent({
            account: accounts[0],
            scopes: ['User.Read'] // Use your required scopes
          })
          console.log('[OAuthCallbackPage] Token acquired:', response.accessToken)
          localStorage.setItem('accessToken', response.accessToken)
          console.log('[OAuthCallbackPage] accessToken stored in localStorage. Redirecting to /metalakes')
          router.replace('/metalakes')
        } catch (e) {
          console.warn('[OAuthCallbackPage] Failed to acquire token:', e)
          router.replace('/ui/login')
        }
      } else {
        console.warn('[OAuthCallbackPage] No accounts found, redirecting to /ui/login')
        router.replace('/ui/login')
      }
    }
    handleAuth()
  }, [accounts, instance, router])

  return (
    <div style={{ textAlign: 'center', marginTop: '2rem' }}>
      <h2>Completing OAuth login...</h2>
      <p>
        If you are not redirected automatically, <a href='/ui/login'>click here</a>.
      </p>
    </div>
  )
}

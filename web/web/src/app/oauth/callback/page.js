'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function OAuthCallbackPage() {
  const router = useRouter()

  useEffect(() => {
    // OAuth redirect is handled automatically by MSAL provider factory
    // Just redirect to metalakes page after a brief delay
    const timer = setTimeout(() => {
      router.replace('/metalakes')
    }, 1000)

    return () => clearTimeout(timer)
  }, [router])

  return (
    <div style={{ textAlign: 'center', marginTop: '2rem' }}>
      <h2>Completing OAuth login...</h2>
      <p>
        If you are not redirected automatically, <a href='/ui/login'>click here</a>.
      </p>
    </div>
  )
}

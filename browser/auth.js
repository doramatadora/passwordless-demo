const REDIRECT_AFTER_AUTH = '/room/devops-bcn'

// Note: This script uses @simplewebauthn/browser, a lightweight wrapper around
// the Web Authentication API: https://simplewebauthn.dev/docs/packages/browser
const {
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
  startRegistration,
  startAuthentication
} = SimpleWebAuthnBrowser

const COMPAT_MESSAGE = document.getElementById('passkeyNotSupported')
const PASSKEY_SUPPORTED = document.getElementById('passkeySupported')
const DIVIDER = document.getElementById('divider')
const REGISTER_BUTTON = document.getElementById('register')
const AUTHENTICATE_BUTTON = document.getElementById('authenticate')
const USER_NAME = document.getElementById('name')
const AUTH_NAME = document.getElementById('auth-name')
const ANNOUNCER = document.getElementById('announcer')

const announce = (msg, keepMs = 3000) => {
  ANNOUNCER.innerText = msg
  ANNOUNCER.style.display = 'block'
  setTimeout(() => {
    ANNOUNCER.style.display = 'none'
  }, keepMs)
}

const postJsonTo = async (url, body) =>
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body)
  })

/**
 * Registration
 */
const webAuthnRegister = async userName => {
  // 1. Get registration options from the Relying Party (RP) server (Fastly Compute).
  const optionsReq = await fetch(`/registration/options?name=${userName}`)
  const options = await optionsReq.json()
  if (!optionsReq.ok && options.error) throw new Error(options.error)
  console.debug('Registration options from RP', options)

  // 2. Submit registration options to the authenticator.
  const regResp = await startRegistration(options)
  console.debug('Registration response from authenticator', regResp)

  // 3. Submit the authenticator's response to the Relying Party for verification.
  const verifyResp = await postJsonTo('/registration/verify', regResp)
  const verification = await verifyResp.json()
  console.debug('Registration verification response from RP', verifyResp)

  if (verification.error) throw new Error(verification.error)
  localStorage.setItem('userName', userName)
  return verification.verified
}

/**
 * Authentication
 */
const webAuthnAuthenticate = async (userName, redirect) => {
  userName = userName || localStorage.getItem('userName')
  // 1. Get authentication options from the Relying Party (RP) server (Fastly Compute).
  const optionsReq = await fetch(`/authentication/options?name=${userName}`)
  const options = await optionsReq.json()
  if (!optionsReq.ok && options.error) throw new Error(options.error)
  console.debug('Authentication options from RP', options)

  // 2. Submit authentication options to the authenticator.
  const authResp = await startAuthentication(options)
  console.debug('Authentication response from authenticator', authResp)

  // 3. Submit the authenticator's response to the Relying Party for verification.
  const verifyResp = await postJsonTo(`/authentication/verify`, authResp)
  const verification = await verifyResp.json()

  if (verification.error) throw new Error(verification.error)

  // Honour redirect if present.
  if (redirect) {
    console.debug('Redirecting to', redirect)
    location.href = redirect
  }

  return verification.verified
}

// Feature detection: Does this browser support passkeys (WebAuthn)?
if (browserSupportsWebAuthn()) {
  // Uncomment if you exclusively want to support platform authenticators
  // (e.g. Face ID, Windows Hello, Android fingerprint unlock etc.)
  // ;(async () => {
  //   if (await platformAuthenticatorIsAvailable()) {
  // Display the form to register or authenticate.
  PASSKEY_SUPPORTED.style.display = 'flex'

  if (localStorage.getItem('userName')) {
    const userName = localStorage.getItem('userName')
    AUTH_NAME.value = userName
    USER_NAME.value = userName
    USER_NAME.disabled = true
    REGISTER_BUTTON.style.display = 'none'
    DIVIDER.style.display = 'none'
  } else {
    REGISTER_BUTTON.style.display = 'block'
    DIVIDER.style.display = 'block'
    USER_NAME.disabled = false
    REGISTER_BUTTON.addEventListener('click', async e => {
      e.preventDefault()
      if (!USER_NAME.value) {
        announce(`Please enter a username`, 2000)
        return USER_NAME.focus()
      }
      try {
        await webAuthnRegister(USER_NAME.value)
        announce(`Success! Now try to authenticate...`)
      } catch (err) {
        announce(`Registration failed: ${err.message}`)
        throw err
      }
    })
  }

  AUTHENTICATE_BUTTON.addEventListener('click', async e => {
    e.preventDefault()
    try {
      const userName = USER_NAME.value || localStorage.getItem('userName')
      if (!userName) {
        announce(`Please enter a username`, 2000)
        return USER_NAME.focus()
      }
      AUTH_NAME.value = userName
      await webAuthnAuthenticate(AUTH_NAME.value, REDIRECT_AFTER_AUTH)
    } catch (err) {
      announce(`Authentication failed: ${err.message}`)
      throw err
    }
  })
  // Uncomment if you exclusively want to support platform authenticators
  // (e.g. Face ID, Windows Hello, Android fingerprint unlock etc.)
  //   } else {
  //     announce(`User verifying platform authenticator is not available`)
  //     throw new Error(`User verifying platform authenticatorƒ is not available`)
  //   }
  // })()
} else {
  // Display message that passkeys are not supported.
  COMPAT_MESSAGE.style.display = 'block'
}

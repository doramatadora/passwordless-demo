/// <reference types="@fastly/js-compute" />

import { env } from 'fastly:env'
import { includeBytes } from 'fastly:experimental'
import { CacheOverride } from 'fastly:cache-override'
import { createFanoutHandoff } from 'fastly:fanout'
import { KVStore } from 'fastly:kv-store'
import { getGeolocationForIpAddress } from 'fastly:geolocation'
import { v4 as uuidv4 } from 'uuid'
import slugify from 'slug'
import * as jose from 'jose'

import { issueAuthJwt, userNameFromAuthJwt, asJwt, asKey } from './lib/jwt'
import * as cookie from './lib/cookie'

import {
  // Registration
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // Authentication
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server'

import { isoUint8Array } from '@simplewebauthn/server/helpers'

// Constants.
import {
  STORE_NAME,
  ORIGIN_API_KEY,
  ORIGIN_BACKEND_NAME,
  AUTH_COOKIE_NAME,
  RP_NAME,
  RP_ID,
  RP_ORIGIN
} from './constants'

// Static files.
const indexPage = includeBytes('./browser/index.html')
const authScript = includeBytes('./browser/auth.js')
const styleSheet = includeBytes('./browser/auth.css')

// App entry point: attach a listener to the fetch event.
addEventListener('fetch', event => event.respondWith(handleRequest(event)))

async function handleRequest (event) {
  // Log service version.
  console.log(
    'FASTLY_SERVICE_VERSION: ',
    env('FASTLY_SERVICE_VERSION') || 'local'
  )

  const req = event.request
  const url = new URL(req.url)
  const qs = url.searchParams

  // Serve static files.
  if (url.pathname === '/auth.js') {
    return textResp(authScript, 'javascript')
  }
  if (url.pathname === '/auth.css') {
    return textResp(styleSheet, 'css')
  }

  // Parse the Cookie header.
  const cookieHeader = req.headers.get('cookie')
  const cookies = cookie.parse(cookieHeader)
  console.debug({ cookies })

  // Assign a session ID.
  const sessId = cookies.authSsid || uuidv4()

  // Initialize KV Store.
  const store = new KVStore(STORE_NAME)

  // Get any user data.
  const userNameFromSession = await userNameFromAuthJwt(
    cookies[AUTH_COOKIE_NAME]
  )
  const userName = userNameFromSession || qs.get('name')
  const userKey = userName ? slugify(userName) : null
  const userExists = await store.get(`user-${userKey}`)

  // 🚀 WebAuthn 🚀

  // ✨ REGISTRATION ✨
  // Generate registration options.
  if (userName && url.pathname == '/registration/options') {
    // Make sure the user doesn't already exist in the KVStore.
    // Comment this block to allow users to register multiple devices...
    if (userExists && userKey === slugify(qs.get('name'))) {
      return errResp('That handle is taken 😔 Please choose another one', 409)
    }
    const user = {
      id: uuidv4(),
      name: userName,
      devices: []
    }
    // ...and retrieve user data from KV Store instead.

    const regOpts = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: user.id,
      userName: user.name,
      timeout: 60000,
      // Don't prompt users for additional information about the authenticator.
      attestationType: 'none',
      // Prevent users from re-registering existing authenticators.
      excludeCredentials: user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports
      })),
      authenticatorSelection: {
        // "Discoverable credentials" used to be called "resident keys". The
        // old name persists in the options passed to `navigator.credentials.create()`.
        residentKey: 'required',
        userVerification: 'preferred'
      }
    })
    console.debug({ regOpts })

    // Store the challenge for verification, in a time-limited JWT, signed with the session ID.
    const token = await asJwt({ challenge: regOpts.challenge }, sessId, '5m')
    // Store the challenge JWT and user data in KV Store.
    await store.put(`sess-${sessId}`, JSON.stringify({ token, user }))

    return jsonResp(regOpts)
  }

  // Verify registration response.
  // Note: Ideally, a separate mechanism should be implemented to verify that a new user is not a bot. Seek verification of ownership of a unique "point of contact" outside of this service (e.g., email with "magic link").
  // See: https://simplewebauthn.dev/docs/advanced/passkeys#registration
  if (req.method === 'POST' && url.pathname == '/registration/verify') {
    try {
      const sessData = await store.get(`sess-${sessId}`).then(c => c?.json())
      if (!sessData) {
        throw new Error(`Session data corrupted`)
      }

      const user = sessData.user

      // Verify the challenge was signed with the right ID.
      const { payload } = await jose.jwtVerify(sessData.token, asKey(sessId))
      const expectedChallenge = `${payload.challenge}`

      // Void challenge to prevent replay attacks.
      await store.put(`sess-${sessId}`, '{}')

      const body = await req.json()
      const verification = await verifyRegistrationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: RP_ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true
      })
      console.debug({ verification })

      const { verified, registrationInfo } = verification
      if (!verified) {
        throw new Error(`Passkey verification failed`)
      }

      if (registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo

        const existingDevice = user.devices.find(device =>
          isoUint8Array.areEqual(device.credentialID, credentialID)
        )
        if (!existingDevice) {
          // Add the returned device to the user's list of devices.
          user.devices.push({
            credentialPublicKey: isoUint8Array.toHex(credentialPublicKey),
            credentialID: isoUint8Array.toHex(credentialID),
            counter,
            transports: body.response.transports
          })
        }

        const userKey = slugify(user.name)

        // Register the user in KV Store.
        await store.put(`user-${userKey}`, JSON.stringify(user))
        // Map the registered credential to the userKey.
        await store.put(`cred-${body.rawId}`, userKey)
      }

      return jsonResp({ verified }, 200)
    } catch (e) {
      console.error(e)
      return errResp(`Uh-oh! We couldn't register you (reason: ${e.message})`)
    }
  }

  // 🚨 The user should exist in KV Store at this point, with credentials mapped to userKey.

  // ✨ AUTHENTICATION ✨
  // Generate authentication options.
  if (req.method === 'GET' && url.pathname == '/authentication/options') {
    let user = userExists ? await userExists.json() : {}
    const authOpts = generateAuthenticationOptions({
      timeout: 60000,
      allowCredentials: user.devices?.map(dev => ({
        id: isoUint8Array.fromHex(dev.credentialID),
        type: 'public-key',
        transports: dev.transports
      })),
      userVerification: 'preferred',
      rpID: RP_ID
    })
    console.debug({ authOpts })

    // Store the challenge for verification, in a time-limited JWT, signed with the session ID.
    const token = await asJwt({ challenge: authOpts.challenge }, sessId, '5m')
    // Store the challenge in KV Store.
    await store.put(`sess-${sessId}`, JSON.stringify({ token }))

    return jsonResp(authOpts)
  }

  // Verify authentication response.
  if (req.method === 'POST' && url.pathname == '/authentication/verify') {
    try {
      const sessData = await store.get(`sess-${sessId}`).then(c => c?.json())
      if (!sessData) {
        throw new Error(`Session data corrupted`)
      }

      // Verify the challenge was signed with the right ID.
      const { payload } = await jose.jwtVerify(sessData.token, asKey(sessId))
      const expectedChallenge = `${payload.challenge}`

      // Void challenge to prevent replay attacks.
      await store.put(`sess-${sessId}`, '{}')

      const body = await req.json()
      const bodyCredIDBuffer = new Buffer(body.rawId, 'base64')

      // Find the user that owns the credential.
      const userKey = await store
        .get(`cred-${body.rawId}`)
        .then(entry => entry?.text())
      const user = await store.get(`user-${userKey}`).then(u => u?.json())

      // Find an authenticator matching the credential ID.
      const authenticator = user?.devices?.find(dev =>
        isoUint8Array.areEqual(
          isoUint8Array.fromHex(dev.credentialID),
          bodyCredIDBuffer
        )
      )
      if (!authenticator) {
        throw new Error(`Passkey isn't registered with this site.`)
      }

      const verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: RP_ORIGIN,
        expectedRPID: RP_ID,
        authenticator: {
          credentialPublicKey: isoUint8Array.fromHex(
            authenticator.credentialPublicKey
          ),
          credentialID: isoUint8Array.fromHex(authenticator.credentialID),
          counter: authenticator.counter,
          transports: authenticator.transports
        },
        requireUserVerification: true
      })
      console.debug({ verification })

      const { verified, authenticationInfo } = verification
      if (!verified) {
        throw new Error(`Passkey verification failed`)
      }

      // Update the authenticator's counter. The parent (user) object will be updated in KV Store.
      authenticator.counter = authenticationInfo.newCounter
      await store.put(`user-${userKey}`, JSON.stringify(user))

      // Generate a time-limited JWT signed with the user's UUID (from KV Store) and set a session cookie to persist authentication.
      const authToken = await issueAuthJwt(userKey)
      const headers = {
        'set-cookie': cookie.session(AUTH_COOKIE_NAME, authToken)
      }

      // Handle redirect if one was assigned.
      const redirect = qs.get('redirect')
      if (redirect) {
        Object.assign(headers, { location: redirect })
      }

      return jsonResp({ verified }, redirect ? 303 : 200, headers)
    } catch (e) {
      console.error(e)
      return errResp(
        `Uh-oh! We couldn't authenticate you (reason: ${e.message})`
      )
    }
  }

  // Login / register screen.
  if (url.pathname === '/') {
    return new Response(indexPage, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': cookie.session('authSsid', sessId)
      }
    })
  }

  // ✨ AUTHENTICATED REQUESTS ✨
  if (url.pathname.startsWith('/room/')) {
    if (!userNameFromSession) {
      return errResp('Unauthorized', 307, { Location: '/' })
    }
    // Set an API key header for all requests to the origin.
    req.headers.set('x-api-key', ORIGIN_API_KEY)
    // Set a header to identify the user.
    req.headers.set('x-user', userNameFromSession)
    // Set any geolocation headers.
    const ip = event.client.address
    const { utc_offset } = getGeolocationForIpAddress(ip)
    req.headers.set('x-utc-offset', utc_offset)
  }

  // ✨ REAL-TIME WITH FASTLY FANOUT ✨
  if (req.headers.get('accept')?.includes('text/event-stream')) {
    return createFanoutHandoff(req, ORIGIN_BACKEND_NAME)
  }

  const cacheOverride =
    req.method === 'GET' || req.headers.get('content-type')?.includes('text/')
      ? new CacheOverride('override', { ttl: 10, swr: 86_400 })
      : new CacheOverride('pass')

  // Pass everything else to the origin.
  return fetch(event.request, {
    cacheOverride,
    backend: ORIGIN_BACKEND_NAME
  })
}

// Response helpers.
const textResp = (body, type) =>
  new Response(body, {
    headers: { 'Content-Type': `text/${type}; charset=utf-8` }
  })

const jsonResp = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  })

const errResp = (error, status = 400, headers = {}) =>
  jsonResp({ error }, status, {
    'Set-Cookie': cookie.expired(AUTH_COOKIE_NAME),
    ...headers
  })

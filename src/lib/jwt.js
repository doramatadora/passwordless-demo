/// <reference types="@fastly/js-compute" />
import * as jose from 'jose'
import { KVStore } from 'fastly:kv-store'
import { STORE_NAME, JWT_LIFETIME } from '../constants'
import slugify from 'slug'

export const asKey = str => new TextEncoder().encode(str)

// Creates a time-limited JWT.
export const asJwt = async (payload, secretStr, exp = JWT_LIFETIME) =>
  await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(asKey(secretStr))

// Issues a time-limited JWT for a user name, signed with the corresponding user ID.
export async function issueAuthJwt (userKey) {
  try {
    // Look up the corresponding user data in KV Store.
    const store = new KVStore(STORE_NAME)
    const { id, name } = await store.get(`user-${userKey}`).then(u => u.json())
    // Create a time-limited JWT, signed with the user's ID, containing the user's name.
    return await asJwt({ name }, id, '24h')
  } catch (e) {
    console.error('Error issuing JWT', e.message)
    return null
  }
}

// Verifies an auth persistence token and returns the associated user name.
export async function userNameFromAuthJwt (token) {
  if (token) {
    try {
      // Decode JWT without verifying, to get the user key from the claims.
      const { name: claimedName, exp } = jose.decodeJwt(token)
      console.log({ claimedName, exp })
      // Look up the corresponding user data in KV Store.
      const store = new KVStore(STORE_NAME)
      const userKey = slugify(claimedName)
      const { id, name } = await store
        .get(`user-${userKey}`)
        .then(u => u.json())
      // Verify that the JWT was signed with the user's ID.
      await jose.jwtVerify(token, asKey(id))

      if (claimedName !== name) {
        throw new Error('User name mismatch')
      }
      return name
    } catch (e) {
      console.error('Error verifying JWT', e.message)
    }
  }
  return null
}

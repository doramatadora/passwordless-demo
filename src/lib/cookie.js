import cookie from 'cookie'
import { env } from 'fastly:env'

// Use secure cookies in production.
const getPrefix = () => (env('FASTLY_SERVICE_VERSION') ? '__Secure-' : '')

const prefix = name => `${getPrefix()}${name}`

const attrs = () => ({
  path: '/',
  sameSite: 'lax',
  secure: Boolean(env('FASTLY_SERVICE_VERSION')),
  HttpOnly: true
})

export const session = (name, value) =>
  cookie.serialize(prefix(name), value, attrs())

export const persistent = (name, value, maxAge) =>
  cookie.serialize(prefix(name), value, {
    ...attrs(),
    maxAge
  })

export const expired = name => persistent(name, 'expired', 0)

export const parse = (cookieHeader, onlyWithPrefix = true) => {
  if (!cookieHeader) {
    return {}
  }
  const cookies = cookie.parse(cookieHeader)
  // By default, return only cookies with the right prefix.
  const cookiePrefix = getPrefix()
  return onlyWithPrefix && Boolean(cookiePrefix)
    ? Object.keys(cookies).reduce((acc, key) => {
        if (key.startsWith(cookiePrefix)) {
          acc[key.slice(cookiePrefix.length)] = cookies[key]
        }
        return acc
      }, {})
    : cookies
}

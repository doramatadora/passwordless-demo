import { env } from 'fastly:env'

// Application set-up.
export const STORE_NAME = env('STORE_NAME')
export const ORIGIN_BACKEND_NAME = env('ORIGIN_BACKEND_NAME')
export const ORIGIN_API_KEY = env('ORIGIN_API_KEY')

// JWT stuff.
export const JWT_LIFETIME = '5m'
export const AUTH_COOKIE_NAME = 'authed'

// ✨ WEBAUTHN RELYING PARTY STUFF ✨
export const RP_NAME = env('RP_NAME')
export const RP_ID = env('RP_ID')
export const RP_ORIGIN = env('RP_ORIGIN')

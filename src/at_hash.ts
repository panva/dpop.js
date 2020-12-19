import { encode } from './base64url'

export default async (alg: string, accessToken: string) => {
  const data = new TextEncoder().encode(accessToken)
  const algorithm = `SHA-${alg.substr(2, 5)}`
  const digest = new Uint8Array(await crypto.subtle.digest(algorithm, data))
  return encode(digest.slice(0, digest.length / 2));
}

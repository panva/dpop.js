import JWT from './jwt'
import jti from './jti'
import atHash from './at_hash'

const iat = () => Date.now() / 1000 | 0

async function toJWK(publicKey: CryptoKey) {
  const { alg, ext, key_ops, ...jwk } = await crypto.subtle.exportKey('jwk', publicKey)
  return jwk
}

export default async (keypair: CryptoKeyPair, alg: string, htu: string, htm: string, accessToken?: string, additional?: object) => {
  const jwk = await toJWK(keypair.publicKey)

  if (accessToken) {
    additional = { ...additional, at_hash: await atHash(alg, accessToken) }
  }

  return JWT(
    keypair.privateKey,
    { typ: 'dpop+jwt', alg, jwk },
    { ...additional, iat: iat(), jti: jti(), htu, htm }
  )
}

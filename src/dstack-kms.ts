/**
 * External dstack KMS root-seed source.
 *
 * On ephemeral hosts (GCP TDX spot instances, replaceable CVMs) the
 * root seed must NOT live on the instance: the VM can be preempted and
 * re-created at any time, and the boot disk is disposable. Instead the
 * seed is derived from key material served by the dstack guest agent,
 * which the external dstack KMS provisions into the CVM after remote
 * attestation. The KMS binds the key to the measured app — a rebuilt
 * instance running the same measured image gets the SAME key, so the
 * root seed (and every wallet KEK / enclave key derived from it) is
 * stable across preemption and failover without ever being persisted.
 *
 * Like attestation.ts, this module talks only to the LOCAL guest-agent
 * unix socket — no external network calls. The agent's GetKey response
 * is treated as IKM and normalized to 32 bytes with HKDF-SHA256 under
 * a fixed, versioned info string so the derivation is deterministic.
 *
 * This module is wired from the entrypoint only; the enclave core
 * (root-seed.ts and friends) stays pure.
 */
import * as crypto from 'node:crypto'
import * as http from 'node:http'
import { ROOT_SEED_BYTES } from './root-seed.js'

export class DstackKmsError extends Error {}

const DEFAULT_DSTACK_SOCK = '/var/run/dstack.sock'
export const DEFAULT_KMS_KEY_PATH = 'wallet-service/root-seed'
const DEFAULT_PURPOSE = 'root-seed'
const HKDF_INFO = 'atproto-wallet-service/root-seed/v1'

/** GET /GetKey from the dstack guest agent over its unix socket. */
function fetchDstackKey(
  socketPath: string,
  keyPath: string,
  purpose: string,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const query = `path=${encodeURIComponent(keyPath)}&purpose=${encodeURIComponent(purpose)}`
    const req = http.request(
      {
        socketPath,
        path: `/GetKey?${query}`,
        method: 'GET',
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            if (typeof body.key === 'string' && body.key.length > 0) {
              resolve(body.key)
            } else {
              reject(new DstackKmsError('dstack GetKey response missing key'))
            }
          } catch (err) {
            reject(
              new DstackKmsError(
                `dstack GetKey response unparsable: ${err instanceof Error ? err.message : String(err)}`,
              ),
            )
          }
        })
      },
    )
    req.on('error', (err) =>
      reject(new DstackKmsError(`dstack GetKey failed: ${err.message}`)),
    )
    req.on('timeout', () => req.destroy(new Error('dstack GetKey timeout')))
    req.end()
  })
}

/**
 * Load the root seed from the external dstack KMS via the local guest
 * agent. Hard failure (throw) on any problem — a wallet service must
 * never fall back to an ambiguous key source.
 */
export async function loadRootSeedFromDstackKms(
  opts: {
    sockPath?: string
    keyPath?: string
    purpose?: string
    timeoutMs?: number
  } = {},
): Promise<Buffer> {
  const keyHex = await fetchDstackKey(
    opts.sockPath ?? DEFAULT_DSTACK_SOCK,
    opts.keyPath ?? DEFAULT_KMS_KEY_PATH,
    opts.purpose ?? DEFAULT_PURPOSE,
    opts.timeoutMs ?? 10_000,
  )
  if (!/^([0-9a-fA-F]{2})+$/.test(keyHex)) {
    throw new DstackKmsError('dstack KMS key material is not valid hex')
  }
  const ikm = Buffer.from(keyHex, 'hex')
  try {
    if (ikm.length < ROOT_SEED_BYTES) {
      throw new DstackKmsError(
        `dstack KMS returned ${ikm.length} bytes of key material; ` +
          `need at least ${ROOT_SEED_BYTES}`,
      )
    }
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        ikm,
        Buffer.alloc(0),
        HKDF_INFO,
        ROOT_SEED_BYTES,
      ),
    )
  } finally {
    ikm.fill(0)
  }
}

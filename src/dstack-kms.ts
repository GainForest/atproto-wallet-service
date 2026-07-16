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
import { DstackClient } from '@phala/dstack-sdk'
import { ROOT_SEED_BYTES } from './root-seed.js'

export class DstackKmsError extends Error {}

const DEFAULT_DSTACK_SOCK = '/var/run/dstack.sock'
export const DEFAULT_KMS_KEY_PATH = 'wallet-service/root-seed'
const DEFAULT_PURPOSE = 'root-seed'
const HKDF_INFO = 'atproto-wallet-service/root-seed/v1'

/** Fetch key material through the official dstack guest-agent SDK. */
async function fetchDstackKey(
  socketPath: string,
  keyPath: string,
  purpose: string,
): Promise<Uint8Array> {
  try {
    const response = await new DstackClient(socketPath).getKey(keyPath, purpose)
    if (!(response.key instanceof Uint8Array) || response.key.length === 0) {
      throw new DstackKmsError('dstack GetKey response missing key')
    }
    return response.key
  } catch (err) {
    if (err instanceof DstackKmsError) throw err
    throw new DstackKmsError(
      `dstack GetKey failed: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
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
  } = {},
): Promise<Buffer> {
  const key = await fetchDstackKey(
    opts.sockPath ?? DEFAULT_DSTACK_SOCK,
    opts.keyPath ?? DEFAULT_KMS_KEY_PATH,
    opts.purpose ?? DEFAULT_PURPOSE,
  )
  const ikm = Buffer.from(key)
  key.fill(0)
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

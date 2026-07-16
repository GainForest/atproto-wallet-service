/**
 * Attestation — proving the signer's key material lives inside a TEE.
 *
 * In production the signer runs as a dstack workload inside a
 * confidential VM (Intel TDX / AMD SEV-SNP). dstack exposes a guest
 * agent on a unix socket that returns a hardware quote over caller-
 * supplied report data. We bind the quote to this signer instance by
 * putting SHA-256(identity public key) into report_data — a verifier
 * can then check: genuine hardware, expected code measurement, and
 * that THIS public key (and therefore every key derived alongside it)
 * lives inside the measured code.
 *
 * Outside a TEE (dev), there is no quote: mode is 'dev' and callers
 * that require attestation (EPDS_SIGNER_REQUIRE_ATTESTATION=1) must
 * refuse to proceed.
 */
import * as fs from 'node:fs'
import { DstackClient } from '@phala/dstack-sdk'

export interface AttestationResult {
  mode: 'dstack' | 'dev'
  /** hex SHA-256 of the signer identity public key, bound into the quote */
  reportData: string
  /** hex-encoded hardware quote, or null in dev mode */
  quote: string | null
  /** Measured dstack event log required to replay the RTMR values. */
  eventLog?: string
  /** dstack VM configuration covered by the attestation evidence. */
  vmConfig?: string
  note?: string
}

const DEFAULT_DSTACK_SOCK = '/var/run/dstack.sock'

/** Fetch quote evidence through the official dstack guest-agent SDK. */
async function fetchDstackQuote(
  socketPath: string,
  reportDataHex: string,
): Promise<{ quote: string; eventLog: string; vmConfig?: string }> {
  const result = await new DstackClient(socketPath).getQuote(
    Buffer.from(reportDataHex, 'hex'),
  )
  if (typeof result.quote !== 'string' || result.quote.length === 0) {
    throw new Error('dstack response missing quote')
  }
  if (typeof result.event_log !== 'string' || result.event_log.length === 0) {
    throw new Error('dstack response missing event log')
  }
  return {
    quote: result.quote,
    eventLog: result.event_log,
    vmConfig: result.vm_config,
  }
}

export async function getAttestation(opts: {
  reportDataHex: string
  dstackSockPath?: string
  /** Production fail-closed mode: never downgrade to `mode: dev`. */
  requireTee?: boolean
}): Promise<AttestationResult> {
  const sockPath = opts.dstackSockPath ?? DEFAULT_DSTACK_SOCK
  if (fs.existsSync(sockPath)) {
    try {
      const evidence = await fetchDstackQuote(sockPath, opts.reportDataHex)
      return {
        mode: 'dstack',
        reportData: opts.reportDataHex,
        quote: evidence.quote,
        eventLog: evidence.eventLog,
        vmConfig: evidence.vmConfig,
      }
    } catch (err) {
      const message = `dstack socket present but quote failed: ${err instanceof Error ? err.message : String(err)}`
      if (opts.requireTee) throw new Error(message)
      return {
        mode: 'dev',
        reportData: opts.reportDataHex,
        quote: null,
        note: message,
      }
    }
  }
  const message = 'no TEE guest agent found — running unattested (dev mode)'
  if (opts.requireTee) throw new Error(message)
  return {
    mode: 'dev',
    reportData: opts.reportDataHex,
    quote: null,
    note: message,
  }
}

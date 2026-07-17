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
 * On hosts without dstack (e.g. GCP TDX CVMs on a stock guest image)
 * we fall back to Linux's configfs-TSM interface, either directly
 * (when privileged) or through the local root-owned quote helper
 * (`tsm-quote-helper.ts`) on its own unix socket. The resulting mode
 * is 'tdx-tsm': a genuine hardware quote over the same report data,
 * but WITHOUT dstack's measured-workload event log — it proves the
 * hardware and boot chain, not that the operator is locked out.
 *
 * Outside a TEE (dev), there is no quote: mode is 'dev' and callers
 * that require attestation (EPDS_SIGNER_REQUIRE_ATTESTATION=1) must
 * refuse to proceed.
 */
import * as fs from 'node:fs'
import * as http from 'node:http'
import { DstackClient } from '@phala/dstack-sdk'
import {
  DEFAULT_TSM_REPORT_DIR,
  fetchTsmQuote,
  tsmAvailable,
} from './tsm-quote.js'

export const DEFAULT_TSM_QUOTE_SOCK = '/run/tdx-quote.sock'

export interface AttestationResult {
  mode: 'dstack' | 'tdx-tsm' | 'dev'
  /** hex SHA-256 of the signer identity public key, bound into the quote */
  reportData: string
  /** hex-encoded raw hardware quote (native TSM) or null. */
  quote: string | null
  /** Versioned dstack evidence bundle (TDX + vTPM + logs + VM config). */
  attestation?: string
  /** Raw dstack quote evidence fields retained for compatibility/debugging. */
  eventLog?: string
  vmConfig?: string
  /** kernel TSM provider (tdx-tsm mode), e.g. "tdx_guest" */
  provider?: string
  note?: string
}

const DEFAULT_DSTACK_SOCK = '/var/run/dstack.sock'

/** Fetch the versioned GCP evidence bundle through the official SDK. */
async function fetchDstackAttestation(
  socketPath: string,
  reportDataHex: string,
): Promise<string> {
  const result = await new DstackClient(socketPath).attest(
    Buffer.from(reportDataHex, 'hex'),
  )
  if (
    typeof result.attestation !== 'string' ||
    result.attestation.length === 0
  ) {
    throw new Error('dstack response missing attestation bundle')
  }
  return result.attestation
}

/** GET /quote from the local root-owned TDX quote helper. */
function fetchHelperQuote(
  socketPath: string,
  reportDataHex: string,
): Promise<{ quote: string; provider: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path: `/quote?report_data=${reportDataHex}`,
        method: 'GET',
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            if (
              res.statusCode === 200 &&
              typeof body.quote === 'string' &&
              body.quote.length > 0
            ) {
              resolve({
                quote: body.quote,
                provider:
                  typeof body.provider === 'string' ? body.provider : '',
              })
            } else {
              reject(
                new Error(
                  `tdx quote helper error (${res.statusCode}): ${typeof body.error === 'string' ? body.error : 'missing quote'}`,
                ),
              )
            }
          } catch (err) {
            reject(err instanceof Error ? err : new Error(String(err)))
          }
        })
      },
    )
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('tdx quote helper timeout')))
    req.end()
  })
}

export async function getAttestation(opts: {
  reportDataHex: string
  dstackSockPath?: string
  /** Unix socket of the root-owned configfs-TSM quote helper. */
  tsmQuoteSockPath?: string
  /** configfs-TSM report directory (direct mode, needs privileges). */
  tsmReportDir?: string
  /** Production fail-closed mode: never downgrade to `mode: dev`. */
  requireTee?: boolean
}): Promise<AttestationResult> {
  const sockPath = opts.dstackSockPath ?? DEFAULT_DSTACK_SOCK
  if (fs.existsSync(sockPath)) {
    try {
      const attestation = await fetchDstackAttestation(
        sockPath,
        opts.reportDataHex,
      )
      return {
        mode: 'dstack',
        reportData: opts.reportDataHex,
        quote: null,
        attestation,
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

  // configfs-TSM fallback: helper socket first (unprivileged service),
  // then direct configfs access (privileged deployments).
  const tsmSock = opts.tsmQuoteSockPath ?? DEFAULT_TSM_QUOTE_SOCK
  const tsmDir = opts.tsmReportDir ?? DEFAULT_TSM_REPORT_DIR
  const tsmNote =
    'configfs-tsm quote: genuine TDX hardware + measured boot chain; ' +
    'no measured-workload event log (not operator-proof)'
  if (fs.existsSync(tsmSock)) {
    try {
      const { quote, provider } = await fetchHelperQuote(
        tsmSock,
        opts.reportDataHex,
      )
      return {
        mode: 'tdx-tsm',
        reportData: opts.reportDataHex,
        quote,
        provider,
        note: tsmNote,
      }
    } catch (err) {
      const message = `tdx quote helper socket present but quote failed: ${err instanceof Error ? err.message : String(err)}`
      if (opts.requireTee) throw new Error(message)
      return {
        mode: 'dev',
        reportData: opts.reportDataHex,
        quote: null,
        note: message,
      }
    }
  }
  if (tsmAvailable(tsmDir)) {
    try {
      const { quote, provider } = await fetchTsmQuote(opts.reportDataHex, {
        reportDir: tsmDir,
      })
      return {
        mode: 'tdx-tsm',
        reportData: opts.reportDataHex,
        quote,
        provider,
        note: tsmNote,
      }
    } catch (err) {
      const message = `configfs-tsm present but quote failed: ${err instanceof Error ? err.message : String(err)}`
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

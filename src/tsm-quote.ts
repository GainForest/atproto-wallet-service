/**
 * configfs-TSM TDX quote support (Linux 6.7+).
 *
 * GCP confidential VMs with Intel TDX expose quote generation through
 * the kernel's configfs-TSM interface (`/sys/kernel/config/tsm/report`)
 * backed by `/dev/tdx_guest` — no dstack guest agent required:
 *
 *   1. mkdir  <report-dir>/<unique-name>
 *   2. write  64-byte report data into  inblob
 *   3. read   the raw TDX quote from    outblob
 *   4. rmdir  the report directory
 *
 * Creating a report requires write access to the (root-owned) configfs
 * tree, so a non-root service uses the companion root helper in
 * `tsm-quote-helper.ts` instead of calling this module directly.
 *
 * Like attestation.ts, this module performs LOCAL kernel/filesystem
 * operations only — no network calls.
 *
 * IMPORTANT trust caveat: a configfs-TSM quote proves the code runs in
 * a genuine Intel TDX VM with a particular measured boot chain. On a
 * general-purpose guest image (SSH, mutable rootfs) it does NOT prove
 * that the operator cannot access key material. Operator-proofness
 * additionally requires a measured, non-interactive workload image
 * (see docs/stateless-tee-design.md).
 */
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'

export const DEFAULT_TSM_REPORT_DIR = '/sys/kernel/config/tsm/report'

/** TDX/TSM report data is exactly 64 bytes (zero-padded). */
export const TSM_REPORT_DATA_BYTES = 64

export class TsmQuoteError extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Normalize hex report data (1..64 bytes) to the fixed 64-byte inblob.
 * Our callers bind SHA-256 digests (32 bytes); the remainder is zero.
 */
export function tsmReportDataFromHex(reportDataHex: string): Buffer {
  if (!/^([0-9a-fA-F]{2})+$/.test(reportDataHex)) {
    throw new TsmQuoteError('report data must be non-empty hex')
  }
  const raw = Buffer.from(reportDataHex, 'hex')
  if (raw.length > TSM_REPORT_DATA_BYTES) {
    throw new TsmQuoteError(
      `report data must be at most ${TSM_REPORT_DATA_BYTES} bytes`,
    )
  }
  const inblob = Buffer.alloc(TSM_REPORT_DATA_BYTES)
  raw.copy(inblob)
  return inblob
}

/** Whether a configfs-TSM report directory is present on this host. */
export function tsmAvailable(
  reportDir: string = DEFAULT_TSM_REPORT_DIR,
): boolean {
  try {
    return fs.statSync(reportDir).isDirectory()
  } catch {
    return false
  }
}

export interface TsmQuote {
  /** hex-encoded raw hardware quote (TDX quote v4/v5) */
  quote: string
  /** kernel TSM provider name, e.g. "tdx_guest" */
  provider: string
}

/**
 * Generate a hardware quote over the given report data via configfs-TSM.
 *
 * On real configfs the outblob read blocks until the quote is ready; we
 * additionally poll with a deadline so tests (plain filesystems) and
 * transient kernel errors terminate deterministically.
 */
export async function fetchTsmQuote(
  reportDataHex: string,
  opts: { reportDir?: string; timeoutMs?: number } = {},
): Promise<TsmQuote> {
  const reportDir = opts.reportDir ?? DEFAULT_TSM_REPORT_DIR
  const timeoutMs = opts.timeoutMs ?? 10_000
  const inblob = tsmReportDataFromHex(reportDataHex)
  if (!tsmAvailable(reportDir)) {
    throw new TsmQuoteError(`no configfs-tsm report dir at ${reportDir}`)
  }
  const dir = path.join(
    reportDir,
    `wallet-${process.pid}-${crypto.randomBytes(8).toString('hex')}`,
  )
  fs.mkdirSync(dir)
  try {
    fs.writeFileSync(path.join(dir, 'inblob'), inblob)
    const deadline = Date.now() + timeoutMs
    let quote: Buffer | undefined
    for (;;) {
      try {
        const out = fs.readFileSync(path.join(dir, 'outblob'))
        if (out.length > 0) {
          quote = out
          break
        }
      } catch {
        // outblob not readable yet — retry until the deadline
      }
      if (Date.now() >= deadline) break
      await sleep(25)
    }
    if (!quote) {
      throw new TsmQuoteError('configfs-tsm outblob missing or empty')
    }
    let provider = ''
    try {
      provider = fs.readFileSync(path.join(dir, 'provider'), 'utf8').trim()
    } catch {
      // provider attribute is informational only
    }
    return { quote: quote.toString('hex'), provider }
  } finally {
    // configfs report dirs are removed with rmdir even though they
    // contain attribute files; on plain filesystems (tests) fall back
    // to a recursive remove.
    try {
      fs.rmdirSync(dir)
    } catch {
      try {
        fs.rmSync(dir, { recursive: true, force: true })
      } catch {
        // best-effort cleanup
      }
    }
  }
}

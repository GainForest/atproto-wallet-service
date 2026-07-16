import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  fetchTsmQuote,
  tsmAvailable,
  tsmReportDataFromHex,
  TsmQuoteError,
  TSM_REPORT_DATA_BYTES,
} from '../tsm-quote.js'

let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsm-quote-test-'))
})

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

/**
 * Emulate the kernel side of configfs-TSM on a plain filesystem: watch
 * for the report directory to appear, then populate outblob/provider.
 */
function armFakeKernel(reportRoot: string, quote: Buffer): void {
  const timer = setInterval(() => {
    const entries = fs.readdirSync(reportRoot)
    if (entries.length === 0) return
    const reportDir = path.join(reportRoot, entries[0])
    if (!fs.existsSync(path.join(reportDir, 'inblob'))) return
    fs.writeFileSync(path.join(reportDir, 'outblob'), quote)
    fs.writeFileSync(path.join(reportDir, 'provider'), 'tdx_guest\n')
    clearInterval(timer)
  }, 5)
  timer.unref()
}

describe('tsmReportDataFromHex', () => {
  it('zero-pads a 32-byte digest to the 64-byte inblob', () => {
    const inblob = tsmReportDataFromHex('ab'.repeat(32))
    expect(inblob.length).toBe(TSM_REPORT_DATA_BYTES)
    expect(inblob.subarray(0, 32)).toEqual(Buffer.alloc(32, 0xab))
    expect(inblob.subarray(32)).toEqual(Buffer.alloc(32, 0))
  })

  it('rejects non-hex and oversized report data', () => {
    expect(() => tsmReportDataFromHex('not hex')).toThrow(TsmQuoteError)
    expect(() => tsmReportDataFromHex('')).toThrow(TsmQuoteError)
    expect(() => tsmReportDataFromHex('ab'.repeat(65))).toThrow(TsmQuoteError)
  })
})

describe('tsmAvailable', () => {
  it('detects presence of the report directory', () => {
    expect(tsmAvailable(dir)).toBe(true)
    expect(tsmAvailable(path.join(dir, 'nope'))).toBe(false)
  })
})

describe('fetchTsmQuote', () => {
  it('writes the inblob and returns the quote + provider', async () => {
    const quote = Buffer.from('0400020081000000', 'hex')
    armFakeKernel(dir, quote)
    const result = await fetchTsmQuote('ab'.repeat(32), { reportDir: dir })
    expect(result.quote).toBe(quote.toString('hex'))
    expect(result.provider).toBe('tdx_guest')
    // report directory is cleaned up
    expect(fs.readdirSync(dir)).toEqual([])
  })

  it('fails when the report directory does not exist', async () => {
    await expect(
      fetchTsmQuote('ab'.repeat(32), { reportDir: path.join(dir, 'nope') }),
    ).rejects.toThrow(TsmQuoteError)
  })

  it('fails when no quote is produced before the deadline', async () => {
    await expect(
      fetchTsmQuote('ab'.repeat(32), { reportDir: dir, timeoutMs: 100 }),
    ).rejects.toThrow(/outblob missing or empty/)
    expect(fs.readdirSync(dir)).toEqual([])
  })
})

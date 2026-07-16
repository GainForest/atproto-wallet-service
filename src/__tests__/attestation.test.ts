import * as fs from 'node:fs'
import * as http from 'node:http'
import * as os from 'node:os'
import * as path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { getAttestation } from '../attestation.js'

const NO_DSTACK = '/definitely/no/dstack.sock'
const NO_TSM_SOCK = '/definitely/no/tdx-quote.sock'
const NO_TSM_DIR = '/definitely/no/tsm/report'

describe('attestation downgrade policy', () => {
  const reportDataHex = 'ab'.repeat(32)

  it('allows explicit dev mode outside production', async () => {
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: NO_DSTACK,
        tsmQuoteSockPath: NO_TSM_SOCK,
        tsmReportDir: NO_TSM_DIR,
      }),
    ).resolves.toMatchObject({ mode: 'dev', quote: null })
  })

  it('fails closed when TEE attestation is required', async () => {
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: NO_DSTACK,
        tsmQuoteSockPath: NO_TSM_SOCK,
        tsmReportDir: NO_TSM_DIR,
        requireTee: true,
      }),
    ).rejects.toThrow(/no TEE guest agent/)
  })
})

describe('configfs-TSM fallback', () => {
  const reportDataHex = 'cd'.repeat(32)
  let dir: string
  let sock: string
  let server: http.Server

  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'attestation-tsm-test-'))
    sock = path.join(dir, 'quote.sock')
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost')
      if (url.pathname !== '/quote') {
        res.writeHead(404).end(JSON.stringify({ error: 'not found' }))
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(
        JSON.stringify({
          quote: '0400020081000000',
          provider: 'tdx_guest',
        }),
      )
    })
    await new Promise<void>((resolve) => server.listen(sock, resolve))
  })

  afterEach(async () => {
    await new Promise((resolve) => server.close(resolve))
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('uses the quote helper socket when dstack is absent', async () => {
    const result = await getAttestation({
      reportDataHex,
      dstackSockPath: NO_DSTACK,
      tsmQuoteSockPath: sock,
      tsmReportDir: NO_TSM_DIR,
    })
    expect(result.mode).toBe('tdx-tsm')
    expect(result.quote).toBe('0400020081000000')
    expect(result.provider).toBe('tdx_guest')
    expect(result.reportData).toBe(reportDataHex)
    expect(result.note).toMatch(/not operator-proof/)
  })

  it('satisfies requireTee via the helper socket', async () => {
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: NO_DSTACK,
        tsmQuoteSockPath: sock,
        tsmReportDir: NO_TSM_DIR,
        requireTee: true,
      }),
    ).resolves.toMatchObject({ mode: 'tdx-tsm' })
  })

  it('fails closed when the helper is broken and TEE is required', async () => {
    await new Promise((resolve) => server.close(resolve))
    server = http.createServer((_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'boom' }))
    })
    await new Promise<void>((resolve) => server.listen(sock, resolve))
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: NO_DSTACK,
        tsmQuoteSockPath: sock,
        tsmReportDir: NO_TSM_DIR,
        requireTee: true,
      }),
    ).rejects.toThrow(/quote failed/)
  })

  it('downgrades to dev with a note when the helper is broken outside production', async () => {
    await new Promise((resolve) => server.close(resolve))
    server = http.createServer((_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'boom' }))
    })
    await new Promise<void>((resolve) => server.listen(sock, resolve))
    const result = await getAttestation({
      reportDataHex,
      dstackSockPath: NO_DSTACK,
      tsmQuoteSockPath: sock,
      tsmReportDir: NO_TSM_DIR,
    })
    expect(result.mode).toBe('dev')
    expect(result.quote).toBeNull()
    expect(result.note).toMatch(/quote failed/)
  })

  it('uses direct configfs access when only the report dir exists', async () => {
    const reportRoot = path.join(dir, 'report')
    fs.mkdirSync(reportRoot)
    // fake kernel: populate outblob once the report dir appears
    const timer = setInterval(() => {
      const entries = fs.readdirSync(reportRoot)
      if (entries.length === 0) return
      const reportDir = path.join(reportRoot, entries[0])
      if (!fs.existsSync(path.join(reportDir, 'inblob'))) return
      fs.writeFileSync(
        path.join(reportDir, 'outblob'),
        Buffer.from('0400020081000000', 'hex'),
      )
      fs.writeFileSync(path.join(reportDir, 'provider'), 'tdx_guest\n')
      clearInterval(timer)
    }, 5)
    timer.unref()
    const result = await getAttestation({
      reportDataHex,
      dstackSockPath: NO_DSTACK,
      tsmQuoteSockPath: NO_TSM_SOCK,
      tsmReportDir: reportRoot,
    })
    expect(result.mode).toBe('tdx-tsm')
    expect(result.quote).toBe('0400020081000000')
    expect(result.provider).toBe('tdx_guest')
  })
})

import * as fs from 'node:fs'
import * as http from 'node:http'
import * as os from 'node:os'
import * as path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createTdxQuoteHelperServer } from '../tsm-quote-helper.js'

let dir: string
let reportRoot: string
let sock: string
let server: http.Server

function armFakeKernel(root: string, quote: Buffer): void {
  const timer = setInterval(() => {
    const entries = fs.readdirSync(root)
    if (entries.length === 0) return
    const reportDir = path.join(root, entries[0])
    if (!fs.existsSync(path.join(reportDir, 'inblob'))) return
    fs.writeFileSync(path.join(reportDir, 'outblob'), quote)
    fs.writeFileSync(path.join(reportDir, 'provider'), 'tdx_guest\n')
    clearInterval(timer)
  }, 5)
  timer.unref()
}

function get(pathname: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { socketPath: sock, path: pathname, method: 'GET' },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
          }),
        )
      },
    )
    req.on('error', reject)
    req.end()
  })
}

beforeEach(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsm-helper-test-'))
  reportRoot = path.join(dir, 'report')
  fs.mkdirSync(reportRoot)
  sock = path.join(dir, 'quote.sock')
  server = createTdxQuoteHelperServer({ reportDir: reportRoot })
  await new Promise<void>((resolve) => server.listen(sock, resolve))
})

afterEach(async () => {
  await new Promise((resolve) => server.close(resolve))
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('tdx quote helper server', () => {
  it('serves quotes over the unix socket', async () => {
    const quote = Buffer.from('0400020081000000', 'hex')
    armFakeKernel(reportRoot, quote)
    const res = await get(`/quote?report_data=${'ab'.repeat(32)}`)
    expect(res.status).toBe(200)
    expect(res.body.quote).toBe(quote.toString('hex'))
    expect(res.body.provider).toBe('tdx_guest')
  })

  it('rejects malformed report data', async () => {
    for (const bad of ['', 'zz', 'abc', 'ab'.repeat(65)]) {
      const res = await get(`/quote?report_data=${bad}`)
      expect(res.status).toBe(400)
    }
  })

  it('rejects unknown routes', async () => {
    const res = await get('/GetKey?path=wallet')
    expect(res.status).toBe(404)
  })

  it('returns 503 when configfs-tsm is unavailable', async () => {
    fs.rmdirSync(reportRoot)
    const res = await get(`/quote?report_data=${'ab'.repeat(32)}`)
    expect(res.status).toBe(503)
  })
})

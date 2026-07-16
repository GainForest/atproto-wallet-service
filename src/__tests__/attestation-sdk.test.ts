import { afterEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as http from 'node:http'
import * as os from 'node:os'
import * as path from 'node:path'
import { getAttestation } from '../attestation.js'

let server: http.Server | undefined
let dir: string | undefined

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()))
    server = undefined
  }
  if (dir) fs.rmSync(dir, { recursive: true, force: true })
  dir = undefined
})

describe('official dstack SDK attestation adapter', () => {
  it('returns quote, event log, and VM config from the guest agent', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstack-attestation-test-'))
    const socket = path.join(dir, 'dstack.sock')
    let requestBody: Record<string, unknown> | undefined
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (chunk: Buffer) => chunks.push(chunk))
      req.on('end', () => {
        requestBody = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        res.end(
          JSON.stringify({
            quote: 'deadbeef',
            event_log: '[]',
            report_data: requestBody?.report_data,
            vm_config: '{"cpu":4}',
          }),
        )
      })
    })
    await new Promise<void>((resolve) => server!.listen(socket, resolve))

    const reportDataHex = 'ab'.repeat(64)
    const result = await getAttestation({
      reportDataHex,
      dstackSockPath: socket,
      requireTee: true,
    })

    expect(requestBody).toEqual({ report_data: reportDataHex })
    expect(result).toEqual({
      mode: 'dstack',
      reportData: reportDataHex,
      quote: 'deadbeef',
      eventLog: '[]',
      vmConfig: '{"cpu":4}',
    })
  })
})

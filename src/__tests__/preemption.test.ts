import { afterEach, describe, expect, it } from 'vitest'
import * as http from 'node:http'
import type { AddressInfo } from 'node:net'
import { watchGcpPreemption, type PreemptionWatcher } from '../preemption.js'

let server: http.Server | undefined
let watcher: PreemptionWatcher | undefined

function startMetadata(handler: http.RequestListener): Promise<string> {
  server = http.createServer(handler)
  return new Promise((resolve) => {
    server!.listen(0, '127.0.0.1', () => {
      const { port } = server!.address() as AddressInfo
      resolve(`http://127.0.0.1:${port}`)
    })
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

afterEach(async () => {
  watcher?.stop()
  watcher = undefined
  if (server) {
    await new Promise((resolve) => server!.close(resolve))
    server = undefined
  }
})

describe('watchGcpPreemption', () => {
  it('fires onPreempted once when metadata flips to TRUE', async () => {
    const responses = ['FALSE', 'FALSE', 'TRUE', 'TRUE']
    let sawFlavor = false
    const base = await startMetadata((req, res) => {
      sawFlavor = req.headers['metadata-flavor'] === 'Google'
      res.end(responses.shift() ?? 'TRUE')
    })
    let calls = 0
    await new Promise<void>((resolve) => {
      watcher = watchGcpPreemption({
        onPreempted: () => {
          calls += 1
          resolve()
        },
        metadataBaseUrl: base,
        pollIntervalMs: 5,
      })
    })
    await sleep(30)
    expect(calls).toBe(1)
    expect(sawFlavor).toBe(true)
  })

  it('retries through transient errors before the notice arrives', async () => {
    let call = 0
    const base = await startMetadata((req, res) => {
      call += 1
      if (call === 1) {
        req.socket.destroy() // connection error on first poll
        return
      }
      res.end('TRUE')
    })
    let calls = 0
    await new Promise<void>((resolve) => {
      watcher = watchGcpPreemption({
        onPreempted: () => {
          calls += 1
          resolve()
        },
        metadataBaseUrl: base,
        pollIntervalMs: 5,
      })
    })
    expect(calls).toBe(1)
    expect(call).toBeGreaterThanOrEqual(2)
  })

  it('stop() halts polling without firing the callback', async () => {
    const base = await startMetadata((_req, res) => {
      res.end('FALSE')
    })
    let calls = 0
    watcher = watchGcpPreemption({
      onPreempted: () => {
        calls += 1
      },
      metadataBaseUrl: base,
      pollIntervalMs: 5,
    })
    await sleep(20)
    watcher.stop()
    await sleep(30)
    expect(calls).toBe(0)
  })
})

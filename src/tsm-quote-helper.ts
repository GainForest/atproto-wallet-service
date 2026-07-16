/**
 * Root-owned TDX quote helper.
 *
 * Creating a configfs-TSM report requires root (the configfs attribute
 * files are always root-owned), but the wallet service deliberately
 * runs as an unprivileged user. This tiny helper is the only privileged
 * piece: it listens on a LOCAL unix socket and turns
 *
 *   GET /quote?report_data=<hex, 1..64 bytes>
 *
 * into `{ "quote": "<hex>", "provider": "tdx_guest" }` via configfs-TSM.
 * Quote generation discloses no secrets — the only thing gated by the
 * socket permissions is the ability to make the hardware sign report
 * data, so the socket is restricted to the service's group.
 *
 * Run as root under systemd, e.g.:
 *
 *   [Service]
 *   ExecStart=/usr/bin/node /path/to/dist/tsm-quote-helper.js
 *   Environment=TDX_QUOTE_HELPER_SOCKET_GID=1001
 *
 * Env:
 *   TDX_QUOTE_HELPER_SOCK        socket path (default /run/tdx-quote.sock)
 *   TDX_QUOTE_HELPER_REPORT_DIR  configfs report dir override
 *   TDX_QUOTE_HELPER_SOCKET_GID  numeric gid granted rw on the socket
 */
import * as fs from 'node:fs'
import * as http from 'node:http'
import {
  DEFAULT_TSM_REPORT_DIR,
  fetchTsmQuote,
  tsmAvailable,
  TsmQuoteError,
} from './tsm-quote.js'

export const DEFAULT_TSM_QUOTE_SOCK = '/run/tdx-quote.sock'

const MAX_REPORT_DATA_HEX = 128 // 64 bytes

export function createTdxQuoteHelperServer(
  opts: { reportDir?: string } = {},
): http.Server {
  const reportDir = opts.reportDir ?? DEFAULT_TSM_REPORT_DIR
  return http.createServer(async (req, res) => {
    const respond = (status: number, body: unknown): void => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    try {
      const url = new URL(req.url ?? '/', 'http://localhost')
      if (req.method !== 'GET' || url.pathname !== '/quote') {
        respond(404, { error: 'not found' })
        return
      }
      const reportData = url.searchParams.get('report_data') ?? ''
      if (
        reportData.length === 0 ||
        reportData.length > MAX_REPORT_DATA_HEX ||
        !/^([0-9a-fA-F]{2})+$/.test(reportData)
      ) {
        respond(400, { error: 'report_data must be 1..64 bytes of hex' })
        return
      }
      if (!tsmAvailable(reportDir)) {
        respond(503, { error: 'configfs-tsm unavailable on this host' })
        return
      }
      const { quote, provider } = await fetchTsmQuote(reportData, {
        reportDir,
      })
      respond(200, { quote, provider })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      respond(err instanceof TsmQuoteError ? 502 : 500, { error: message })
    }
  })
}

function main(): void {
  const sockPath = process.env.TDX_QUOTE_HELPER_SOCK || DEFAULT_TSM_QUOTE_SOCK
  const reportDir =
    process.env.TDX_QUOTE_HELPER_REPORT_DIR || DEFAULT_TSM_REPORT_DIR
  const gidRaw = process.env.TDX_QUOTE_HELPER_SOCKET_GID

  if (!tsmAvailable(reportDir)) {
    // Fail fast: this helper is pointless off TDX/configfs-TSM hosts.
    console.error(`tdx-quote-helper: no configfs-tsm at ${reportDir}`)
    process.exit(1)
  }

  try {
    fs.unlinkSync(sockPath)
  } catch {
    // no stale socket
  }

  const server = createTdxQuoteHelperServer({ reportDir })
  server.listen(sockPath, () => {
    // Owner (root) + one explicit group get access; everyone else none.
    fs.chmodSync(sockPath, 0o660)
    if (gidRaw) {
      const gid = parseInt(gidRaw, 10)
      if (!Number.isSafeInteger(gid) || gid < 0) {
        console.error('tdx-quote-helper: TDX_QUOTE_HELPER_SOCKET_GID invalid')
        process.exit(1)
      }
      fs.chownSync(sockPath, 0, gid)
    }
    console.log(`tdx-quote-helper: listening on ${sockPath}`)
  })

  const shutdown = (): void => {
    server.close(() => {
      try {
        fs.unlinkSync(sockPath)
      } catch {
        // already gone
      }
      process.exit(0)
    })
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

if (require.main === module) {
  main()
}

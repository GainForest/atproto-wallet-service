/**
 * Spot/preemptible-instance preemption watcher.
 *
 * GCP signals spot preemption ~30s before termination by flipping the
 * instance metadata key `instance/preempted` to TRUE (and delivering
 * ACPI G2 soft-off, which systemd translates to SIGTERM — this watcher
 * is the belt to that suspender: it catches the notice even when the
 * process is not the one receiving the signal, e.g. under a container
 * runtime that swallows it).
 *
 * The watcher polls the LOCAL metadata server (link-local, never the
 * public network) and invokes `onPreempted` exactly once, after which
 * the caller is expected to run its controlled shutdown: drain, WAL
 * checkpoint, store close, seed wipe. Polling is plain GET on a short
 * interval rather than a hanging `wait_for_change` request so behavior
 * is deterministic when the instance starts out already-preempted.
 *
 * Entrypoint-only module — not part of the enclave core.
 */
import { createLogger } from './lib/shared.js'

const logger = createLogger('preemption-watcher')

const DEFAULT_METADATA_BASE = 'http://metadata.google.internal'
const PREEMPTED_PATH = '/computeMetadata/v1/instance/preempted'

export interface PreemptionWatcher {
  /** Stop watching. Safe to call multiple times. */
  stop(): void
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms)
    t.unref?.()
  })
}

export function watchGcpPreemption(opts: {
  onPreempted: () => void
  /** Override for tests. Default: the GCP metadata server. */
  metadataBaseUrl?: string
  /** Poll interval in ms. Default 1000 — well inside the ~30s notice. */
  pollIntervalMs?: number
  /** Per-request timeout in ms. Default 5000. */
  requestTimeoutMs?: number
}): PreemptionWatcher {
  const base = opts.metadataBaseUrl ?? DEFAULT_METADATA_BASE
  const pollIntervalMs = opts.pollIntervalMs ?? 1000
  const requestTimeoutMs = opts.requestTimeoutMs ?? 5000
  const url = `${base}${PREEMPTED_PATH}`
  let stopped = false

  const run = async (): Promise<void> => {
    while (!stopped) {
      try {
        const res = await fetch(url, {
          headers: { 'Metadata-Flavor': 'Google' },
          signal: AbortSignal.timeout(requestTimeoutMs),
        })
        if (res.ok) {
          const text = (await res.text()).trim().toUpperCase()
          if (text === 'TRUE') {
            if (!stopped) {
              stopped = true
              logger.warn('spot preemption notice received')
              opts.onPreempted()
            }
            return
          }
        }
      } catch (err) {
        if (stopped) return
        logger.debug({ err }, 'preemption metadata poll failed; retrying')
      }
      await sleep(pollIntervalMs)
    }
  }
  void run()

  return {
    stop() {
      stopped = true
    },
  }
}

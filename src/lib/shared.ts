/**
 * Small utilities vendored from tPDS's @certified-app/shared so this
 * service has zero workspace dependencies.
 */
import * as crypto from 'node:crypto'
import pino from 'pino'

function defaultLogLevel(): string {
  switch (process.env.NODE_ENV) {
    case 'development':
      return 'debug'
    case 'test':
      return 'silent'
    default:
      return 'info'
  }
}

const LOG_LEVEL = process.env.LOG_LEVEL || defaultLogLevel()

export function createLogger(name: string): pino.Logger {
  return pino({
    name,
    level: LOG_LEVEL,
    ...(process.env.NODE_ENV === 'development'
      ? {
          transport: { target: 'pino/file', options: { destination: 1 } },
          formatters: { level: (label: string) => ({ level: label }) },
        }
      : {}),
  })
}

/** Constant-time string comparison that never throws on length mismatch. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    const dummy = Buffer.alloc(a.length)
    crypto.timingSafeEqual(dummy, dummy)
    return false
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

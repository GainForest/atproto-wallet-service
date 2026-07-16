/**
 * Optimistic repository contract for sealed per-DID wallet state.
 *
 * Implementations treat `SealedState` as opaque bytes. Decryption,
 * authorization, nonce checks, and state transitions happen inside the
 * wallet service. Revisions are adapter-owned opaque tokens used only
 * for compare-and-swap.
 */
import type { SealedState } from './state.js'

export interface StateSnapshot {
  sealed: SealedState
  revision: string
}

export type CreateResult = 'created' | 'exists'
export type CasResult = 'updated' | 'conflict' | 'missing'

export interface WalletStateRepository {
  load(did: string): Promise<StateSnapshot | null>
  create(did: string, sealed: SealedState): Promise<CreateResult>
  compareAndSwap(
    did: string,
    expectedRevision: string,
    sealed: SealedState,
  ): Promise<CasResult>
  close?(): void | Promise<void>
}

function cloneSealed(sealed: SealedState): SealedState {
  return { ...sealed }
}

/** In-memory CAS adapter for deterministic state-machine tests. */
export class MemoryWalletStateRepository implements WalletStateRepository {
  private readonly rows = new Map<
    string,
    { sealed: SealedState; revision: number }
  >()

  async load(did: string): Promise<StateSnapshot | null> {
    const row = this.rows.get(did)
    return row
      ? { sealed: cloneSealed(row.sealed), revision: String(row.revision) }
      : null
  }

  async create(did: string, sealed: SealedState): Promise<CreateResult> {
    if (this.rows.has(did)) return 'exists'
    this.rows.set(did, { sealed: cloneSealed(sealed), revision: 1 })
    return 'created'
  }

  async compareAndSwap(
    did: string,
    expectedRevision: string,
    sealed: SealedState,
  ): Promise<CasResult> {
    const row = this.rows.get(did)
    if (!row) return 'missing'
    if (String(row.revision) !== expectedRevision) return 'conflict'
    this.rows.set(did, {
      sealed: cloneSealed(sealed),
      revision: row.revision + 1,
    })
    return 'updated'
  }
}

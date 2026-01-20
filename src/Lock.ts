import {
  Hash,
  LockingScript,
  PrivateKey,
  Script,
  ScriptTemplate,
  Transaction,
  TransactionSignature,
  UnlockingScript,
  Utils
} from '@bsv/sdk'

/**
 * Simple Lock prefix - the first part of the locking script before the PKH
 */
const LOCK_PREFIX = '20d37f4de0d1c735b4d51a5572df0f3d9104d1d9e99db8694fdd1b1a92e1f0dce1757601687f76a9'

/**
 * Simple Lock suffix - the part after the "until" block height
 */
const LOCK_SUFFIX = '88ac7e7601207f75a9011488'

/**
 * Decoded Lock script data
 */
export interface LockDecoded {
  /** The public key hash (20 bytes) */
  pkh: number[]
  /** The block height until which the coins are locked */
  until: number
}

/**
 * Lock Script Template for time-locked coins.
 *
 * This is the "simple lock" format used by 1Sat ecosystem wallets.
 * Coins can only be spent after the specified block height.
 *
 * The script structure is:
 * PREFIX (constant) + PKH (20 bytes) + UNTIL (block height) + SUFFIX (constant)
 *
 * Unlocking requires:
 * - tx.lockTime >= until
 * - input.sequence = 0 (enables nLockTime checking)
 */
export default class Lock implements ScriptTemplate {
  /**
   * Creates a Lock locking script that time-locks coins until a specific block height.
   *
   * @param address - The BSV address (base58check encoded) that can unlock after expiry
   * @param until - The block height until which the coins are locked
   * @returns The Lock locking script
   */
  lock (address: string, until: number): LockingScript {
    const pkh = Utils.fromBase58Check(address).data as number[]
    return new LockingScript([
      ...Script.fromHex(LOCK_PREFIX).chunks,
      { op: 20, data: pkh },
      ...Lock.encodeBlockHeight(until),
      ...Script.fromHex(LOCK_SUFFIX).chunks
    ])
  }

  /**
   * Creates an unlocking script template for spending a Lock output.
   *
   * IMPORTANT: The transaction using this unlock must have:
   * - tx.lockTime >= the lock's "until" value
   * - input.sequence = 0 (to enable nLockTime checking)
   *
   * @param privateKey - The private key corresponding to the locked address
   * @param signOutputs - Which outputs to sign ('all', 'none', 'single')
   * @param anyoneCanPay - Whether to use SIGHASH_ANYONECANPAY
   * @param sourceSatoshis - Optional source satoshis (for signing without sourceTransaction)
   * @param lockingScript - Optional locking script (for signing without sourceTransaction)
   * @returns An object with sign and estimateLength functions
   */
  unlock (
    privateKey: PrivateKey,
    signOutputs: 'all' | 'none' | 'single' = 'all',
    anyoneCanPay = false,
    sourceSatoshis?: number,
    lockingScript?: Script
  ): {
      sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>
      estimateLength: () => Promise<number>
    } {
    return {
      sign: async (tx: Transaction, inputIndex: number): Promise<UnlockingScript> => {
        let signatureScope = TransactionSignature.SIGHASH_FORKID
        if (signOutputs === 'all') {
          signatureScope |= TransactionSignature.SIGHASH_ALL
        } else if (signOutputs === 'none') {
          signatureScope |= TransactionSignature.SIGHASH_NONE
        } else if (signOutputs === 'single') {
          signatureScope |= TransactionSignature.SIGHASH_SINGLE
        }
        if (anyoneCanPay) {
          signatureScope |= TransactionSignature.SIGHASH_ANYONECANPAY
        }

        const input = tx.inputs[inputIndex]
        const otherInputs = tx.inputs.filter((_, index) => index !== inputIndex)
        const sourceTXID = input.sourceTXID ?? input.sourceTransaction?.id('hex')

        if (!sourceTXID) {
          throw new Error('The input sourceTXID or sourceTransaction is required for transaction signing.')
        }

        const sats = sourceSatoshis ?? input.sourceTransaction?.outputs[input.sourceOutputIndex]?.satoshis ?? 0
        const subscript =
          lockingScript ?? input.sourceTransaction?.outputs[input.sourceOutputIndex]?.lockingScript ?? new Script()

        const preimage = TransactionSignature.format({
          sourceTXID,
          sourceOutputIndex: input.sourceOutputIndex,
          sourceSatoshis: sats,
          transactionVersion: tx.version,
          otherInputs,
          inputIndex,
          outputs: tx.outputs,
          inputSequence: input.sequence ?? 0,
          subscript,
          lockTime: tx.lockTime,
          scope: signatureScope
        })

        const rawSignature = privateKey.sign(Hash.sha256(preimage))
        const sig = new TransactionSignature(rawSignature.r, rawSignature.s, signatureScope)
        const pubKey = privateKey.toPublicKey()

        return new UnlockingScript([
          { op: sig.toChecksigFormat().length, data: sig.toChecksigFormat() },
          { op: 33, data: pubKey.encode(true) as number[] }
        ])
      },
      estimateLength: async (): Promise<number> => {
        // Signature (~71-73 bytes) + pubkey (33 bytes) + push opcodes (2 bytes)
        return 108
      }
    }
  }

  /**
   * Decodes a Lock script to extract the PKH and until values.
   *
   * @param script - The script to decode
   * @returns The decoded lock data (pkh and until)
   * @throws Error if the script is not a valid Lock script
   */
  static decode (script: Script): LockDecoded {
    if (!Lock.isLock(script)) {
      throw new Error('Script is not a valid Lock script')
    }

    const hex = script.toHex()
    // Script structure in hex:
    // - LOCK_PREFIX: 78 hex chars (39 bytes)
    // - PKH opcode: 2 hex chars (0x14 = push 20 bytes)
    // - PKH data: 40 hex chars (20 bytes)
    // - UNTIL opcode + data: variable
    // - LOCK_SUFFIX: 24 hex chars (12 bytes)

    const pkhOpcodeStart = LOCK_PREFIX.length // 78
    const pkhDataStart = pkhOpcodeStart + 2 // 80 (skip the 0x14 opcode)
    const pkhHex = hex.slice(pkhDataStart, pkhDataStart + 40)
    const pkh = Utils.toArray(pkhHex, 'hex')

    // Until starts after PKH data, ends before suffix
    const untilStart = pkhDataStart + 40 // 120
    const suffixStart = hex.length - LOCK_SUFFIX.length
    const untilHex = hex.slice(untilStart, suffixStart)

    // Parse the until value from minimal encoding
    const until = Lock.decodeBlockHeight(untilHex)

    return { pkh, until }
  }

  /**
   * Checks if a script is a Lock script.
   *
   * @param script - The script to check
   * @returns True if the script is a Lock script
   */
  static isLock (script: Script): boolean {
    const hex = script.toHex()
    return hex.startsWith(LOCK_PREFIX) && hex.endsWith(LOCK_SUFFIX)
  }

  /**
   * Encodes a block height as script chunks using minimal encoding.
   */
  private static encodeBlockHeight (height: number): Array<{ op: number, data?: number[] }> {
    if (height === 0) {
      return [{ op: 0 }] // OP_0
    }
    if (height >= 1 && height <= 16) {
      return [{ op: 0x50 + height }] // OP_1 through OP_16
    }
    if (height === -1) {
      return [{ op: 0x4f }] // OP_1NEGATE
    }

    // Convert to little-endian bytes with sign handling
    const bytes: number[] = []
    let n = height
    const negative = n < 0
    if (negative) n = -n

    while (n > 0) {
      bytes.push(n & 0xff)
      n >>= 8
    }

    // Handle sign bit
    if (bytes[bytes.length - 1] & 0x80) {
      bytes.push(negative ? 0x80 : 0x00)
    } else if (negative) {
      bytes[bytes.length - 1] |= 0x80
    }

    return [{ op: bytes.length, data: bytes }]
  }

  /**
   * Decodes a block height from hex-encoded script number.
   */
  private static decodeBlockHeight (hex: string): number {
    if (hex.length === 0) return 0

    // First byte is the length/opcode
    const opcode = parseInt(hex.slice(0, 2), 16)

    // OP_0
    if (opcode === 0) return 0

    // OP_1 through OP_16
    if (opcode >= 0x51 && opcode <= 0x60) {
      return opcode - 0x50
    }

    // OP_1NEGATE
    if (opcode === 0x4f) return -1

    // Data push - opcode is the length
    const dataHex = hex.slice(2, 2 + opcode * 2)
    const bytes = Utils.toArray(dataHex, 'hex')

    if (bytes.length === 0) return 0

    // Convert from little-endian with sign handling
    let result = 0
    for (let i = 0; i < bytes.length; i++) {
      result |= bytes[i] << (8 * i)
    }

    // Handle negative numbers
    if (bytes[bytes.length - 1] & 0x80) {
      result &= ~(0x80 << (8 * (bytes.length - 1)))
      result = -result
    }

    return result
  }
}

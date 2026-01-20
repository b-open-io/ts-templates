import { PrivateKey, Transaction, P2PKH } from '@bsv/sdk'
import Lock from '../Lock'

describe('Lock script', () => {
  // Test address (mainnet)
  const testAddress = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
  const testUntil = 800000

  it('creates a Lock locking script', () => {
    const lock = new Lock()
    const script = lock.lock(testAddress, testUntil)

    expect(script).toBeDefined()
    expect(script.toHex()).toBeTruthy()
  })

  it('isLock returns true for Lock scripts', () => {
    const lock = new Lock()
    const script = lock.lock(testAddress, testUntil)

    expect(Lock.isLock(script)).toBe(true)
  })

  it('isLock returns false for non-Lock scripts', () => {
    const p2pkh = new P2PKH().lock(testAddress)
    expect(Lock.isLock(p2pkh)).toBe(false)
  })

  it('decode extracts correct data from Lock script', () => {
    const lock = new Lock()
    const script = lock.lock(testAddress, testUntil)

    const decoded = Lock.decode(script)
    expect(decoded).toBeDefined()
    expect(decoded.until).toBe(testUntil)
    // PKH should be 20 bytes
    expect(decoded.pkh.length).toBe(20)
  })

  it('roundtrips lock -> decode for various block heights', () => {
    const heights = [0, 1, 15, 16, 127, 128, 255, 256, 65535, 500000, 800000, 2147483647]
    const lock = new Lock()

    for (const height of heights) {
      const script = lock.lock(testAddress, height)
      expect(Lock.isLock(script)).toBe(true)

      const decoded = Lock.decode(script)
      expect(decoded.until).toBe(height)
    }
  })

  it('unlock returns sign and estimateLength functions', () => {
    const privateKey = PrivateKey.fromRandom()
    const lock = new Lock()
    const template = lock.unlock(privateKey)

    expect(typeof template.sign).toBe('function')
    expect(typeof template.estimateLength).toBe('function')
  })

  it('estimateLength returns reasonable value', async () => {
    const privateKey = PrivateKey.fromRandom()
    const lock = new Lock()
    const template = lock.unlock(privateKey)

    const length = await template.estimateLength()
    // Signature (~71-73) + pubkey (33) + push opcodes (2) = ~106-108
    expect(length).toBeGreaterThanOrEqual(100)
    expect(length).toBeLessThanOrEqual(120)
  })

  it('creates unlocking script with valid signature', async () => {
    const privateKey = PrivateKey.fromRandom()
    const address = privateKey.toPublicKey().toAddress()
    const lockHeight = 800000
    const satoshis = 10000

    const lock = new Lock()
    const lockScript = lock.lock(address, lockHeight)

    // Create a mock transaction with the locked output
    const sourceTx = new Transaction()
    sourceTx.addOutput({
      lockingScript: lockScript,
      satoshis
    })

    // Create spending transaction
    const tx = new Transaction()
    tx.lockTime = lockHeight // Must be >= until
    tx.addInput({
      sourceTransaction: sourceTx,
      sourceOutputIndex: 0,
      sequence: 0 // Must be 0 to enable lockTime
    })
    tx.addOutput({
      lockingScript: new P2PKH().lock(address),
      satoshis: satoshis - 200 // minus fee
    })

    // Create unlock template and sign
    const unlockTemplate = lock.unlock(privateKey, 'all', false, satoshis, lockScript)
    const unlockScript = await unlockTemplate.sign(tx, 0)

    expect(unlockScript).toBeDefined()
    // Unlocking script should have signature + pubkey
    expect(unlockScript.chunks.length).toBe(2)
  })
})

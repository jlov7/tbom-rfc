# Performance Characterization

## Complexity Analysis

The core operations of TBOM verification are **canonicalization**, **hashing**, and **signature verification**.

### 1. Canonicalization (RFC 8785)
- **Complexity**: $O(N \log N)$ where $N$ is the size of the JSON object (due to key sorting).
- **Impact**: For typical tool definitions (1KB - 100KB), this is negligible (< 10ms).
- **Scaling**: Linear-logarithmic with respect to the number of tools and fields.

### 2. Hashing (SHA-256)
- **Complexity**: $O(N)$ where $N$ is the byte length of the canonicalized input.
- **Impact**: extremely fast on modern hardware (GB/s range).
- **Optimization**: Hashing is performed on the *canonical* representation, which ensures stability.

### 3. Signature Verification (Ed25519)
- **Complexity**: Constant time $O(1)$ for the verification operation itself (fixed number of curve operations).
- **Impact**: < 1ms per signature.
- **Throughput**: Thousands of verifications per second on standard CPUs.

## Indicative Performance (Non-Normative)

No formal benchmark suite is published yet. The measurements below are **expected
to be dominated by JSON canonicalization and signature verification**, and for
typical tool definitions (1KB-100KB) should be small relative to network or model
latency. Performance will vary by CPU, JSON structure, and runtime.

## Scalability Considerations

- **Verification Latency**: The drift detection algorithm runs at connect time. With sub-millisecond overhead per tool, checking 100 tools adds < 100ms latency, which is acceptable for the user experience.
- **Registry Load**: Registries serve static JSON files. These can be heavily cached (CDN), ensuring high availability and low latency.
- **Storage**: TBOM files are small (typically < 50KB even for large toolsets), adding negligible storage overhead.

# Hardware Dispatch

QuantLib includes a production-safe hardware dispatcher for selecting CPU, vector, and GPU backend paths. Provider-gated acceleration must be verified before deployment.


The dispatcher is intentionally conservative:

- `cpu-generic` is always available and remains the correctness baseline.
- `cpu-native` is enabled through `QUANTLIB_ENABLE_NATIVE`.
- AES-NI, AVX2, AVX-512, NEON, CUDA, and OpenCL are exposed as backend capabilities when applicable.
- GPU/vector hooks never silently replace vetted crypto providers.
- Unsupported accelerators fail closed when strict acceleration is requested.

Inspect support:

```bash
quantlib-inspect --hardware
```

The dispatcher is designed for high-volume workloads such as batch hashing, batch verification, protocol frame processing, and future PQ batch operations.

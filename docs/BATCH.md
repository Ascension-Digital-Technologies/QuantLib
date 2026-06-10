# Batch Crypto

QuantLib includes batch crypto APIs for high-throughput workloads where amortized dispatch and routing matter.


Current APIs:

```cpp
quantlib::batch::sha256(messages);
quantlib::batch::verify_signatures(items);
```

`batch::sha256` is fully functional and routes through the hardware/GPU dispatcher while preserving the exact same digest outputs as `quantlib::hash::sha256`.

`batch::verify_signatures` is a fail-closed API boundary. It exists so integrations can adopt the stable interface now, but it returns `unsupported_algorithm` until a vetted provider-specific batch verifier is wired in.

Inspect support:

```bash
quantlib-inspect --batch
```

Benchmark support:

```bash
quantlib-bench
```

The benchmark now reports both one-at-a-time SHA-256 throughput and batch SHA-256 throughput.

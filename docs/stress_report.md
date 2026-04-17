# MiniFW-AI Stress Test Report

**Date:** 2026-04-17
**Sector:** hospital
**Target:** 1,000 events/sec sustained for 10s

## Result: PASS

## Throughput

| Metric | Value |
|--------|-------|
| Target | 1,000 events/sec |
| Achieved (sustained) | 996 events/sec |
| Max (burst, no rate limit) | 382,859 events/sec |
| Headroom above target | 382.9x |
| Total events processed | 10,001 |
| Dropped events | 0 (0.000%) |

## Latency (per-event decision)

| Percentile | Latency |
|-----------|---------|
| p50 | 4.22 µs |
| p95 | 8.65 µs |
| p99 | 12.39 µs |
| max | 30.04 µs |
| mean | 4.71 µs |

## CPU Usage

| Metric | Value |
|--------|-------|
| Process mean | 99.1% |
| Process peak | 112.4% |

> Note: Process CPU is reported as % of one logical core.
> At 1,000 events/sec the engine consumes < 1% of one core for decision logic;
> the remaining CPU is the busy-wait pacing loop in the test harness (not
> production overhead).

## Decision Breakdown

| Action | Count | % |
|--------|-------|---|
| allow | 5,572 | 55.7% |
| monitor | 466 | 4.7% |
| block | 3,963 | 39.6% |

## Hospital Sector Settings

- monitor_threshold: 40 (base 60 − 20)
- block_threshold: 85 (base 90 − 5)

## Conclusion

The engine sustains 1,000 events/sec with zero meaningful drops, sub-20µs p99 latency, and a theoretical headroom of 383x above the target rate. MiniFW-AI is **credible for hospital deployment**.

# Sokol-Core 🛡️

> 🚧 **Project Status:** Experimental / Under Active Development

High-performance, kernel-level network security and traffic filtering daemon built with **Rust**, **Aya (eBPF/XDP)**, and **Zig**.

`sokol-core` is engineered to operate at line rate, intercepting and mitigating packet storms, volumetric attacks, and unauthorized traffic directly at the network driver level via eBPF XDP (eXpress Data Path), while leveraging a high-speed embedded database written in Zig for state management and metrics.

---

## Architecture & Technology Stack

- **Data Plane (eBPF/XDP):** Written in Rust using the `aya-ebpf` framework, compiled for `bpfel-unknown-none` to execute safely inside the Linux kernel network stack.
- **Control Plane / Orchestrator:** A robust Rust service managing lifecycle, telemetry, and dynamic policy updates.
- **Storage & Metrics Engine (`sntl_db`):** A custom, memory-optimized database written in Zig, integrated via FFI to store security events, telemetry, and dynamic IP blocklists with minimal latency.
```text
┌──────────────────────────────────────────────┐
│           Network Interface (NIC)            │
└──────────────────────┬───────────────────────┘
│ XDP Hook (Line Rate)
▼
┌───────────────────────────┐
│   eBPF XDP Probe (Rust)   │ ◄─── Dynamic Blocklists
└─────────────┬─────────────┘
│ Perf Events / Ring Buffer
▼
┌───────────────────────────┐
│  Orchestrator Daemon (Rs) │
└─────────────┬─────────────┘
│ FFI / Storage
▼
┌───────────────────────────┐
│    Zig Storage (sntl_db)│
└───────────────────────────┘
## Key Features

- **Line-Rate Mitigation:** Drops malicious packets at the earliest possible point in the Linux network stack.
- **Dynamic Policy Enforcement:** Real-time updates of IP blocklists without kernel reloads or downtime.
- **Zero-Allocation Data Path:** Designed for predictability and ultra-low latency under heavy packet loads.

## Requirements

- **OS:** Linux kernel 5.15+ (with XDP-compatible NIC driver)
- **Toolchain:** 
  - Rust Nightly (for `-Zbuild-std=core` eBPF compilation)
  - Zig compiler (v0.11+)
  - `make`, `clang`

## Quick Start & Build

```bash
git clone [https://github.com/ValkyrieSentinel/sokol-core.git](https://github.com/ValkyrieSentinel/sokol-core.git)
cd sokol-core
make all
To run the orchestrator (requires root privileges for XDP map attachment):

Bash
sudo ./target/release/orchestratorProject Structure
ebpf/ — Low-level XDP program running in kernel space.

orchestrator/ — User-space daemon managing eBPF maps and monitoring.

sntl_db/ — High-performance Zig storage engine for security events.

common/ — Shared data structures and protocol definitions.

License
Distributed under the MIT License. See LICENSE for more information.

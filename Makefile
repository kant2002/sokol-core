.PHONY: all db ebpf orchestrator clean

all: db ebpf orchestrator

db:
	@echo "[+] Building sntl_db (Zig Engine)..."
	cd sntl_db && zig build -Doptimize=ReleaseSafe

 ebpf:
	@echo "[+] Building eBPF XDP Probe..."
	cd ebpf && PATH="$$HOME/.cargo/bin:$$PATH" cargo +nightly build --target bpfel-unknown-none --release -Zbuild-std=core
	mkdir -p target/bpfel-unknown-none/release
	find ebpf/target/bpfel-unknown-none/release -maxdepth 1 -type f -exec cp {} target/bpfel-unknown-none/release/ \;

orchestrator: db ebpf
	@echo "[+] Building Sokol Orchestrator & Dashboard..."
	cd orchestrator && cargo build --release

clean:
	@echo "[-] Cleaning build artifacts..."
	rm -rf sntl_db/zig-out sntl_db/.zig-cache
	cd ebpf && cargo clean
	cd orchestrator && cargo clean
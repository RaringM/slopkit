(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const VERSION = 1;
    const existing = NS.ElfLoaderJitLifecycle;
    if (existing && existing.installed) {
        if (typeof module !== "undefined" && module.exports)
            module.exports = existing;
        return;
    }
    if (typeof NS.ElfLoader !== "function")
        throw new Error("elf-loader JIT lifecycle requires ElfLoader");

    const hasOwn = (object, property) =>
        Object.prototype.hasOwnProperty.call(object, property);
    const restoreProperty = (object, property, owned, descriptor) => {
        if (owned) Object.defineProperty(object, property, descriptor);
        else delete object[property];
    };
    const errorMessage = (error) => error && typeof error.message === "string"
        ? error.message : String(error);

    function install() {
        if (api.installed) return api;
        const prototype = NS.ElfLoader.prototype;
        const originalMapImage = prototype.mapImage;
        if (typeof originalMapImage !== "function")
            throw new Error("elf-loader mapImage is unavailable");

        prototype.mapImage = function mapImageWithJitFdLifecycle(image) {
            const kernel = this.kernel;
            if (!kernel || typeof kernel.alloc !== "function"
                || !this.switcher || typeof this.switcher.run !== "function")
                throw new Error("elf-loader JIT lifecycle dependencies are unavailable");

            const allocOwned = hasOwn(kernel, "alloc");
            const allocDescriptor = allocOwned
                ? Object.getOwnPropertyDescriptor(kernel, "alloc") : null;
            const originalAlloc = kernel.alloc;
            const captures = [];
            let primaryError = null;
            let result;

            kernel.alloc = function trackedAlloc(size, alignment, label) {
                const buffer = originalAlloc.call(this, size, alignment, label);
                if (label !== "elf-jit-fds") return buffer;
                if (!buffer || typeof buffer.get32 !== "function")
                    throw new Error("JIT descriptor buffer is invalid");
                if (captures.length)
                    throw new Error("multiple JIT descriptor buffers were allocated");

                const get32Owned = hasOwn(buffer, "get32");
                const get32Descriptor = get32Owned
                    ? Object.getOwnPropertyDescriptor(buffer, "get32") : null;
                const originalGet32 = buffer.get32;
                const capture = { buffer, get32Owned, get32Descriptor,
                    originalGet32, executeFd: -1, writeFd: -1, reads: 0 };
                buffer.get32 = function trackedGet32(offset) {
                    const value = originalGet32.call(this, offset);
                    if (offset !== 0) return value;
                    const descriptor = value | 0;
                    if (capture.reads === 0) capture.executeFd = descriptor;
                    else if (capture.reads === 1) {
                        capture.writeFd = descriptor;
                        if (descriptor >= 0 && descriptor === capture.executeFd)
                            throw new Error("identical JIT descriptors");
                    } else {
                        throw new Error("unexpected JIT descriptor read");
                    }
                    capture.reads++;
                    return value;
                };
                captures.push(capture);
                return buffer;
            };

            try {
                result = originalMapImage.call(this, image);
            } catch (error) {
                primaryError = error;
            } finally {
                restoreProperty(kernel, "alloc", allocOwned, allocDescriptor);
                for (const capture of captures) {
                    restoreProperty(capture.buffer, "get32", capture.get32Owned,
                        capture.get32Descriptor);
                }
            }

            const capture = captures[0] || { executeFd: -1, writeFd: -1, reads: 0 };
            const closeOrder = [];
            for (const descriptor of [capture.writeFd, capture.executeFd]) {
                if (descriptor >= 0 && !closeOrder.includes(descriptor))
                    closeOrder.push(descriptor);
            }
            const cleanupFailures = [];
            let cleanupUnsafe = false;
            if (closeOrder.length) {
                try {
                    this.switcher.run(() => {
                        for (const descriptor of closeOrder) {
                            try {
                                const closeResult = this.bridge.callOffsetI32(
                                    "native.exports.close", [descriptor]);
                                if (closeResult !== 0)
                                    cleanupFailures.push(`close(${descriptor})=${closeResult}`);
                            } catch (error) {
                                cleanupFailures.push(`close(${descriptor}): `
                                    + errorMessage(error));
                            }
                        }
                    });
                } catch (error) {
                    cleanupFailures.push("sysent cleanup: " + errorMessage(error));
                    cleanupUnsafe = error?.rollbackVerified === false;
                }
            }

            if (!primaryError && (captures.length !== 1 || capture.reads !== 2
                || capture.executeFd < 0 || capture.writeFd < 0
                || capture.executeFd === capture.writeFd)) {
                primaryError = new Error("JIT descriptor lifecycle was incomplete");
            }
            if (cleanupFailures.length) {
                const prefix = primaryError ? errorMessage(primaryError) + "; " : "";
                primaryError = new Error(prefix + "JIT descriptor cleanup failed: "
                    + cleanupFailures.join(", "));
            }
            if (cleanupUnsafe) {
                primaryError.rollbackVerified = false;
                primaryError.rebootRequired = true;
            }
            if (primaryError) throw primaryError;

            return result;
        };

        api.originalMapImage = originalMapImage;
        api.wrappedMapImage = prototype.mapImage;
        api.installed = true;
        return api;
    }

    const api = { version: VERSION, installed: false, install };
    NS.ElfLoaderJitLifecycle = api;
    install();
    if (typeof module !== "undefined" && module.exports)
        module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);

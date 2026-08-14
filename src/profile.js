(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const FULL_MODES = new Set(["elf-loader", "full"]);
    const EXPLOITS = new Set(["poops", "lapse", "p2jb"]);
    const QUALIFICATION_STATUSES = new Set(["unsupported", "supported"]);
    const RUNTIME_CATALOG = "runtime";
    const LAPSE_ENGINE_REVISION = "lapse-profiled-r13-reclaim-gated";
    const P2JB_ENGINE_REVISION = "p2jb-profiled-topology-preflight";
    const SLOPKIT_ATTESTATION_KIND = "slopkit-live-v2";
    const SLOPKIT_ATTESTATION_REVISION =
        "6b9309f52e7d1fddf9eb913993a80b36fb58a6f3";
    const SLOPKIT_ATTESTATION_MAIN_SHA256 =
        "369c7dc279014dee7515fbceefe4f4d6c24cd4183f8e5d69ec4fccde98c151f9";
    const SLOPKIT_ATTESTATION_CORE_SHA256 =
        "c3c11d24c14bfc2b69eca17273229c3512f3fb4e354a68948eccd3c61dede686";
    const SLOPKIT_ATTESTATION_PINS = Object.freeze({
        "09.00": Object.freeze({ family: "09.40",
            tableSha256: "37640487c81dbd9ffb55a17a496c045afb32c18ba3a3185a52fd045130f5f75a",
            libkernelSha256: "8fc1a74fe9932207ada1b3ca1f249d444cc5f257e608052f118cc266fb4e8c75",
            libkernelSize: 527180,
            libcSha256: "e8f1575464d312c9d0607e3393267fa594a04e6c8fbc1f63d89f71e671770413",
            libcSize: 2041544, codeLimit: 0x33c18c8,
            kernelSlot: 0x33c18c8, kernelExport: 0x6d1d0,
            libcSlot: 0x33c3ec0, libcExport: 0x14b90 }),
        "09.20": Object.freeze({ family: "09.40",
            tableSha256: "fdd7aef45b6a7726a84251918e29499ef9d981a961af3b4f3585cf381ece3f66",
            libkernelSha256: "d40715e17a0dd473c535654d10c5193630209bb46dba3dffd4498499a2965ffb",
            libkernelSize: 527180,
            libcSha256: "fb2341e59d6302aa04eecab607ca98cff3c488c91cfb87bbd4ebe07d969f5588",
            libcSize: 2041544, codeLimit: 0x33c18c8,
            kernelSlot: 0x33c18c8, kernelExport: 0x6d1d0,
            libcSlot: 0x33c3ec0, libcExport: 0x14b90 }),
        "09.60": Object.freeze({ family: "09.40",
            tableSha256: "15997e22d5ac6387e1fc8abf28d1cc5982283bccb2084acc7995129387a5a037",
            libkernelSha256: "c457130c3a13e577860d16a82fbac3be79b1bf83051bc584d7a9dbba13af873f",
            libkernelSize: 527180,
            libcSha256: "8df22f28daaddb6053989e3d558ebcde170be7d485cacd9614ee28dad35b15f8",
            libcSize: 2041544, codeLimit: 0x33c18d8,
            kernelSlot: 0x33c18d8, kernelExport: 0x6d1d0,
            libcSlot: 0x33c3ed0, libcExport: 0x14b90 }),
        "10.20": Object.freeze({ family: "10.01",
            tableSha256: "c25371b79948034a26ca04e86fd2784e9c284e2db267384a6ff991113e8c7986",
            libkernelSha256: "f5fc6ba256bf2db239db6889f207cd9243aafe4050fd2e110d5a00a68536d930",
            libkernelSize: 527132,
            libcSha256: "84477cc9f3c81729fef2650e7567d38d743c2f81b4be5f8992e6230bbfd4f600",
            libcSize: 2041976, codeLimit: 0x35cd6b8,
            kernelSlot: 0x35cd6b8, kernelExport: 0x6d1d0,
            libcSlot: 0x35cfca8, libcExport: 0x15170 }),
        "10.40": Object.freeze({ family: "10.01",
            tableSha256: "8d0a6108087fd30716526a84d69f37861571d72199bcd9f099ebd1d5d6276f01",
            libkernelSha256: "ceb47aac5bd3cfe384bdf2279315363a55a5e176d3ac22df71378a4f97447db7",
            libkernelSize: 527132,
            libcSha256: "e35c361f57362c007e63f8435ec7515a354191bc970426df93fcc62937b4af58",
            libcSize: 2041976, codeLimit: 0x35cd6b8,
            kernelSlot: 0x35cd6b8, kernelExport: 0x6d1d0,
            libcSlot: 0x35cfca8, libcExport: 0x15170 }),
        "10.60": Object.freeze({ family: "10.01",
            tableSha256: "4e50c8c583a27d8e53e66ce077e1c3d27c3e8b96536132059c302c003f0bc582",
            libkernelSha256: "d3d0d989299c762bf512af64cbf921dd4c416cb9f2f05b4212392a977bb747d6",
            libkernelSize: 527132,
            libcSha256: "3cf41503fd72d21c4d498a5a043a93cfc7737c446b767528c6d8d0cee440ce04",
            libcSize: 2041976, codeLimit: 0x35cd6b8,
            kernelSlot: 0x35cd6b8, kernelExport: 0x6d1d0,
            libcSlot: 0x35cfca8, libcExport: 0x15170 }),
        "11.20": Object.freeze({ family: "11.60",
            tableSha256: "9bad61a2ecb71cb0bac6855d1f47b6636e73c5efb84909588ce3ee99d77fe5c8",
            libkernelSha256: "002aa8a7f47d40ca41eb0f95f88f14479dd6963658c0aac9000f4ab49e47adf5",
            libkernelSize: 527420,
            libcSha256: "f21c17031aed62ca8ad9266ee565d2b6a736bbaa7e455fff1378388b2941849e",
            libcSize: 2059464, codeLimit: 0x34f5718,
            kernelSlot: 0x34f5718, kernelExport: 0x6d1d0,
            libcSlot: 0x34f7da0, libcExport: 0x14e80 }),
        "11.40": Object.freeze({ family: "11.60",
            tableSha256: "8c0c8a83802338bd9ed9718682641b749163980edb20271c798d6173794cda55",
            libkernelSha256: "2f8a4203934019a0f9617f6e28194523eecd5dcea8905fb6385d9e94131b6348",
            libkernelSize: 527420,
            libcSha256: "eae99edf77536bba0f59f298a501d45edd05c15369490f59925285391f297f57",
            libcSize: 2059464, codeLimit: 0x34f5718,
            kernelSlot: 0x34f5718, kernelExport: 0x6d1d0,
            libcSlot: 0x34f7da0, libcExport: 0x14e80 })
    });
    const P2JB_FIRMWARE_PINS = Object.freeze({
        "09.00": Object.freeze({ gadget: 0x2006a4, reference: "09.00" }),
        "09.20": Object.freeze({ gadget: 0x200684, reference: "09.20" }),
        "09.40": Object.freeze({ gadget: 0x200684, reference: "09.40" }),
        "09.60": Object.freeze({ gadget: 0x200684, reference: "09.60" }),
        "10.01": Object.freeze({ gadget: 0x169f14, reference: "10.01" }),
        "10.20": Object.freeze({ gadget: 0x169f14, reference: "10.20" }),
        "10.40": Object.freeze({ gadget: 0x169f14, reference: "10.40" }),
        "10.60": Object.freeze({ gadget: 0x169f14, reference: "10.60" }),
        "11.00": Object.freeze({ gadget: 0x9fd65, reference: "11.00" }),
        "11.20": Object.freeze({ gadget: 0x9fd65, reference: "11.20" }),
        "11.40": Object.freeze({ gadget: 0x9fd65, reference: "11.40" }),
        "11.60": Object.freeze({ gadget: 0x9fd65, reference: "11.60" }),
        "12.00": Object.freeze({ gadget: 0xdf94, reference: "12.00" })
    });
    const SLOPKIT_ATTESTATION_GADGET_BYTES = Object.freeze({
        popRax: "58c3", popRdi: "5fc3", popRsi: "5ec3", popRdx: "5ac3",
        popRcx: "59c3", popR8: "4158c3", popRsp: "5cc3",
        movRaxPtrRax: "488b00c3", movPtrRdiRax: "488907c3"
    });
    const SLOPKIT_ATTESTATION_WEBKIT = Object.freeze({
        "09.00": Object.freeze({
            hostConstructors: ["0x34f98", "0x35808", "0x35900"],
            readableAnchors: [
                { rva: "0x2b44000", bytes: "011b033b749d0a00ad530100e0c04bfd" },
                { rva: "0x2e71650", bytes: "20c71cff9e00000000410e108602430d" }
            ],
            gadgets: { popRax: "0x2661d", popRdi: "0x17324d",
                popRsi: "0x30c9e", popRdx: "0xea62", popRcx: "0x19f15",
                popR8: "0x1d1992f", popRsp: "0x1076d",
                movRaxPtrRax: "0x17620b", movPtrRdiRax: "0x9f1af" }
        }),
        "09.20": Object.freeze({
            hostConstructors: ["0x34f98", "0x35808", "0x35900"],
            readableAnchors: [
                { rva: "0x2b44000", bytes: "011b033b749d0a00ad530100e0c04bfd" },
                { rva: "0x2e71650", bytes: "20c71cff9e00000000410e108602430d" }
            ],
            gadgets: { popRax: "0x2661d", popRdi: "0x8b61d",
                popRsi: "0x30c9e", popRdx: "0x16e8ea", popRcx: "0x19f15",
                popR8: "0x1d1990f", popRsp: "0x1076d",
                movRaxPtrRax: "0x1761eb", movPtrRdiRax: "0x9f1af" }
        }),
        "09.40": Object.freeze({
            hostConstructors: ["0x34f98", "0x35808", "0x35900"],
            readableAnchors: [
                { rva: "0x2b44000", bytes: "011b033b749d0a00ad530100e0c04bfd" },
                { rva: "0x2e71650", bytes: "20c71cff9e00000000410e108602430d" }
            ],
            gadgets: { popRax: "0x2661d", popRdi: "0x8b61d",
                popRsi: "0x30c9e", popRdx: "0x65770", popRcx: "0x19f15",
                popR8: "0x1d19b6f", popRsp: "0x1076d",
                movRaxPtrRax: "0x1761eb", movPtrRdiRax: "0x9f1af" }
        }),
        "10.01": Object.freeze({
            hostConstructors: ["0x2c00", "0x5178", "0x5690"],
            readableAnchors: [
                { rva: "0x2d40000", bytes: "011b033becdf0a00fc5b0100e0002cfd" },
                { rva: "0x3076790", bytes: "00410e108602430d06488303027a0c07" }
            ],
            gadgets: { popRax: "0x45b53", popRdi: "0x5fc4e",
                popRsi: "0x1027fa", popRdx: "0x106760", popRcx: "0x24d8d",
                popR8: "0x17daf73", popRsp: "0x394c0",
                movRaxPtrRax: "0x24f22", movPtrRdiRax: "0x32a57" }
        }),
        "11.60": Object.freeze({
            hostConstructors: ["0x1e0d8", "0x1e320", "0x1f368"],
            readableAnchors: [
                { rva: "0x2c7c000", bytes: "011b033bfc900a001e520100e04038fd" },
                { rva: "0x2fa8540", bytes: "0708410c0610740c0708430c06100000" }
            ],
            gadgets: { popRax: "0xd53", popRdi: "0x4575b",
                popRsi: "0x45a94", popRdx: "0x10f32", popRcx: "0x2b555",
                popR8: "0x1d84d0f", popRsp: "0xd3c6",
                movRaxPtrRax: "0x2dd81", movPtrRdiRax: "0x253a" }
        })
    });
    const REVISION_PATTERN = /^[a-z0-9][a-z0-9.-]{2,127}$/;
    const ELFLDR_GLOB_DAT_SYMBOLS = Object.freeze([
        "getpid", "puts", "__error", "strerror", "printf", "malloc",
        "memcpy", "free", "kqueue", "rfork_thread", "kevent", "waitpid",
        "close", "kill", "open", "execve", "strlen", "sysctl", "strcmp",
        "recv", "realloc", "memset", "vsnprintf",
        "sceKernelSendNotificationRequest"
    ]);
    const ELFLDR_LIBC_ANCHORS = Object.freeze(["malloc", "free", "memcpy"]);
    const RENDERER_CONTRACT_SCHEMA = 1;
    const RENDERER_LAYOUT_NAMES = Object.freeze(["packed-32", "split-64"]);
    const RENDERER_CONTRACT_PATHS = Object.freeze([
        "rendererLayout.snapshotBytes", "rendererLayout.butterflyOffset",
        "rendererLayout.vectorOffset", "rendererLayout.lengthOffset",
        "rendererLayout.lengthBytes", "rendererLayout.byteOffsetOffset",
        "rendererLayout.byteOffsetBytes", "rendererLayout.modeOffset",
        "rendererLayout.modeBytes", "rendererLayout.modeValue",
        "rendererEncoding.jsValueDoubleEncodeOffset",
        "rendererEncoding.jsValueDoubleEncodeHigh32",
        "rendererBootstrap.uint8ArrayStructureId",
        "rendererBootstrap.indexingType",
        "rendererBootstrap.cellState",
        "rendererObjects.plainObject.snapshotBytes",
        "rendererObjects.plainObject.butterflyOffset",
        "rendererObjects.plainObject.inlineStorageOffset",
        "rendererObjects.plainObject.inlineCapacity",
        "rendererObjects.plainObject.cellType",
        "rendererObjects.plainObject.typeFlags",
        "rendererObjects.uint8Array.snapshotBytes",
        "rendererObjects.uint8Array.cellType",
        "rendererObjects.uint8Array.typeFlags",
        "rendererObjects.jsFunction.snapshotBytes",
        "rendererObjects.jsFunction.butterflyOffset",
        "rendererObjects.jsFunction.scopeOffset",
        "rendererObjects.jsFunction.executableOffset",
        "rendererObjects.jsFunction.taggedExecutablePayloadOffset",
        "rendererObjects.jsFunction.cellType",
        "rendererObjects.jsFunction.typeFlags",
        "rendererObjects.nativeExecutable.snapshotBytes",
        "rendererObjects.nativeExecutable.cellType",
        "rendererObjects.nativeExecutable.typeFlags",
        "rendererObjects.nativeExecutable.nativeFunctionOffset",
        "rendererObjects.nativeExecutable.nativeConstructorOffset",
        "rendererObjects.boundFunction.snapshotBytes",
        "rendererObjects.boundFunction.cellType",
        "rendererObjects.boundFunction.typeFlags",
        "rendererObjects.intlCollator.snapshotBytes",
        "rendererObjects.intlCollator.cellType",
        "rendererObjects.intlCollator.boundCompareOffset",
        "rendererObjects.intlCollator.collatorOffset",
        "rendererObjects.intlCollator.localeOffset",
        "rendererObjects.intlCollator.collationOffset",
        "rendererObjects.intlCollator.usageOffset",
        "rendererObjects.intlCollator.sensitivityOffset",
        "rendererObjects.intlCollator.caseFirstOffset",
        "rendererObjects.intlCollator.asciiStateOffset",
        "rendererObjects.intlCollator.numericOffset",
        "rendererObjects.intlCollator.ignorePunctuationOffset",
        "rendererObjects.intlCollator.searchUsageValue",
        "rendererObjects.intlCollator.falseAsciiStateValue",
        "rendererObjects.intlCollator.trueAsciiStateValue",
        "rendererObjects.intlCollator.indeterminateAsciiStateValue"
    ]);

    function detectFirmware(userAgent) {
        const match = /PlayStation 5\/(\d+)\.(\d+)/.exec(String(userAgent || ""));
        return match ? `${match[1].padStart(2, "0")}.${match[2].padStart(2, "0")}` : null;
    }

    function parseOffset(value, label) {
        if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
            return value;
        if (typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)) {
            const result = parseInt(value, 16);
            if (Number.isSafeInteger(result)) return result;
        }
        throw new TypeError(`invalid offset ${label || "value"}`);
    }

    function requirePath(object, path) {
        let current = object;
        for (const key of path.split(".")) {
            if (!current || !Object.prototype.hasOwnProperty.call(current, key))
                throw new Error(`profile is missing ${path}`);
            current = current[key];
        }
        return current;
    }

    function setPath(object, path, value) {
        const parts = path.split(".");
        let current = object;
        for (let index = 0; index < parts.length - 1; ++index) {
            const key = parts[index];
            current = current[key] = current[key] || {};
        }
        current[parts[parts.length - 1]] = value;
    }

    function freezeTree(value) {
        if (!value || typeof value !== "object" || Object.isFrozen(value))
            return value;
        for (const child of Object.values(value)) freezeTree(child);
        return Object.freeze(value);
    }

    function normalizeRendererContract(raw) {
        if (!raw || typeof raw !== "object" || Array.isArray(raw))
            throw new Error("renderer contract is not an object");
        const name = requirePath(raw, "rendererLayout.name");
        if (!RENDERER_LAYOUT_NAMES.includes(name))
            throw new Error(`unsupported renderer layout ${name}`);
        const result = { rendererLayout: { name }, rendererEncoding: {},
            rendererBootstrap: {}, rendererObjects: {} };
        for (const path of RENDERER_CONTRACT_PATHS) {
            const value = requirePath(raw, path);
            if (path === "rendererLayout.byteOffsetOffset" && value === null)
                setPath(result, path, null);
            else
                setPath(result, path, parseOffset(value, path));
        }

        const layout = result.rendererLayout;
        const supported = {
            "packed-32": [0x28, 4, 0x1c, 4, 0x20, 4, 2],
            "split-64": [0x30, 8, 0x20, 8, 0x28, 1, 0x58]
        }[name];
        const actual = [layout.snapshotBytes, layout.lengthBytes,
            layout.byteOffsetOffset, layout.byteOffsetBytes,
            layout.modeOffset, layout.modeBytes, layout.modeValue];
        if (layout.butterflyOffset !== 8 || layout.vectorOffset !== 0x10
            || layout.lengthOffset !== 0x18
            || actual.some((value, index) => value !== supported[index]))
            throw new Error(`renderer layout ${name} has unsupported geometry`);

        const objects = result.rendererObjects;
        const plain = objects.plainObject;
        if (plain.butterflyOffset !== layout.butterflyOffset
            || plain.inlineStorageOffset !== plain.butterflyOffset + 8
            || plain.inlineCapacity !== 6
            || plain.snapshotBytes !== plain.inlineStorageOffset
                + plain.inlineCapacity * 8)
            throw new Error("renderer plain-object contract is inconsistent");
        if (objects.uint8Array.snapshotBytes !== layout.snapshotBytes)
            throw new Error("renderer Uint8Array snapshot is inconsistent");
        const fn = objects.jsFunction;
        if (fn.snapshotBytes !== 0x20
            || fn.butterflyOffset !== layout.butterflyOffset
            || fn.scopeOffset !== 0x10 || fn.executableOffset !== 0x18)
            throw new Error("renderer JSFunction contract is inconsistent");
        const native = objects.nativeExecutable;
        if (native.nativeFunctionOffset + 8 > native.snapshotBytes
            || native.nativeConstructorOffset + 8 > native.snapshotBytes)
            throw new Error("renderer NativeExecutable contract is inconsistent");
        const collator = objects.intlCollator;
        for (const path of ["boundCompareOffset", "collatorOffset",
            "localeOffset", "collationOffset"]) {
            if (collator[path] + 8 > collator.snapshotBytes)
                throw new Error(`renderer Intl.Collator ${path} is invalid`);
        }
        for (const path of ["usageOffset", "sensitivityOffset",
            "caseFirstOffset", "asciiStateOffset", "numericOffset",
            "ignorePunctuationOffset"]) {
            if (collator[path] >= collator.snapshotBytes)
                throw new Error(`renderer Intl.Collator ${path} is invalid`);
        }
        const encoding = result.rendererEncoding;
        if (encoding.jsValueDoubleEncodeOffset !== 2 ** 49
            || encoding.jsValueDoubleEncodeHigh32 !== 0x00020000)
            throw new Error("renderer JSValue double encoding is unsupported");
        const bootstrap = result.rendererBootstrap;
        if (bootstrap.uint8ArrayStructureId < 0x4000
            || bootstrap.uint8ArrayStructureId >= 0x08000000
            || (bootstrap.uint8ArrayStructureId & 0xf) !== 0
            || bootstrap.indexingType !== 0 || bootstrap.cellState !== 1)
            throw new Error("renderer bootstrap cell header is unsupported");
        for (const object of Object.values(objects)) {
            for (const field of ["cellType", "typeFlags"]) {
                if (object[field] > 0xff)
                    throw new Error(`renderer object ${field} is invalid`);
            }
        }
        const uint8 = objects.uint8Array;
        const cellHeaderHigh = bootstrap.indexingType
            + uint8.cellType * 0x100 + uint8.typeFlags * 0x10000
            + bootstrap.cellState * 0x1000000;
        const encodedHeaderHigh = cellHeaderHigh
            - encoding.jsValueDoubleEncodeHigh32;
        const bits = new ArrayBuffer(8);
        const words = new Uint32Array(bits);
        words[0] = bootstrap.uint8ArrayStructureId;
        words[1] = encodedHeaderHigh;
        if (encodedHeaderHigh < 0 || encodedHeaderHigh > 0xffffffff
            || !Number.isFinite(new Float64Array(bits)[0]))
            throw new Error("renderer bootstrap JSValue header is invalid");
        return freezeTree(result);
    }

    function encodeRendererContract(raw) {
        const contract = normalizeRendererContract(raw);
        const layoutIndex = RENDERER_LAYOUT_NAMES.indexOf(
            contract.rendererLayout.name);
        return JSON.stringify([RENDERER_CONTRACT_SCHEMA, layoutIndex,
            ...RENDERER_CONTRACT_PATHS.map((path) =>
                requirePath(contract, path))]);
    }

    function decodeRendererContract(encoded) {
        if (typeof encoded !== "string" || encoded.length === 0
            || encoded.length > 2048)
            throw new Error("renderer contract query is missing or oversized");
        let values;
        try { values = JSON.parse(encoded); }
        catch { throw new Error("renderer contract query is not canonical JSON"); }
        if (!Array.isArray(values)
            || values.length !== RENDERER_CONTRACT_PATHS.length + 2
            || values[0] !== RENDERER_CONTRACT_SCHEMA
            || !Number.isInteger(values[1])
            || !RENDERER_LAYOUT_NAMES[values[1]])
            throw new Error("renderer contract query has an invalid schema");
        const raw = { rendererLayout: {
            name: RENDERER_LAYOUT_NAMES[values[1]] }, rendererEncoding: {},
            rendererBootstrap: {}, rendererObjects: {} };
        RENDERER_CONTRACT_PATHS.forEach((path, index) =>
            setPath(raw, path, values[index + 2]));
        const contract = normalizeRendererContract(raw);
        if (encodeRendererContract(contract) !== encoded)
            throw new Error("renderer contract query is not canonical");
        return contract;
    }

    function resolveRendererContract(metadata, entry) {
        const contracts = metadata?.rendererContracts;
        const key = entry?.rendererContract;
        if (!key || !contracts || typeof contracts !== "object"
            || !Object.prototype.hasOwnProperty.call(contracts, key))
            throw new Error("profile has no exact renderer contract");
        return normalizeRendererContract(contracts[key]);
    }

    function validateRendererContractInventory(metadata) {
        const contracts = metadata?.rendererContracts;
        if (!contracts || typeof contracts !== "object"
            || Array.isArray(contracts) || Object.keys(contracts).length === 0)
            throw new Error("offset database renderer contract inventory is invalid");
        const encodings = new Set();
        for (const [key, contract] of Object.entries(contracts)) {
            if (!/^(packed-32|split-64)$/.test(key))
                throw new Error(`renderer contract key ${key} is invalid`);
            const encoding = encodeRendererContract(contract);
            if (encodings.has(encoding))
                throw new Error("offset database has duplicate renderer contracts");
            encodings.add(encoding);
        }
        return true;
    }

    function hasArtifactIdentity(entry) {
        const verified = entry?.verified;
        if (!verified || typeof verified !== "object"
            || Array.isArray(verified) || verified.xomCode !== true)
            return false;
        for (const name of ["webkitSha256", "libkernelWebSha256",
            "libcInternalSha256", "jscSha256"]) {
            if (!/^[0-9a-f]{64}$/i.test(String(verified[name] || "")))
                return false;
        }
        for (const name of ["webkitSize", "libkernelWebSize",
            "libcInternalSize", "jscSize"]) {
            if (!Number.isSafeInteger(verified[name]) || verified[name] <= 0)
                return false;
        }
        return true;
    }

    function byteSignature(value) {
        return typeof value === "string" && /^(?:[0-9a-f]{2})+$/i.test(value);
    }

    function exactObjectKeys(value, names, label) {
        if (!value || typeof value !== "object" || Array.isArray(value))
            throw new Error(`${label} is not an object`);
        const actual = Object.keys(value).sort();
        const expected = names.slice().sort();
        if (actual.length !== expected.length
            || actual.some((name, index) => name !== expected[index]))
            throw new Error(`${label} has an invalid field inventory`);
    }

    function validateReadableAnchors(anchors, label, lowerBound, upperBound) {
        if (!Array.isArray(anchors) || anchors.length < 2)
            throw new Error(`${label} requires at least two readable anchors`);
        for (let index = 0; index < anchors.length; ++index) {
            const anchor = anchors[index];
            const rva = parseOffset(anchor?.rva,
                `${label}[${index}].rva`);
            if ((lowerBound !== null && rva < lowerBound)
                || (upperBound !== null && rva >= upperBound)
                || !byteSignature(anchor?.bytes))
                throw new Error(`${label} ${index} is invalid`);
        }
        return true;
    }

    function validateSlopkitAttestation(entry, firmware) {
        const pin = SLOPKIT_ATTESTATION_PINS[firmware];
        if (!pin)
            throw new Error(`SlopKit has no pinned live attestation for ${firmware}`);
        const attestation = requirePath(entry, "slopkitAttestation");
        exactObjectKeys(attestation, ["kind", "sourceRevision",
            "tableSha256", "coreSha256", "mainSha256",
            "familyProfile", "webkitCodeLimit", "kernelImport",
            "libcImport"], "SlopKit live attestation");
        if (attestation.kind !== SLOPKIT_ATTESTATION_KIND
            || attestation.sourceRevision !== SLOPKIT_ATTESTATION_REVISION
            || attestation.tableSha256 !== pin.tableSha256
            || attestation.coreSha256 !== SLOPKIT_ATTESTATION_CORE_SHA256
            || attestation.mainSha256 !== SLOPKIT_ATTESTATION_MAIN_SHA256
            || attestation.familyProfile !== pin.family)
            throw new Error("SlopKit live attestation does not match its pin");

        const verified = requirePath(entry, "verified");
        exactObjectKeys(verified, ["libkernelWebSha256", "libkernelWebSize",
            "libcInternalSha256", "libcInternalSize", "xomCode"],
        "SlopKit live artifact identity");
        if (verified.libkernelWebSha256 !== pin.libkernelSha256
            || verified.libkernelWebSize !== pin.libkernelSize
            || verified.libcInternalSha256 !== pin.libcSha256
            || verified.libcInternalSize !== pin.libcSize
            || verified.xomCode !== true)
            throw new Error("SlopKit live native artifact identity is not pinned");
        for (const name of ["webkitSha256", "webkitSize", "jscSha256",
            "jscSize"]) {
            if (Object.prototype.hasOwnProperty.call(verified, name))
                throw new Error(`SlopKit live profile must omit ${name}`);
        }

        if (Object.prototype.hasOwnProperty.call(entry.webkit, "textSize")
            || Object.prototype.hasOwnProperty.call(entry.webkit, "imports"))
            throw new Error("SlopKit live profile claims unmeasured WebKit fields");
        const codeLimit = parseOffset(attestation.webkitCodeLimit,
            "slopkitAttestation.webkitCodeLimit");
        if (codeLimit !== pin.codeLimit)
            throw new Error("SlopKit live WebKit code limit is invalid");
        exactObjectKeys(attestation.kernelImport, ["slot", "export"],
            "SlopKit kernel import");
        exactObjectKeys(attestation.libcImport, ["slot", "export"],
            "SlopKit libc import");
        const importSlots = [];
        for (const [name, binding] of [["kernel", attestation.kernelImport],
            ["libc", attestation.libcImport]]) {
            const slot = parseOffset(binding.slot,
                `slopkitAttestation.${name}Import.slot`);
            parseOffset(binding.export,
                `slopkitAttestation.${name}Import.export`);
            if ((slot & 7) !== 0 || slot < codeLimit)
                throw new Error(`SlopKit ${name} import is outside its pinned envelope`);
            importSlots.push(slot);
        }
        if (parseOffset(attestation.kernelImport.slot) !== pin.kernelSlot
            || parseOffset(attestation.kernelImport.export) !== pin.kernelExport
            || parseOffset(attestation.libcImport.slot) !== pin.libcSlot
            || parseOffset(attestation.libcImport.export) !== pin.libcExport)
            throw new Error("SlopKit live import contract does not match its pin");
        if (parseOffset(attestation.kernelImport.export)
                >= requirePath(entry, "verified.libkernelWebSize")
            || parseOffset(attestation.libcImport.export)
                >= parseOffset(requirePath(entry, "loader.libcTextSize")))
            throw new Error("SlopKit live import export is outside its module envelope");
        if (codeLimit !== Math.min(...importSlots))
            throw new Error("SlopKit WebKit code limit is not the first pinned import");

        const webkitPin = SLOPKIT_ATTESTATION_WEBKIT[firmware]
            || SLOPKIT_ATTESTATION_WEBKIT[pin.family];
        exactObjectKeys(entry.webkit, ["readableAnchors", "hostConstructors",
            "gadgets", "gadgetBytes"], "SlopKit live WebKit contract");
        exactObjectKeys(entry.webkit.gadgets,
            Object.keys(webkitPin.gadgets), "SlopKit live gadgets");
        exactObjectKeys(entry.webkit.gadgetBytes,
            Object.keys(SLOPKIT_ATTESTATION_GADGET_BYTES),
            "SlopKit live gadget signatures");
        if (JSON.stringify(entry.webkit.hostConstructors)
                !== JSON.stringify(webkitPin.hostConstructors)
            || entry.webkit.readableAnchors.length
                !== webkitPin.readableAnchors.length
            || webkitPin.readableAnchors.some((anchor, index) =>
                entry.webkit.readableAnchors[index]?.rva !== anchor.rva
                || entry.webkit.readableAnchors[index]?.bytes !== anchor.bytes)
            || Object.keys(webkitPin.gadgets).some((name) =>
                entry.webkit.gadgets[name] !== webkitPin.gadgets[name])
            || Object.keys(SLOPKIT_ATTESTATION_GADGET_BYTES).some((name) =>
                entry.webkit.gadgetBytes[name]
                    !== SLOPKIT_ATTESTATION_GADGET_BYTES[name]))
            throw new Error("SlopKit live WebKit contract does not match its family pin");
        validateReadableAnchors(entry.webkit.readableAnchors,
            "webkit.readableAnchors", null, codeLimit);
        validateReadableAnchors(requirePath(entry, "libc.readableAnchors"),
            "libc.readableAnchors", parseOffset(entry.loader.libcTextSize), null);
        return true;
    }

    function isSlopkitAttested(entry, firmware) {
        try { return validateSlopkitAttestation(entry, firmware); }
        catch { return false; }
    }

    function validateWorkerTuning(entry, poops) {
        const tuning = requirePath(entry, "kernel.tuning");
        const names = ["recvWorkers", "readvWorkers",
            "writevWorkers", "realtimePriority", "reclaimCycles",
            "workerUnblockBytes", "twinRounds", "tripletRounds",
            "kqueueRounds", "maxInnerIterations"];
        if (poops) names.push("ipv6Sockets", "phantomSocketLimit");
        for (const name of names) {
            const value = requirePath(tuning, name);
            if (!Number.isSafeInteger(value) || value <= 0)
                throw new Error(`invalid positive integer kernel.tuning.${name}`);
        }
        if (poops && (!Number.isSafeInteger(tuning.mainCore)
            || tuning.mainCore < 0 || tuning.mainCore >= 128))
            throw new Error("invalid worker CPU core");
        if (tuning.readvWorkers !== tuning.writevWorkers
            || tuning.workerUnblockBytes !== tuning.recvWorkers)
            throw new Error("worker tuning is inconsistent with the fixed worker ABI");
        return tuning;
    }

    function validatePoops(entry) {
        const tuning = validateWorkerTuning(entry, true);
        const drainAfter = requirePath(tuning, "phantomDrainAfter");
        const drainBatch = requirePath(tuning, "phantomDrainBatch");
        const socketLimit = requirePath(tuning, "phantomSocketLimit");
        if (!Number.isSafeInteger(drainAfter) || drainAfter <= 0
            || !Number.isSafeInteger(drainBatch) || drainBatch <= 0
            || !Number.isSafeInteger(socketLimit) || socketLimit <= 0
            || drainAfter + drainBatch > socketLimit)
            throw new Error("invalid explicit POOPS phantom drain geometry");

        const geometry = ["cleanupPipeHolds", "cleanupTripletHeaders",
            "cleanupUafDetached", "cleanupUafPurged",
            "cleanupWorkerDescriptors"];
        for (const name of geometry) {
            const value = requirePath(tuning, name);
            if (!Number.isSafeInteger(value) || value <= 0)
                throw new Error(`invalid POOPS cleanup geometry ${name}`);
        }
        // The worker descriptor count is the two socketpairs, not the number
        // of native workers. Keep it explicit so changing the worker ABI cannot
        // silently alter cleanup geometry.
        if (tuning.cleanupPipeHolds !== 4
            || tuning.cleanupTripletHeaders !== 3
            || tuning.cleanupUafDetached !== 1
            || tuning.cleanupUafPurged !== 3
            || tuning.cleanupWorkerDescriptors !== 4)
            throw new Error("unsupported POOPS cleanup geometry");

        for (const name of ["netcontrol", "setuid", "socket", "dup",
            "close", "setsockopt", "getsockopt", "recvmsg", "readv",
            "writev", "read", "write", "pipe", "fcntl", "socketpair",
            "pthreadCreate", "pthreadExit",
            "pthreadJoin", "cpusetGetaffinity", "cpusetSetaffinity",
            "rtprioThread", "nanosleep", "schedYield", "error", "umtxOp",
            "kqueue"]) {
            parseOffset(requirePath(entry, `native.exports.${name}`),
                `native.exports.${name}`);
        }
        for (const name of ["afUnix", "sockStream", "ipprotoIpv6",
            "ipv6Rthdr", "netcontrolSetQueue", "netcontrolClearQueue",
            "umtxWaitPrivate", "umtxWakePrivate", "ucredSize", "rthdrTag",
            "msgIovNum", "uioIovNum", "uioSysspace", "solSocket",
            "soSndbuf", "pageSize", "fSetfl", "oNonblock"]) {
            parseOffset(requirePath(entry, `kernel.constants.${name}`),
                `kernel.constants.${name}`);
        }
        const structures = {};
        for (const name of ["fileData", "fileRefcount", "socketPcb",
            "filedescentSize", "fdtOfiles", "kqueueFdp", "pipeSigio",
            "in6pOutputopts", "ip6poRthdr", "procPid", "procFd"]) {
            structures[name] = parseOffset(requirePath(entry,
                `kernel.structures.${name}`),
                `kernel.structures.${name}`);
        }
        if ((structures.fileData & 7) !== 0
            || (structures.fileRefcount & 3) !== 0
            || (structures.socketPcb & 7) !== 0
            || structures.fileData >= 0x400
            || structures.fileRefcount >= 0x400
            || structures.socketPcb >= 0x400)
            throw new Error("invalid POOPS file/socket structure geometry");
        return true;
    }

    function validateLapseConfig(entry, firmware, metadata) {
        const minimalRuntime = Array.isArray(metadata.supported);
        const revision = minimalRuntime ? null : requirePath(metadata,
            "qualificationRevisions.engines.lapse");
        if (!minimalRuntime && revision !== LAPSE_ENGINE_REVISION)
            throw new Error(`Lapse engine ${revision} is not implemented`);
        const configs = requirePath(metadata, "lapse.firmwares");
        const config = configs?.[firmware];
        if (!config)
            throw new Error(`profile is missing Lapse configuration ${firmware}`);
        const fields = ["mainCore",
            "mainRtprio", "groomGroups", "spraySockets",
            "alternateSockets", "raceAttempts", "aliasAttempts",
            "leakRecords", "leakRounds", "clobberAttempts",
            "eventHandles", "curprocReadAttempts", "maxAioIds",
            "raceThreadWaitRounds", "rthdrSize", "rthdrMarkerOffset"];
        if (!minimalRuntime) fields.unshift("revision", "firmware");
        exactObjectKeys(config, fields,
        `Lapse ${firmware} configuration`);
        if (!minimalRuntime
            && (config.revision !== revision || config.firmware !== firmware))
            throw new Error(`Lapse ${firmware} configuration identity is stale`);
        for (const name of ["mainCore", "mainRtprio", "groomGroups",
            "spraySockets", "alternateSockets", "raceAttempts",
            "aliasAttempts", "leakRecords", "leakRounds",
            "clobberAttempts", "eventHandles", "curprocReadAttempts",
            "maxAioIds", "raceThreadWaitRounds", "rthdrSize",
            "rthdrMarkerOffset"]) {
            if (!Number.isSafeInteger(config[name]) || config[name] < 0)
                throw new Error(`invalid Lapse setting ${firmware}.${name}`);
        }
        if (config.mainCore >= 128 || config.mainRtprio > 0xffff
            || config.groomGroups === 0
            || config.spraySockets < 2 || config.alternateSockets < 2
            || config.raceAttempts === 0 || config.aliasAttempts === 0
            || config.leakRecords < 2 || config.leakRounds === 0
            || config.clobberAttempts === 0 || config.eventHandles === 0
            || config.curprocReadAttempts === 0 || config.maxAioIds === 0
            || config.raceThreadWaitRounds === 0 || config.rthdrSize < 0x80
            || (config.rthdrSize & 7) !== 0
            || (config.rthdrMarkerOffset & 3) !== 0
            || config.rthdrMarkerOffset + 4 > config.rthdrSize)
            throw new Error(`unsafe Lapse setting geometry for ${firmware}`);
        return config;
    }

    function validateLapse(entry, firmware, metadata) {
        validateLapseConfig(entry, firmware, metadata);

        for (const name of ["accept", "aioMultiCancel", "aioMultiDelete",
            "aioMultiPoll", "aioMultiWait", "aioSubmitCmd", "bind", "close",
            "connect", "cpusetGetaffinity", "cpusetSetaffinity", "evfClear",
            "evfCreate", "evfDelete", "evfSet", "fcntl", "getpid",
            "getsockname", "getsockopt", "listen", "nanosleep", "pipe",
            "pthreadCreate", "pthreadExit", "pthreadJoin", "read",
            "rtprioThread", "schedYield", "setsockopt", "socket",
            "socketpair", "thrResumeUcontext", "thrSelf",
            "thrSuspendUcontext", "write"]) {
            parseOffset(requirePath(entry, `native.exports.${name}`),
                `native.exports.${name}`);
        }
        for (const name of ["afInet", "afInet6", "sockDgram", "ipprotoUdp",
            "ipprotoIpv6", "ipv6Rthdr", "ipv6Pktinfo", "ipv6Nexthop",
            "ipv6Tclass", "fSetfl", "oNonblock", "pageSize"]) {
            parseOffset(requirePath(entry, `kernel.constants.${name}`),
                `kernel.constants.${name}`);
        }
        const structures = {};
        for (const name of ["fileData", "fileRefcount", "socketPcb",
            "filedescentSize", "fdtOfiles", "in6pOutputopts",
            "ip6poRthdr", "procFd", "procPid"]) {
            structures[name] = parseOffset(requirePath(entry,
                `kernel.structures.${name}`), `kernel.structures.${name}`);
        }
        if ((structures.fileData & 7) !== 0
            || (structures.fileRefcount & 3) !== 0
            || (structures.socketPcb & 7) !== 0
            || structures.fileData >= 0x400
            || structures.fileRefcount >= 0x400
            || structures.socketPcb >= 0x400
            || structures.filedescentSize < 0x30
            || (structures.filedescentSize & 7) !== 0
            || (structures.fdtOfiles & 7) !== 0
            || (structures.in6pOutputopts & 7) !== 0
            || (structures.ip6poRthdr & 7) !== 0
            || (structures.procFd & 7) !== 0
            || (structures.procPid & 3) !== 0)
            throw new Error("Lapse kernel structure geometry is invalid");
        return true;
    }

    function validateOperationalProfile(entry, firmware, metadata, attested) {
        resolveRendererContract(metadata, entry);
        if (!/^\d{2}\.\d{2}$/.test(String(firmware || "")))
            throw new Error("full-chain profile has an invalid firmware identity");
        if (attested)
            validateSlopkitAttestation(entry, firmware);
        else if (!hasArtifactIdentity(entry))
            throw new Error("full-chain profile is not backed by an exact firmware image set");
        const webkitLimitPath = attested
            ? "slopkitAttestation.webkitCodeLimit" : "webkit.textSize";
        const paths = [
            webkitLimitPath, "webkit.readableAnchors",
            "webkit.gadgets.popRax", "webkit.gadgets.popRdi",
            "webkit.gadgets.popRsi", "webkit.gadgets.popRdx",
            "webkit.gadgets.popRcx", "webkit.gadgets.popR8",
            "webkit.gadgets.popRsp",
            "webkit.gadgets.movPtrRdiRax", "webkit.gadgetBytes",
            "native.textSize", "native.readableAnchors",
            "native.context.captureEntry",
            "native.context.setcontextEntry", "native.context.naturalTrampoline",
            "native.context.captureBytes", "native.context.setcontextBytes",
            "native.context.trampolineBytes",
            "native.exportBytes",
            "native.syscallStubs.dynlibDlsym",
            "native.syscallStubBytes.dynlibDlsym",
            "native.exports.mmap", "native.exports.pthreadCreate",
            "post.allproc", "post.kernelPmapStore", "loader.version",
            "loader.path", "loader.sha256",
            "loader.size", "loader.mappingAddress", "loader.shadowAddress",
            "loader.syscallInstructionOffset", "loader.libcTextSize",
            "loader.symbols"
        ];
        paths.push("verified.libkernelWebSha256",
            "verified.libcInternalSha256", "verified.libkernelWebSize",
            "verified.libcInternalSize", "verified.xomCode");
        if (!attested) paths.push(
            "verified.webkitSha256", "verified.jscSha256",
            "verified.webkitSize", "verified.jscSize", "loader.libcAnchors");
        else paths.push("libc.readableAnchors");
        for (const path of paths) requirePath(entry, path);

        const offsetPaths = [
            webkitLimitPath, "native.textSize",
            "native.context.sigsetjmp", "native.context.captureEntry",
            "native.context.setcontext", "native.context.setcontextEntry",
            "native.context.naturalTrampoline",
            "kernel.constants.afInet", "kernel.constants.afInet6",
            "kernel.constants.sockDgram", "kernel.constants.sockStream",
            "kernel.constants.ipprotoIpv6", "kernel.constants.ipprotoUdp",
            "kernel.constants.ipv6Pktinfo", "kernel.constants.fiosetown",
            "kernel.constants.solSocket", "kernel.constants.soNosigpipe",
            "kernel.constants.soSndtimeo",
            "kernel.structures.pipeSigio", "kernel.structures.in6pOutputopts",
            "kernel.structures.procPid", "kernel.structures.procUcred",
            "kernel.structures.procFd", "kernel.structures.procDynlib",
            "kernel.structures.procVmspace",
            "kernel.structures.vmspacePmapObject",
            "kernel.structures.pmapPml4", "kernel.structures.pmapCr3",
            "post.dataBaseOffset", "post.allproc", "post.securityFlags",
            "post.rootVnode", "post.kernelPmapStore", "post.gvmspace",
            "post.sizeofGvmspace", "post.sysentOffset",
            "loader.mappingAddress", "loader.shadowAddress",
            "native.syscallStubs.dynlibDlsym"
        ];
        for (const path of offsetPaths)
            parseOffset(requirePath(entry, path), path);

        const vmspacePmapObject = parseOffset(
            entry.kernel.structures.vmspacePmapObject,
            "kernel.structures.vmspacePmapObject");
        const pmapPml4 = parseOffset(entry.kernel.structures.pmapPml4,
            "kernel.structures.pmapPml4");
        const pmapCr3 = parseOffset(entry.kernel.structures.pmapCr3,
            "kernel.structures.pmapCr3");
        if ((vmspacePmapObject & 7) !== 0 || vmspacePmapObject < 0x200
            || vmspacePmapObject >= 0x1000 || (pmapPml4 & 7) !== 0
            || pmapCr3 !== pmapPml4 + 8)
            throw new Error("profiled vmspace pmap geometry is invalid");

        const contextOffsets = ["rdi", "rsi", "rdx", "rcx", "r8", "r9",
            "rax", "rbx", "rbp", "r12", "r13", "r14", "r15", "rip", "rsp"];
        for (const name of contextOffsets)
            parseOffset(requirePath(entry, `native.context.offsets.${name}`),
                `native.context.offsets.${name}`);

        const hashPaths = ["loader.sha256", "verified.libkernelWebSha256",
            "verified.libcInternalSha256"];
        if (!attested) hashPaths.push("verified.webkitSha256",
            "verified.jscSha256");
        for (const path of hashPaths) {
            if (!/^[0-9a-f]{64}$/i.test(String(requirePath(entry, path))))
                throw new Error(`invalid SHA-256 ${path}`);
        }
        const sizePaths = ["loader.size", "verified.libkernelWebSize",
            "verified.libcInternalSize"];
        if (!attested) sizePaths.push("verified.webkitSize",
            "verified.jscSize");
        for (const path of sizePaths) {
            const value = requirePath(entry, path);
            if (!Number.isSafeInteger(value) || value <= 0)
                throw new Error(`invalid positive integer ${path}`);
        }

        for (const name of ["allocateMainDirectMemory", "bind", "close", "connect",
            "dlsym", "error", "getpid", "ioctl",
            "jitCreateAlias", "jitCreateSharedMemory",
            "mapDirectMemory", "mmap", "mprotect", "munmap", "nanosleep", "open",
            "pthreadAttrDestroy", "pthreadAttrInit",
            "pthreadAttrSetdetachstate", "pthreadAttrSetstacksize",
            "pthreadCreate", "setsockopt", "socket", "sysctlbyname", "write"]) {
            parseOffset(requirePath(entry, `native.exports.${name}`),
                `native.exports.${name}`);
        }
        if (!/^payloads\/[A-Za-z0-9._-]+$/.test(
            requirePath(entry, "loader.path")))
            throw new Error("invalid pinned loader location");
        if (entry.loader.version !== "0.24")
            throw new Error("loader ABI is not pinned to elfldr v0.24");
        if (!/^0x[0-9a-f]{1,16}$/i.test(requirePath(entry, "post.systemAuthId")))
            throw new Error("invalid post.systemAuthId");
        for (const name of ["uid", "ruid", "svuid", "ngroups", "rgid", "svgid"]) {
            const value = requirePath(entry, `post.browserCredential.${name}`);
            if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff)
                throw new Error(`invalid post.browserCredential.${name}`);
        }
        for (const name of ["authId", "caps0", "caps1", "attrs"]) {
            if (!/^0x[0-9a-f]{1,16}$/i.test(requirePath(entry,
                `post.browserCredential.${name}`)))
                throw new Error(`invalid post.browserCredential.${name}`);
        }
        const mapping = parseOffset(entry.loader.mappingAddress,
            "loader.mappingAddress");
        const shadow = parseOffset(entry.loader.shadowAddress,
            "loader.shadowAddress");
        if (mapping === shadow || (mapping & 0x3fff) !== 0
            || (shadow & 0x3fff) !== 0)
            throw new Error("loader mappings are invalid");

        if (entry.verified.xomCode !== true)
            throw new Error("profile must declare execute-only module code");
        const webkitTextSize = parseOffset(requirePath(entry,
            webkitLimitPath), webkitLimitPath);
        if (attested) {
            validateReadableAnchors(entry.webkit.readableAnchors,
                "webkit.readableAnchors", null, webkitTextSize);
        } else {
            validateReadableAnchors(entry.webkit.readableAnchors,
                "webkit.readableAnchors", webkitTextSize, null);
        }
        const nativeTextSize = parseOffset(entry.native.textSize,
            "native.textSize");
        validateReadableAnchors(entry.native.readableAnchors,
            "native.readableAnchors", nativeTextSize, null);
        const gadgets = requirePath(entry, "webkit.gadgets");
        const gadgetBytes = requirePath(entry, "webkit.gadgetBytes");
        for (const name of Object.keys(gadgets)) {
            const offset = parseOffset(gadgets[name], `webkit.gadgets.${name}`);
            if (offset >= webkitTextSize)
                throw new Error(`WebKit gadget ${name} is outside XOM text`);
            if (!byteSignature(gadgetBytes[name]))
                throw new Error(`invalid WebKit gadget signature ${name}`);
        }
        const orphanGadget = Object.keys(gadgetBytes).find((name) =>
            !(name in gadgets));
        if (orphanGadget)
            throw new Error(`WebKit gadget signature ${orphanGadget} has no matching offset`);

        for (const name of ["captureBytes", "setcontextBytes", "trampolineBytes"]) {
            if (!byteSignature(requirePath(entry, `native.context.${name}`)))
                throw new Error(`invalid native context signature ${name}`);
        }
        for (const name of ["sigsetjmp", "captureEntry", "setcontext",
            "setcontextEntry", "naturalTrampoline"]) {
            if (parseOffset(entry.native.context[name],
                `native.context.${name}`) >= nativeTextSize)
                throw new Error(`native context ${name} is outside XOM text`);
        }
        const exports = requirePath(entry, "native.exports");
        const exportBytes = requirePath(entry, "native.exportBytes");
        for (const name of Object.keys(exports)) {
            const offset = parseOffset(exports[name], `native.exports.${name}`);
            if (offset >= nativeTextSize)
                throw new Error(`native export ${name} is outside XOM text`);
            if (!byteSignature(exportBytes[name]))
                throw new Error(`invalid native export signature ${name}`);
        }
        const orphanExport = Object.keys(exportBytes).find((name) =>
            !(name in exports));
        if (orphanExport)
            throw new Error(`native export signature ${orphanExport} has no matching offset`);

        const syscallStubs = requirePath(entry, "native.syscallStubs");
        const syscallStubBytes = requirePath(entry, "native.syscallStubBytes");
        for (const name of Object.keys(syscallStubs)) {
            const offset = parseOffset(syscallStubs[name],
                `native.syscallStubs.${name}`);
            if (offset >= parseOffset(entry.native.textSize))
                throw new Error(`native syscall stub ${name} is outside XOM text`);
            if (!byteSignature(syscallStubBytes[name]))
                throw new Error(`invalid native syscall stub signature ${name}`);
        }
        const orphanStub = Object.keys(syscallStubBytes).find((name) =>
            !(name in syscallStubs));
        if (orphanStub)
            throw new Error(`native syscall stub signature ${orphanStub} has no matching offset`);

        const syscallOffset = requirePath(entry, "loader.syscallInstructionOffset");
        const stubBytes = syscallStubBytes.dynlibDlsym.match(/../g)
            .map((value) => parseInt(value, 16));
        if (syscallOffset !== 10 || stubBytes.length <= syscallOffset + 1
            || stubBytes[0] !== 0x48 || stubBytes[1] !== 0xc7
            || stubBytes[2] !== 0xc0
            || (stubBytes[3] | (stubBytes[4] << 8)
                | (stubBytes[5] << 16) | (stubBytes[6] << 24)) !== 0x24f
            || stubBytes[syscallOffset] !== 0x0f
            || stubBytes[syscallOffset + 1] !== 0x05)
            throw new Error("dynlib dlsym syscall stub does not encode syscall 0x24f at +0xa");
        const wrapperBytes = exportBytes.dlsym.match(/../g)
            .map((value) => parseInt(value, 16));
        const relative = (wrapperBytes[5] | (wrapperBytes[6] << 8)
            | (wrapperBytes[7] << 16) | (wrapperBytes[8] << 24)) | 0;
        const wrapperOffset = parseOffset(exports.dlsym,
            "native.exports.dlsym");
        const stubOffset = parseOffset(syscallStubs.dynlibDlsym,
            "native.syscallStubs.dynlibDlsym");
        if (wrapperBytes.length < 9 || wrapperBytes[4] !== 0xe8
            || wrapperOffset + 9 + relative !== stubOffset)
            throw new Error("sceKernelDlsym wrapper does not call the pinned raw stub");

        const imports = attested ? null : requirePath(entry, "webkit.imports");
        if (!attested) {
            for (const name of ["getpid", "close", "error",
                ...ELFLDR_LIBC_ANCHORS]) {
                parseOffset(requirePath(imports, `${name}.slot`),
                    `webkit.imports.${name}.slot`);
                parseOffset(requirePath(imports, `${name}.export`),
                    `webkit.imports.${name}.export`);
            }
        }

        const symbols = requirePath(entry, "loader.symbols");
        const symbolNames = Object.keys(symbols);
        if (symbolNames.length !== ELFLDR_GLOB_DAT_SYMBOLS.length
            || ELFLDR_GLOB_DAT_SYMBOLS.some((name) => !(name in symbols))
            || symbolNames.some((name) => !ELFLDR_GLOB_DAT_SYMBOLS.includes(name)))
            throw new Error("loader symbol profile is not the exact elfldr v0.24 GLOB_DAT set");
        const nids = new Set();
        let libkernelSymbols = 0, libcSymbols = 0;
        for (const name of ELFLDR_GLOB_DAT_SYMBOLS) {
            const symbol = symbols[name];
            if (!symbol || !/^[A-Za-z0-9+-]{11}$/.test(symbol.nid)
                || nids.has(symbol.nid))
                throw new Error(`invalid or duplicate loader NID ${name}`);
            nids.add(symbol.nid);
            if (symbol.module === "libkernel") {
                libkernelSymbols++;
                if (typeof symbol.export !== "string"
                    || !(symbol.export in exports)
                    || Object.prototype.hasOwnProperty.call(symbol, "offset"))
                    throw new Error(`invalid libkernel loader symbol ${name}`);
            } else if (symbol.module === "libc") {
                libcSymbols++;
                parseOffset(requirePath(symbol, "offset"),
                    `loader.symbols.${name}.offset`);
                if (Object.prototype.hasOwnProperty.call(symbol, "export"))
                    throw new Error(`invalid libc loader symbol ${name}`);
            } else {
                throw new Error(`invalid loader symbol module ${name}`);
            }
        }
        if (libkernelSymbols !== 13 || libcSymbols !== 11)
            throw new Error("loader symbol profile is not split 13 libkernel / 11 libc");
        if (!attested) {
            const anchors = requirePath(entry, "loader.libcAnchors");
            if (!Array.isArray(anchors)
                || anchors.length !== ELFLDR_LIBC_ANCHORS.length
                || new Set(anchors).size !== anchors.length
                || ELFLDR_LIBC_ANCHORS.some((name) => !anchors.includes(name)))
                throw new Error("loader libc anchors are invalid");
            for (const name of anchors) {
                if (symbols[name].module !== "libc"
                    || parseOffset(imports[name].export)
                        !== parseOffset(symbols[name].offset))
                    throw new Error(`loader libc anchor ${name} disagrees with its export`);
            }
        } else {
            validateReadableAnchors(entry.libc.readableAnchors,
                "libc.readableAnchors", parseOffset(entry.loader.libcTextSize),
                null);
        }
        const libcTextEnd = parseOffset(requirePath(entry,
            "loader.libcTextSize"), "loader.libcTextSize");
        if (libcTextEnd === 0 || libcTextEnd > 0x10000000)
            throw new Error("loader libc text size is invalid");
        for (const [name, symbol] of Object.entries(symbols)) {
            if (symbol.module === "libc"
                && parseOffset(symbol.offset,
                    `loader.symbols.${name}.offset`) >= libcTextEnd)
                throw new Error(`loader libc symbol ${name} is outside executable text`);
        }
        const hosts = requirePath(entry, "webkit.hostConstructors");
        if (!Array.isArray(hosts) || hosts.length === 0
            || hosts.some((value) => parseOffset(value) >= webkitTextSize))
            throw new Error("WebKit host constructor is outside XOM text");
        return true;
    }

    function validateFull(entry, firmware, metadata) {
        return validateOperationalProfile(entry, firmware, metadata, false);
    }

    function validateSlopkitLive(entry, firmware, metadata) {
        return validateOperationalProfile(entry, firmware, metadata, true);
    }

    function p2jbMetadata(metadata, firmware) {
        const config = requirePath(metadata, "p2jb");
        const firmwares = requirePath(config, "firmwares");
        if (!Object.prototype.hasOwnProperty.call(firmwares, firmware))
            throw new Error(`P2JB has no capability record for firmware ${firmware}`);
        const firmwareConfig = firmwares[firmware];
        return { config, firmware: firmwareConfig };
    }

    function validateP2jbTopologies(config, firmwareConfig, minimalRuntime) {
        const topologies = requirePath(firmwareConfig, "coreTopologies");
        if (!Array.isArray(topologies) || topologies.length === 0)
            throw new Error("P2JB core topology inventory is empty");
        for (let index = 0; index < topologies.length; ++index) {
            const topology = topologies[index];
            exactObjectKeys(topology, minimalRuntime
                ? ["mainCore", "burnCoresDefault"]
                : ["mainCore", "burnCoresDefault", "burnCoresAdvanced"],
            `P2JB core topology ${index}`);
            if (!Number.isSafeInteger(topology.mainCore)
                || topology.mainCore < 0 || topology.mainCore >= 128)
                throw new Error(`invalid P2JB controller core ${index}`);
            const coreSets = [["burnCoresDefault", config.defaultBurnWorkers]];
            if (!minimalRuntime)
                coreSets.push(["burnCoresAdvanced", config.advancedBurnWorkers]);
            for (const [name, count] of coreSets) {
                const cores = topology[name];
                if (!Array.isArray(cores) || cores.length !== count
                    || new Set(cores).size !== cores.length
                    || cores.some((core) => !Number.isSafeInteger(core)
                        || core < 0 || core >= 128
                        || core === topology.mainCore))
                    throw new Error(`invalid P2JB core topology ${index}.${name}`);
            }
            if (!minimalRuntime && topology.burnCoresDefault.some((core) =>
                !topology.burnCoresAdvanced.includes(core)))
                throw new Error(`P2JB topology ${index} changes default workers`);
        }
        return topologies;
    }

    function validateP2jbFirmwareMetadata(entry, firmware, metadata) {
        const minimalRuntime = Array.isArray(metadata.supported);
        const { config, firmware: firmwareConfig } = p2jbMetadata(
            metadata, firmware);
        const fields = ["incDwordPtrRax", "referenceFirmware",
            "coreTopologies"];
        if (!minimalRuntime) fields.push("evidenceClass");
        if (!minimalRuntime && metadata.catalog !== RUNTIME_CATALOG)
            fields.push("evidence");
        exactObjectKeys(firmwareConfig, fields,
            `P2JB firmware ${firmware}`);
        if (!minimalRuntime && metadata.catalog !== RUNTIME_CATALOG
            && (typeof firmwareConfig.evidence !== "string"
                || firmwareConfig.evidence.length < 8
                || firmwareConfig.evidence.length > 512))
            throw new Error("P2JB firmware evidence is invalid");
        if (config.method !== "kqueueex-cr-ref-overflow")
            throw new Error("P2JB method metadata is unsupported");
        if (!minimalRuntime && metadata.catalog !== RUNTIME_CATALOG
            && requirePath(metadata, "qualificationRevisions.engines.p2jb")
                !== P2JB_ENGINE_REVISION)
            throw new Error("P2JB engine revision is unsupported");
        if (config.defaultBurnWorkers !== 3
            || (!minimalRuntime && config.advancedBurnWorkers !== 4))
            throw new Error("P2JB worker geometry is unsupported");
        validateP2jbTopologies(config, firmwareConfig, minimalRuntime);

        const gadget = parseOffset(requirePath(firmwareConfig,
            "incDwordPtrRax"), "p2jb.incDwordPtrRax");
        const pin = P2JB_FIRMWARE_PINS[firmware];
        if (!pin || gadget !== pin.gadget
            || firmwareConfig.referenceFirmware !== pin.reference)
            throw new Error("P2JB firmware contract does not match its pin");
        const webkitLimit = Object.prototype.hasOwnProperty.call(entry,
            "slopkitAttestation")
            ? parseOffset(entry.slopkitAttestation.webkitCodeLimit,
                "slopkitAttestation.webkitCodeLimit")
            : parseOffset(entry.webkit.textSize, "webkit.textSize");
        if (gadget >= webkitLimit)
            throw new Error("P2JB counter gadget is outside WebKit text");
        if (!/^(?:[0-9a-f]{2})+$/i.test(String(requirePath(config,
            "gadgetBytes.incDwordPtrRax"))))
            throw new Error("P2JB counter gadget signature is invalid");
        const expectedEvidenceClass = Object.prototype.hasOwnProperty.call(
            entry, "slopkitAttestation") ? "live-attested" : "exact";
        if (!minimalRuntime && requirePath(firmwareConfig, "evidenceClass")
            !== expectedEvidenceClass)
            throw new Error("P2JB firmware evidence class disagrees with its profile");
        if (!minimalRuntime && metadata.catalog !== RUNTIME_CATALOG
            && expectedEvidenceClass === "live-attested"
            && !/^pinned-(?:target|same-family)-table-and-live-semantic-preflight$/
                .test(firmwareConfig.evidence))
            throw new Error("P2JB live firmware lacks its semantic preflight contract");
        if (!/^\d{2}\.\d{2}$/.test(String(requirePath(firmwareConfig,
            "referenceFirmware"))))
            throw new Error("P2JB reference firmware is invalid");
        return { config, firmwareConfig };
    }

    function validateP2jb(entry, firmware, metadata) {
        const minimalRuntime = Array.isArray(metadata.supported);
        const { config } = validateP2jbFirmwareMetadata(entry, firmware,
            metadata);
        const tuning = validateWorkerTuning(entry, false);

        const numericSettings = ["defaultBurnWorkers",
            "mainCore", "burnUnroll", "fdBudgetMargin", "freeFdCap",
            "fdLimitTarget", "fdProbeBatch", "fdProbeHeartbeat",
            "fdProbeYieldMs", "minimumFdHeadroom", "tripleFreeAttempts", "stallTimeoutMs",
            "pollIntervalMs", "workerReadyTimeoutMs", "workerExitTimeoutMs",
            "settleDelayMs", "postRaceSettleMs",
            "ipv6Sockets", "cleanupPipeHolds", "cleanupWorkerDescriptors",
            "cleanupParkedWorkers"];
        if (!minimalRuntime) numericSettings.push("advancedBurnWorkers");
        for (const name of numericSettings) {
            const value = requirePath(config, name);
            if (!Number.isSafeInteger(value) || value <= 0)
                throw new Error(`invalid P2JB setting ${name}`);
        }
        if (config.defaultBurnWorkers !== 3
            || (!minimalRuntime && (config.advancedBurnWorkers !== 4
                || config.defaultBurnWorkers > config.advancedBurnWorkers)))
            throw new Error("P2JB worker geometry is unsupported");
        if (config.cleanupPipeHolds !== 4
            || config.cleanupWorkerDescriptors !== 4
            || config.cleanupParkedWorkers !== tuning.recvWorkers
                + tuning.readvWorkers + tuning.writevWorkers)
            throw new Error("P2JB cleanup geometry is unsupported");
        if (config.fdLimitTarget < config.freeFdCap + config.fdBudgetMargin
            + config.ipv6Sockets + 32
            || config.fdProbeBatch > 256
            || config.fdProbeHeartbeat < config.fdProbeBatch
            || config.fdProbeHeartbeat % config.fdProbeBatch !== 0)
            throw new Error("P2JB descriptor-probe geometry is unsupported");
        const structureNames = ["fileData", "fileCred", "fileRefcount",
            "pipeBuffer", "socketPcb", "fdescenttblHeader", "procThreads",
            "threadProc", "threadNext", "threadUcred", "ucredRef"];
        for (const name of structureNames)
            parseOffset(requirePath(config, `structureOffsets.${name}`),
                `p2jb.structureOffsets.${name}`);

        for (const name of ["kqueueex", "getrlimit", "setrlimit",
            "setuid", "open", "close", "pipe", "read", "write", "fcntl",
            "socket", "socketpair", "setsockopt", "getsockopt", "recvmsg",
            "readv", "writev", "kqueue", "umtxOp", "schedYield", "nanosleep",
            "pthreadCreate", "pthreadExit", "pthreadJoin",
            "cpusetGetaffinity", "cpusetSetaffinity", "rtprioThread",
            "ioctl", "getpid", "error", "mmap", "munmap"])
            parseOffset(requirePath(entry, `native.exports.${name}`),
                `native.exports.${name}`);
        for (const name of ["filedescentSize", "fdtOfiles", "kqueueFdp",
            "pipeSigio", "in6pOutputopts", "ip6poRthdr", "procPid",
            "procUcred", "procFd"])
            parseOffset(requirePath(entry, `kernel.structures.${name}`),
                `kernel.structures.${name}`);
        for (const name of ["afUnix", "sockStream", "fSetfl", "oNonblock",
            "ipprotoIpv6", "ipv6Rthdr", "umtxWaitPrivate",
            "umtxWakePrivate", "ucredSize", "rthdrTag", "msgIovNum",
            "uioIovNum", "uioSysspace", "solSocket", "soSndbuf",
            "pageSize"]) {
            parseOffset(requirePath(entry, `kernel.constants.${name}`),
                `kernel.constants.${name}`);
        }
        return true;
    }

    function validateExploitProfile(entry, firmware, metadata, exploit) {
        const attested = Object.prototype.hasOwnProperty.call(entry,
            "slopkitAttestation");
        if (attested) validateSlopkitLive(entry, firmware, metadata);
        else validateFull(entry, firmware, metadata);
        if (exploit === "poops") return validatePoops(entry);
        if (exploit === "lapse") return validateLapse(entry, firmware, metadata);
        if (exploit === "p2jb") return validateP2jb(entry, firmware, metadata);
        throw new Error(`unknown exploit ${exploit}`);
    }

    function firmwareList(values, label) {
        if (!Array.isArray(values) || values.length === 0
            || values.some((value) => !/^\d{2}\.\d{2}$/.test(value))
            || new Set(values).size !== values.length
            || values.some((value, index) => index > 0
                && value <= values[index - 1]))
            throw new Error(`offset database has invalid ${label}`);
        return values;
    }

    function declaredFirmwares(metadata, exploit) {
        if (Array.isArray(metadata?.supported)) {
            const values = metadata.supported
                .filter((tuple) => Array.isArray(tuple)
                    && tuple[0] === exploit)
                .map((tuple) => tuple[1]);
            return firmwareList(Array.from(new Set(values)).sort(),
                `${exploit} firmware inventory`);
        }
        const values = exploit === "p2jb"
            ? Object.keys(metadata?.p2jb?.firmwares || {}).sort()
            : metadata?.exploitFirmwares?.[exploit];
        return firmwareList(values, `${exploit} firmware inventory`);
    }

    function validateRevision(value, label) {
        if (typeof value !== "string" || !REVISION_PATTERN.test(value))
            throw new Error(`invalid qualification revision ${label}`);
        return value;
    }

    function qualificationRecord(metadata, exploit, firmware, mode) {
        if (Array.isArray(metadata?.supported)) {
            const found = metadata.supported.find((tuple) =>
                Array.isArray(tuple) && tuple.length === 6
                && tuple[0] === exploit && tuple[1] === firmware
                && tuple[2] === mode);
            return found ? {
                exploit, firmware, mode, status: "supported",
                profileRevision: found[3],
                engineRevision: found[4],
                runtimeRevision: found[5]
            } : null;
        }
        const records = metadata?.qualifications;
        if (!Array.isArray(records)) return null;
        return records.find((record) => record?.exploit === exploit
            && record.firmware === firmware && record.mode === mode) || null;
    }

    function validateQualificationInventory(data, exact) {
        const metadata = data._meta || {};
        const runtimeCatalog = metadata.catalog === RUNTIME_CATALOG;
        if (metadata.catalog !== undefined && !runtimeCatalog)
            throw new Error("offset database catalog is unsupported");
        if (Object.prototype.hasOwnProperty.call(metadata,
            "hardwareQualifiedFirmwares"))
            throw new Error("legacy firmware-global qualification is forbidden");

        const profileRevisions = requirePath(metadata, "profileRevisions");
        if (!profileRevisions || typeof profileRevisions !== "object"
            || Array.isArray(profileRevisions))
            throw new Error("profile revision inventory is invalid");
        const revisionFirmwares = Object.keys(profileRevisions).sort();
        const sortedExact = exact.slice().sort();
        if (revisionFirmwares.length !== sortedExact.length
            || revisionFirmwares.some((value, index) =>
                value !== sortedExact[index]))
            throw new Error("profile revision inventory disagrees with exact firmwares");
        for (const firmware of exact)
            validateRevision(profileRevisions[firmware], `profile ${firmware}`);
        const unsupportedProfiles = metadata.unsupportedProfileRevisions || {};
        if (!unsupportedProfiles || typeof unsupportedProfiles !== "object"
            || Array.isArray(unsupportedProfiles))
            throw new Error("unsupported profile revision inventory is invalid");
        for (const [firmware, revision] of Object.entries(
            unsupportedProfiles)) {
            if (!/^\d{2}\.\d{2}$/.test(firmware) || exact.includes(firmware))
                throw new Error(`invalid unsupported profile ${firmware}`);
            validateRevision(revision, `unsupported profile ${firmware}`);
        }

        const qualificationRevisions = requirePath(metadata,
            "qualificationRevisions");
        const runtimeRevision = validateRevision(requirePath(
            qualificationRevisions, "runtime"), "runtime");
        const engines = requirePath(qualificationRevisions, "engines");
        const engineNames = Object.keys(engines).sort();
        const exploitNames = Array.from(EXPLOITS).sort();
        if (engineNames.length !== exploitNames.length
            || engineNames.some((value, index) => value !== exploitNames[index]))
            throw new Error("engine revision inventory is incomplete");
        for (const exploit of EXPLOITS)
            validateRevision(engines[exploit], `engine ${exploit}`);

        const records = requirePath(metadata, "qualifications");
        if (!Array.isArray(records) || records.length === 0)
            throw new Error("qualification record inventory is invalid");
        const expectedKeys = new Set();
        for (const exploit of EXPLOITS) {
            for (const firmware of declaredFirmwares(metadata, exploit)) {
                if (!exact.includes(firmware)
                    && !Object.prototype.hasOwnProperty.call(
                        metadata.unsupportedProfileRevisions || {}, firmware))
                    throw new Error(`${exploit} qualification references unknown firmware ${firmware}`);
                for (const mode of FULL_MODES)
                    expectedKeys.add(`${exploit}:${firmware}:${mode}`);
            }
        }

        const seen = new Set();
        for (const record of records) {
            if (!record || typeof record !== "object" || Array.isArray(record))
                throw new Error("qualification record is not an object");
            const { exploit, firmware, mode, status } = record;
            const validStatus = runtimeCatalog
                ? status === "supported" : QUALIFICATION_STATUSES.has(status);
            const knownFirmware = exact.includes(firmware)
                || Object.prototype.hasOwnProperty.call(
                    metadata.unsupportedProfileRevisions || {}, firmware);
            if (!EXPLOITS.has(exploit) || !knownFirmware
                || !FULL_MODES.has(mode) || !validStatus)
                throw new Error("qualification record identity or status is invalid");
            const key = `${exploit}:${firmware}:${mode}`;
            if (!expectedKeys.has(key))
                throw new Error(`qualification record ${key} has no exploit capability`);
            if (seen.has(key))
                throw new Error(`duplicate qualification record ${key}`);
            seen.add(key);
            const expectedRevision = profileRevisions[firmware]
                || metadata.unsupportedProfileRevisions?.[firmware];
            if (record.profileRevision !== expectedRevision)
                throw new Error(`qualification record ${key} has stale profile revision`);
            if (record.engineRevision !== engines[exploit])
                throw new Error(`qualification record ${key} has stale engine revision`);
            if (record.runtimeRevision !== runtimeRevision)
                throw new Error(`qualification record ${key} has stale runtime revision`);
            if (runtimeCatalog) {
                if (Object.prototype.hasOwnProperty.call(record, "evidence"))
                    throw new Error(`runtime support record ${key} contains evidence`);
            } else if (typeof record.evidence !== "string"
                || record.evidence.length < 8 || record.evidence.length > 512) {
                throw new Error(`qualification record ${key} has invalid evidence`);
            }
            if (status !== "unsupported") {
                const entry = data[firmware];
                const exactIdentity = hasArtifactIdentity(entry);
                let liveAttested = false;
                if (entry && Object.prototype.hasOwnProperty.call(entry,
                    "slopkitAttestation")) {
                    validateSlopkitAttestation(entry, firmware);
                    liveAttested = true;
                }
                if (!exactIdentity && !liveAttested)
                    throw new Error(`qualification record ${key} lacks exact artifact identity`);
            }
        }
        if (seen.size !== expectedKeys.size
            || Array.from(expectedKeys).some((key) => !seen.has(key)))
            throw new Error("qualification record inventory is incomplete");
        return true;
    }

    function validateCompatibilityMatrix(matrix) {
        if (!Array.isArray(matrix) || matrix.length !== 82)
            throw new Error("compatibility matrix must cover 82 exploit/firmware pairs");
        const allowedStatuses = new Set(["supported", "unsupported"]);
        const evidenceClasses = new Set(["exact", "live-attested",
            "incomplete"]);
        const expected = {
            lapse: ["04.03", "04.50", "04.51", "05.00", "05.02",
                "05.10", "05.50", "06.00", "06.02", "06.50", "07.00",
                "07.01", "07.20", "07.40", "07.60", "07.61", "08.00",
                "08.20", "08.40", "08.60", "09.00", "09.05", "09.20",
                "09.40", "09.60", "10.00", "10.01"],
            poops: ["04.03", "04.50", "04.51", "05.00", "05.02",
                "05.10", "05.50", "06.00", "06.02", "06.50", "07.00",
                "07.01", "07.20", "07.40", "07.60", "07.61", "08.00",
                "08.20", "08.40", "08.60", "09.00", "09.05", "09.20",
                "09.40", "09.60", "10.00", "10.01", "10.20", "10.40",
                "10.60", "11.00", "11.20", "11.40", "11.60", "12.00"],
            p2jb: ["09.00", "09.05", "09.20", "09.40", "09.60",
                "10.00", "10.01", "10.20", "10.40", "10.60", "11.00",
                "11.20", "11.40", "11.60", "12.00", "12.02", "12.20",
                "12.40", "12.60", "12.70"]
        };
        const expectedKeys = new Set();
        for (const [exploit, firmwares] of Object.entries(expected))
            for (const firmware of firmwares)
                expectedKeys.add(`${exploit}:${firmware}`);
        const seen = new Set();
        for (const record of matrix) {
            exactObjectKeys(record, ["exploit", "firmware", "status",
                "evidenceClass", "evidence", "blockers", "artifacts"],
            "compatibility record");
            const key = `${record.exploit}:${record.firmware}`;
            if (!expectedKeys.has(key) || seen.has(key)
                || !allowedStatuses.has(record.status)
                || !evidenceClasses.has(record.evidenceClass)
                || typeof record.evidence !== "string"
                || record.evidence.length < 8
                || !Array.isArray(record.blockers)
                || !Array.isArray(record.artifacts))
                throw new Error(`invalid compatibility record ${key}`);
            if (record.status === "supported"
                && (record.blockers.length !== 0
                    || record.evidenceClass === "incomplete"))
                throw new Error(`supported compatibility record ${key} has blockers`);
            if (record.status === "unsupported"
                && (record.blockers.length === 0
                    || record.evidenceClass !== "incomplete"))
                throw new Error(`unsupported compatibility record ${key} lacks a blocker`);
            seen.add(key);
        }
        if (seen.size !== expectedKeys.size)
            throw new Error("compatibility matrix is incomplete");
        return true;
    }

    function validateCompatibilityParity(data, matrix) {
        const metadata = data._meta || {};
        const qualifications = requirePath(metadata, "qualifications");
        const matrixKeys = new Set(matrix.map((record) =>
            `${record.exploit}:${record.firmware}`));
        const matrixFirmwares = new Set(matrix.map((record) =>
            record.firmware));
        const supportedProfiles = new Set(matrix.filter((record) =>
            record.status === "supported").map((record) => record.firmware));
        for (const exploit of EXPLOITS) {
            for (const firmware of declaredFirmwares(metadata, exploit)) {
                if (!matrixKeys.has(`${exploit}:${firmware}`))
                    throw new Error(`${exploit} firmware ${firmware} is outside the compatibility matrix`);
            }
        }
        for (const firmware of Object.keys(
            metadata.unsupportedProfileRevisions || {})) {
            if (!matrixFirmwares.has(firmware))
                throw new Error(`unsupported profile ${firmware} is outside the compatibility matrix`);
        }
        for (const firmware of metadata.operationalFirmwares || []) {
            if (!supportedProfiles.has(firmware))
                throw new Error(`operational profile ${firmware} has no supported compatibility record`);
        }
        for (const record of matrix) {
            const key = `${record.exploit}:${record.firmware}`;
            const declared = declaredFirmwares(metadata, record.exploit)
                .includes(record.firmware);
            const pair = qualifications.filter((item) =>
                item.exploit === record.exploit
                && item.firmware === record.firmware);
            const modes = new Set(pair.map((item) => item.mode));
            if (record.status === "supported") {
                if (!declared || !data[record.firmware])
                    throw new Error(`supported compatibility record ${key} has no operational profile`);
                if (pair.length !== FULL_MODES.size
                    || modes.size !== FULL_MODES.size
                    || Array.from(FULL_MODES).some((mode) => !modes.has(mode))
                    || pair.some((item) => item.status !== "supported"))
                    throw new Error(`supported compatibility record ${key} disagrees with run modes`);
                const expectedClass = Object.prototype.hasOwnProperty.call(
                    data[record.firmware], "slopkitAttestation")
                    ? "live-attested" : "exact";
                if (record.evidenceClass !== expectedClass)
                    throw new Error(`supported compatibility record ${key} disagrees with profile evidence`);
            } else if (pair.some((item) => item.status !== "unsupported")) {
                throw new Error(`unsupported compatibility record ${key} is launchable`);
            }
            if (!declared && pair.length !== 0)
                throw new Error(`compatibility record ${key} has undeclared run modes`);
            if (record.exploit === "p2jb") {
                const firmwareConfig = metadata.p2jb?.firmwares?.[record.firmware];
                if (!firmwareConfig
                    || firmwareConfig.evidenceClass !== record.evidenceClass)
                    throw new Error(`P2JB compatibility record ${key} disagrees with firmware evidence`);
                if (record.status === "supported")
                    validateP2jbFirmwareMetadata(data[record.firmware],
                        record.firmware, metadata);
            }
        }
        return true;
    }

    function validateDatabase(data, firmware) {
        const metadata = data._meta || {};
        if (metadata.schemaVersion !== 5)
            throw new Error("offset database schema is unsupported");
        validateRendererContractInventory(metadata);
        if (Array.isArray(metadata.supported)) {
            if (metadata.supported.length === 0)
                throw new Error("runtime support inventory is empty");
            const seen = new Set();
            const pairModes = new Map();
            const profileRevisions = new Map();
            const engineRevisions = new Map();
            let runtimeRevision = null;
            for (const tuple of metadata.supported) {
                if (!Array.isArray(tuple) || tuple.length !== 6
                    || !EXPLOITS.has(tuple[0])
                    || !/^\d{2}\.\d{2}$/.test(tuple[1])
                    || !FULL_MODES.has(tuple[2]))
                    throw new Error("runtime support tuple is invalid");
                const profileRevision = validateRevision(tuple[3],
                    `runtime profile ${tuple[1]}`);
                const engineRevision = validateRevision(tuple[4],
                    `runtime engine ${tuple[0]}`);
                const tupleRuntimeRevision = validateRevision(tuple[5],
                    "runtime");
                const key = tuple.slice(0, 3).join(":");
                if (seen.has(key))
                    throw new Error(`duplicate runtime support tuple ${key}`);
                seen.add(key);
                if (profileRevisions.has(tuple[1])
                    && profileRevisions.get(tuple[1]) !== profileRevision)
                    throw new Error(`runtime profile ${tuple[1]} has inconsistent revisions`);
                profileRevisions.set(tuple[1], profileRevision);
                if (engineRevisions.has(tuple[0])
                    && engineRevisions.get(tuple[0]) !== engineRevision)
                    throw new Error(`runtime engine ${tuple[0]} has inconsistent revisions`);
                engineRevisions.set(tuple[0], engineRevision);
                if (runtimeRevision !== null
                    && runtimeRevision !== tupleRuntimeRevision)
                    throw new Error("runtime support inventory has inconsistent runtime revisions");
                runtimeRevision = tupleRuntimeRevision;
                const pair = `${tuple[0]}:${tuple[1]}`;
                if (!pairModes.has(pair)) pairModes.set(pair, new Set());
                pairModes.get(pair).add(tuple[2]);
            }
            if (Array.from(pairModes.values()).some((modes) =>
                modes.size !== FULL_MODES.size
                    || Array.from(FULL_MODES).some((mode) => !modes.has(mode))))
                throw new Error("runtime support pair lacks a run mode");
            const exact = Array.from(new Set(metadata.supported.map(
                (tuple) => tuple[1]))).sort();
            const declared = Object.keys(data)
                .filter((name) => name !== "_meta").sort();
            if (declared.length !== exact.length
                || declared.some((value, index) => value !== exact[index]))
                throw new Error("runtime support inventory disagrees with profiles");
            for (const p2jbFirmware of declaredFirmwares(metadata, "p2jb"))
                validateP2jbFirmwareMetadata(data[p2jbFirmware],
                    p2jbFirmware, metadata);
            if (!exact.includes(firmware))
                throw new Error(`firmware ${firmware} has no exact full-chain profile`);
            return;
        }
        const exact = firmwareList(metadata.operationalFirmwares,
            "operationalFirmwares");
        const matrix = metadata.compatibilityMatrix;
        if (metadata.catalog === RUNTIME_CATALOG) {
            if (matrix !== undefined)
                throw new Error("runtime catalog contains a compatibility matrix");
        } else {
            validateCompatibilityMatrix(matrix);
        }
        const declared = Object.keys(data)
            .filter((name) => name !== "_meta").sort();
        if (declared.length !== exact.length
            || declared.some((value, index) => value !== exact[index]))
            throw new Error("operational firmware inventory disagrees with profile entries");
        validateQualificationInventory(data, exact);
        if (metadata.catalog === RUNTIME_CATALOG) {
            const p2jbFirmwares = new Set(metadata.qualifications
                .filter((record) => record.exploit === "p2jb"
                    && record.status === "supported")
                .map((record) => record.firmware));
            for (const p2jbFirmware of p2jbFirmwares)
                validateP2jbFirmwareMetadata(data[p2jbFirmware],
                    p2jbFirmware, metadata);
        } else {
            validateCompatibilityParity(data, matrix);
        }
        for (const referenceFirmware of exact) {
            const reference = data[referenceFirmware];
            if (!reference || !Object.prototype.hasOwnProperty.call(reference,
                "slopkitAttestation")) continue;
            validateSlopkitAttestation(reference, referenceFirmware);
            for (const otherFirmware of exact) {
                if (otherFirmware === referenceFirmware) continue;
                const other = data[otherFirmware]?.verified;
                if (!other || typeof other !== "object") continue;
                for (const name of ["libkernelWebSha256",
                    "libcInternalSha256"]) {
                    if (reference.verified[name] === other[name])
                        throw new Error(`SlopKit attestation ${referenceFirmware} aliases ${otherFirmware} ${name}`);
                }
            }
        }
        if (!exact.includes(firmware))
            throw new Error(`firmware ${firmware} has no exact full-chain profile`);
    }

    function selectExact(data, firmware, mode) {
        if (!data || typeof data !== "object")
            throw new TypeError("offset database is not an object");
        if (!firmware) throw new Error("not a PS5 browser");
        const entry = data[firmware];
        if (!entry) throw new Error(`firmware ${firmware} has no exact profile`);
        const requested = mode || "full";
        if (!FULL_MODES.has(requested))
            throw new Error(`unknown run mode ${requested}`);
        validateDatabase(data, firmware);
        validateFull(entry, firmware, data._meta || {});
        return new FirmwareProfile(firmware, requested, entry, data._meta || {},
            null, null);
    }

    function selectForExploit(data, firmware, mode, exploit) {
        if (!data || typeof data !== "object")
            throw new TypeError("offset database is not an object");
        if (!firmware) throw new Error("not a PS5 browser");
        const selected = exploit || "poops";
        if (!EXPLOITS.has(selected))
            throw new Error(`unknown exploit ${selected}`);
        const requested = mode || "full";
        if (!FULL_MODES.has(requested))
            throw new Error(`unknown run mode ${requested}`);
        const metadata = data._meta || {};
        const declared = declaredFirmwares(metadata, selected);
        if (!declared.includes(firmware))
            throw new Error(`${selected.toUpperCase()} is unavailable on firmware ${firmware}`);

        const qualification = qualificationRecord(metadata, selected,
            firmware, requested);
        if (!qualification || qualification.status === "unsupported") {
            const detail = qualification?.evidence
                ? `: ${qualification.evidence}` : "";
            throw new Error(`${selected.toUpperCase()} is unavailable on firmware ${firmware}${detail}`);
        }

        const entry = data[firmware];
        if (!entry)
            throw new Error(`${selected.toUpperCase()} is unavailable on firmware ${firmware}: operational profile is absent`);
        validateDatabase(data, firmware);

        validateExploitProfile(entry, firmware, metadata, selected);
        return new FirmwareProfile(firmware, requested, entry,
            metadata, selected, qualification);
    }

    function supportedFirmwares(data, exploit, mode) {
        if (!data || typeof data !== "object") return [];
        const selected = exploit || "poops";
        if (!EXPLOITS.has(selected)) return [];
        const requested = mode || "elf-loader";
        if (!FULL_MODES.has(requested)) return [];
        const metadata = data._meta || {};
        let declared;
        try {
            const exact = Array.isArray(metadata.supported)
                ? firmwareList(Array.from(new Set(metadata.supported.map(
                    (tuple) => tuple[1]))).sort(), "runtime firmware inventory")
                : firmwareList(metadata.operationalFirmwares,
                    "operationalFirmwares");
            validateDatabase(data, exact[0]);
            declared = declaredFirmwares(metadata, selected);
        }
        catch { return []; }
        return declared.filter((firmware) => {
            const record = qualificationRecord(metadata, selected,
                firmware, requested);
            if (!data[firmware] || !record || record.status === "unsupported")
                return false;
            try {
                validateExploitProfile(data[firmware], firmware, metadata,
                    selected);
                return true;
            }
            catch { return false; }
        });
    }

    class FirmwareProfile {
        constructor(firmware, mode, raw, metadata, exploit, qualification) {
            this.firmware = firmware;
            this.mode = mode;
            this.exploit = exploit === undefined ? "poops" : exploit;
            this.raw = raw;
            this.metadata = metadata;
            const record = qualification || (this.exploit
                ? qualificationRecord(metadata, this.exploit, firmware, mode)
                : null);
            this._qualification = record
                ? Object.freeze(Object.assign({}, record)) : null;
            this._rendererContract = resolveRendererContract(metadata, raw);
        }

        offset(path) { return parseOffset(requirePath(this.raw, path), path); }
        value(path) { return requirePath(this.raw, path); }
        qualification() {
            return this._qualification?.status || "supported";
        }
        qualificationRecord() { return this._qualification; }
        rendererContract() { return this._rendererContract; }
        isXomCode() {
            return hasArtifactIdentity(this.raw)
                && this.raw.verified.xomCode === true;
        }
        isSlopkitAttested() {
            return isSlopkitAttested(this.raw, this.firmware);
        }
        isPoopsReferenceAttested() {
            return this.exploit === "poops" && this.isSlopkitAttested();
        }
        webkitCodeLimit() {
            return this.isSlopkitAttested()
                ? this.offset("slopkitAttestation.webkitCodeLimit")
                : this.offset("webkit.textSize");
        }
        lapseConfig() {
            if (this.exploit !== "lapse")
                throw new Error("Lapse metadata requested for another exploit");
            return freezeTree(Object.assign({}, validateLapseConfig(this.raw,
                this.firmware, this.metadata)));
        }
        p2jbConfig() {
            if (this.exploit !== "p2jb")
                throw new Error("P2JB metadata requested for another exploit");
            return p2jbMetadata(this.metadata, this.firmware);
        }
        p2jbOffset(name) {
            const { config, firmware } = this.p2jbConfig();
            if (Object.prototype.hasOwnProperty.call(firmware, name))
                return parseOffset(firmware[name], `p2jb.firmwares.${this.firmware}.${name}`);
            return parseOffset(requirePath(config, `structureOffsets.${name}`),
                `p2jb.structureOffsets.${name}`);
        }
        p2jbValue(name) {
            return requirePath(this.p2jbConfig().config, name);
        }
        p2jbQualification() {
            const firmware = this.p2jbConfig().firmware;
            return Object.freeze({ evidenceClass: firmware.evidenceClass,
                evidence: firmware.evidence,
                status: this.qualification(),
                profileRevision: this._qualification?.profileRevision,
                engineRevision: this._qualification?.engineRevision,
                runtimeRevision: this._qualification?.runtimeRevision,
                mode: this.mode });
        }

        rendererQuery(extra) {
            const q = new URLSearchParams(extra || {});
            q.set("go", "1");
            q.set("fw", this.firmware);
            q.set("mode", this.mode);
            q.set("schema", String(this.metadata.schemaVersion || 0));
            q.set("hc", this.raw.webkit.hostConstructors.join(","));
            q.set("gd", this.raw.native.context.naturalTrampoline);
            q.set("notify", this.raw.native.exports.notify);
            if (this.isSlopkitAttested()) {
                const attestation = this.raw.slopkitAttestation;
                q.set("att", attestation.kind);
                q.set("kis", attestation.kernelImport.slot);
                q.set("kie", attestation.kernelImport.export);
                q.set("lis", attestation.libcImport.slot);
                q.set("lie", attestation.libcImport.export);
                q.set("wcl", attestation.webkitCodeLimit);
            } else {
                q.set("gps", this.raw.webkit.imports.getpid.slot);
                q.set("gpe", this.raw.webkit.imports.getpid.export);
                q.set("cls", this.raw.webkit.imports.close.slot);
                q.set("cle", this.raw.webkit.imports.close.export);
                q.set("ers", this.raw.webkit.imports.error.slot);
                q.set("ere", this.raw.webkit.imports.error.export);
                q.set("wts", this.raw.webkit.textSize);
            }
            if (this.raw.native?.textSize)
                q.set("nts", this.raw.native.textSize);
            q.set("rc", encodeRendererContract(this._rendererContract));
            return q;
        }
    }

    async function loadDatabase(url) {
        const response = await fetch(url || "offsets/offsets.json", { cache: "no-store" });
        if (!response.ok) throw new Error(`offset request failed: ${response.status}`);
        return response.json();
    }

    async function loadExact(url, firmware, mode) {
        return selectExact(await loadDatabase(url), firmware, mode);
    }

    async function loadForExploit(url, firmware, mode, exploit) {
        return selectForExploit(await loadDatabase(url), firmware, mode, exploit);
    }

    NS.Profile = {
        FirmwareProfile,
        detectFirmware,
        parseOffset,
        encodeRendererContract,
        decodeRendererContract,
        validateDatabase,
        validateFull,
        validateSlopkitLive,
        validateSlopkitAttestation,
        isSlopkitAttested,
        validatePoops,
        validateLapse,
        validateP2jb,
        validateCompatibilityMatrix,
        validateCompatibilityParity,
        validateExploitProfile,
        selectExact,
        selectForExploit,
        supportedFirmwares,
        loadDatabase,
        loadExact,
        loadForExploit
    };
    if (typeof module !== "undefined" && module.exports)
        module.exports = NS.Profile;
})(typeof globalThis !== "undefined" ? globalThis : this);

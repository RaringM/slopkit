(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const BASE_LOCALE = "en";
    const LOAD_TIMEOUT_MS = 3000;

    const ENGLISH = Object.freeze({
        "common.about": "About",
        "common.close": "Close",
        "common.loading": "Loading…",
        "common.settings": "Settings",

        "language.auto": "Auto",
        "language.label": "Language",

        "exploit.option.poops": "POOPS",
        "exploit.option.lapse": "Lapse",
        "exploit.option.p2jb": "P2JB",
        "launcher.run": "Run {exploit}",
        "launcher.clear": "I rebooted",
        "launcher.clearCold": "I powered off and restarted",
        "launcher.settings.exploit": "Exploit",
        "launcher.settings.autoAutoloader":
            "Auto-launch Unified Autoloader",
        "launcher.pending.queued": "Requested action queued: {action}",
        "launcher.pending.cancel": "Cancel",
        "launcher.settings.diagnostics": "Show console",
        "launcher.about.firmware": "Supported firmware · {exploit}",
        "launcher.about.credits": "Credits",
        "launcher.about.reset": "Reset stats",
        "launcher.about.reliability": "Attempt history",
        "launcher.about.source": "Source code",
        "launcher.about.none": "None",
        "launcher.stats.none": "No attempts",
        "launcher.stats.row": "{exploit}: {wins}/{total} ({rate}%)",
        "launcher.status.preparing": "Preparing…",
        "launcher.status.starting": "Starting…",
        "launcher.status.ready": "Firmware {firmware} · Ready",
        "launcher.status.browserRequired": "PS5 browser required",
        "launcher.status.exploitUnavailable":
            "No exploit available for firmware {firmware}",
        "launcher.status.dataUnavailable": "Couldn’t load firmware data",
        "launcher.status.dataInvalid": "Firmware data invalid",
        "launcher.status.storageUnavailable":
            "Browser storage unavailable · Cannot start safely",
        "launcher.status.reboot": "Reboot before trying again",
        "launcher.status.coldPower":
            "Power off fully before trying again · Do not use Restart PS5",
        "launcher.confirm.reset": "Reset all stats?",
        "launcher.stats.summary":
            "{wins} of {total} successful ({rate}%)",

        "runtime.caption": "slopkit · PS5 {firmware}",
        "runtime.stage.preparing": "Preparing",
        "runtime.stage.preparingP2jb": "Preparing P2JB",
        "runtime.stage.runningPoops": "Running POOPS · Keep this page open",
        "runtime.stage.runningLapse": "Running Lapse · Keep this page open",
        "runtime.stage.runningP2jb": "Running P2JB · Keep this page open",
        "runtime.stage.finishing": "Finishing",
        "runtime.stage.preparingElfldr": "Preparing elfldr",
        "runtime.stage.startingElfldr": "Starting elfldr",
        "runtime.stage.startingRequestedAction": "Sending requested action",
        "runtime.stage.startingAutoloader":
            "Sending Unified Autoloader",
        "runtime.stage.complete": "Complete",
        "runtime.stage.preview": "UI preview",
        "runtime.stage.stopped": "Stopped",
        "runtime.stage.powerOff": "Turn off PS5 completely",
        "runtime.status.poops":
            "If this page freezes, hold the power button until the PS5 turns off, then power it on.",
        "runtime.status.p2jbChecking": "Checking requirements…",
        "runtime.status.p2jbInitial": "0% · 0s elapsed · Estimating…",
        "runtime.status.p2jbEstimating":
            "{percent}% · {elapsed} elapsed · Estimating…",
        "runtime.status.p2jbRemaining":
            "{percent}% · {elapsed} elapsed · ~{remaining} left",
        "runtime.status.p2jbComplete": "100% · {elapsed} elapsed",
        "runtime.status.reboot": "Reboot before trying again",
        "runtime.status.coldPower":
            "Hold the physical power button until all lights are off · Do not use Restart PS5",
        "runtime.status.openLauncher": "Open from launcher",
        "runtime.status.preview": "Preview only · No exploit will run",
        "runtime.status.browserUnsupported": "Browser not supported",
        "runtime.status.autoloaderStarting": "Handing off…",
        "runtime.diagnostics.heading": "Console",
        "runtime.actions.heading": "Post-exploit actions",
        "runtime.requested.title": "Requested action",
        "runtime.requested.run": "Run requested action",
        "runtime.requested.sending": "Sending requested action…",
        "runtime.requested.sent": "Requested action sent",
        "runtime.requested.retry": "Retry requested action",
        "runtime.requested.failed": "Requested action failed",
        "runtime.requested.unavailable": "Requested action unavailable",
        "runtime.requested.sentStatus": "Check the PS5 notification",
        "runtime.requested.failedStatus": "Retry without rebooting",
        "runtime.autoloader.heading": "Unified Autoloader",
        "runtime.autoloader.launch": "Launch Unified Autoloader",
        "runtime.autoloader.launching": "Sending Unified Autoloader…",
        "runtime.autoloader.retry": "Retry Unified Autoloader",
        "runtime.autoloader.failed": "Couldn’t send Unified Autoloader",
        "runtime.autoloader.sent": "Unified Autoloader sent",
        "runtime.autoloader.unavailable":
            "Unified Autoloader unavailable",
        "runtime.autoloader.failedStatus": "Retry without rebooting",
        "runtime.payload.launchAction": "Launch {action}",
        "runtime.payload.launching": "Launching…",
        "runtime.payload.retry": "Retry",
        "runtime.payload.failed": "Launch failed",
        "runtime.payload.sent": "{action} sent",
        "runtime.payload.unavailable": "Action unavailable",
        "runtime.payload.sentStatus": "Payload sent.",

        "time.seconds": "{seconds}s",
        "time.minutes": "{minutes}m {seconds}s",
        "time.hours": "{hours}h {minutes}m {seconds}s"
    });

    const localeMetadata = Object.create(null);
    const catalogs = Object.create(null);
    localeMetadata.en = Object.freeze({
        locale: "en", label: "English", dir: "ltr", url: null
    });
    catalogs.en = ENGLISH;

    let activeLocale = BASE_LOCALE;
    let activeCatalog = ENGLISH;
    let lastLoadError = null;
    let readyPromise = Promise.resolve(BASE_LOCALE);
    let activationSequence = 0;

    function normalizeLocale(value) {
        return String(value || "").trim().replace(/_/g, "-").toLowerCase();
    }

    function validLocale(value) {
        return /^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/.test(value);
    }

    function placeholders(value) {
        const found = [];
        String(value).replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g,
            function (_, name) { found.push(name); return _; });
        return Array.from(new Set(found)).sort();
    }

    function validateMessages(locale, messages) {
        if (!messages || typeof messages !== "object" || Array.isArray(messages))
            throw new TypeError(`locale ${locale} messages are invalid`);
        const baseKeys = Object.keys(ENGLISH).sort();
        const keys = Object.keys(messages).sort();
        if (keys.length !== baseKeys.length
                || keys.some(function (key, index) { return key !== baseKeys[index]; }))
            throw new Error(`locale ${locale} keys do not match English`);
        for (const key of baseKeys) {
            const value = messages[key];
            if (typeof value !== "string" || !value.trim())
                throw new Error(`locale ${locale} has an empty ${key}`);
            if (/[<>]/.test(value))
                throw new Error(`locale ${locale} ${key} must be plain text`);
            const expected = placeholders(ENGLISH[key]);
            const actual = placeholders(value);
            if (expected.length !== actual.length
                    || expected.some(function (name, index) {
                        return name !== actual[index];
                    }))
                throw new Error(`locale ${locale} ${key} placeholders differ`);
        }
        return true;
    }

    function registerLocale(metadata) {
        const locale = normalizeLocale(metadata?.locale);
        if (!validLocale(locale) || locale === BASE_LOCALE)
            throw new Error(`invalid locale registration ${locale || "(empty)"}`);
        if (!metadata || typeof metadata.label !== "string"
                || !metadata.label.trim() || !/^(ltr|rtl)$/.test(metadata.dir)
                || typeof metadata.url !== "string" || !metadata.url)
            throw new Error(`locale ${locale} metadata is invalid`);
        localeMetadata[locale] = Object.freeze({
            locale,
            label: metadata.label.trim(),
            dir: metadata.dir,
            url: metadata.url
        });
        return locale;
    }

    registerLocale({
        locale: "es", label: "Español", dir: "ltr", url: "locales/es.json"
    });

    function registerCatalog(locale, messages) {
        const normalized = normalizeLocale(locale);
        if (!localeMetadata[normalized])
            throw new Error(`locale ${normalized} is not registered`);
        validateMessages(normalized, messages);
        catalogs[normalized] = Object.freeze(Object.assign({}, messages));
        return normalized;
    }

    function availableLocales() {
        return Object.keys(localeMetadata).sort().map(function (locale) {
            return localeMetadata[locale];
        });
    }

    function resolveLocale(preference, browserLocales) {
        const requested = [];
        const explicit = normalizeLocale(preference);
        if (explicit && explicit !== "auto") {
            requested.push(explicit);
        } else {
            const values = Array.isArray(browserLocales)
                ? browserLocales : [browserLocales];
            for (const value of values) {
                const normalized = normalizeLocale(value);
                if (normalized) requested.push(normalized);
            }
        }
        for (const locale of requested) {
            if (localeMetadata[locale]) return locale;
            const base = locale.split("-")[0];
            if (localeMetadata[base]) return base;
        }
        return BASE_LOCALE;
    }

    function loadCatalog(locale) {
        if (catalogs[locale]) return Promise.resolve(catalogs[locale]);
        const metadata = localeMetadata[locale];
        if (!metadata?.url || typeof root.XMLHttpRequest !== "function")
            return Promise.reject(new Error(`locale ${locale} is unavailable`));
        return new Promise(function (resolve, reject) {
            const xhr = new root.XMLHttpRequest();
            let settled = false;
            function finish(error, messages) {
                if (settled) return;
                settled = true;
                if (error) reject(error);
                else resolve(messages);
            }
            xhr.open("GET", metadata.url, true);
            xhr.timeout = LOAD_TIMEOUT_MS;
            xhr.onload = function () {
                if (xhr.status < 200 || xhr.status >= 300) {
                    finish(new Error(`locale ${locale} request failed: ${xhr.status}`));
                    return;
                }
                try {
                    const payload = JSON.parse(xhr.responseText);
                    if (normalizeLocale(payload?.locale) !== locale)
                        throw new Error(`locale ${locale} response disagrees`);
                    registerCatalog(locale, payload.messages);
                    finish(null, catalogs[locale]);
                } catch (error) {
                    finish(error);
                }
            };
            xhr.onerror = function () {
                finish(new Error(`locale ${locale} request failed`));
            };
            xhr.ontimeout = function () {
                try { xhr.abort(); } catch {}
                finish(new Error(`locale ${locale} request timed out`));
            };
            try { xhr.send(); }
            catch (error) { finish(error); }
        });
    }

    function setDocumentLanguage() {
        const documentNode = root.document;
        if (!documentNode?.documentElement) return;
        const metadata = localeMetadata[activeLocale]
            || localeMetadata[BASE_LOCALE];
        documentNode.documentElement.lang = activeLocale;
        documentNode.documentElement.dir = metadata.dir;
    }

    function activate(preference, browserLocales) {
        const locale = resolveLocale(preference, browserLocales);
        const sequence = ++activationSequence;
        lastLoadError = null;
        const candidates = [locale];
        const base = locale.split("-")[0];
        if (base !== locale && localeMetadata[base]) candidates.push(base);
        if (!candidates.includes(BASE_LOCALE)) candidates.push(BASE_LOCALE);
        let firstError = null;

        function loadCandidate(index) {
            const candidate = candidates[index];
            return loadCatalog(candidate).then(function (catalog) {
                return { catalog, locale: candidate };
            }).catch(function (error) {
                if (!firstError) firstError = error;
                if (index + 1 < candidates.length)
                    return loadCandidate(index + 1);
                throw error;
            });
        }

        readyPromise = loadCandidate(0).then(function (result) {
            if (sequence !== activationSequence) return activeLocale;
            lastLoadError = firstError;
            activeLocale = result.locale;
            activeCatalog = result.catalog;
            setDocumentLanguage();
            if (firstError) {
                try { root.console?.warn?.(firstError); } catch {}
            }
            return result.locale;
        }).catch(function (error) {
            if (sequence !== activationSequence) return activeLocale;
            lastLoadError = error;
            activeLocale = BASE_LOCALE;
            activeCatalog = ENGLISH;
            setDocumentLanguage();
            try { root.console?.warn?.(error); } catch {}
            return BASE_LOCALE;
        });
        return readyPromise;
    }

    function translate(key, values) {
        const template = activeCatalog[key] ?? ENGLISH[key];
        if (typeof template !== "string") return String(key);
        const replacements = values || {};
        return template.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g,
            function (token, name) {
                return Object.prototype.hasOwnProperty.call(replacements, name)
                    ? String(replacements[name]) : token;
            });
    }

    function apply(rootNode) {
        const documentNode = root.document;
        const scope = rootNode || documentNode;
        if (!scope?.querySelectorAll) return;
        setDocumentLanguage();
        const textNodes = Array.from(scope.querySelectorAll("[data-i18n]"));
        if (scope.matches?.("[data-i18n]")) textNodes.unshift(scope);
        for (const node of textNodes)
            node.textContent = translate(node.getAttribute("data-i18n"));
        const ariaNodes = Array.from(scope.querySelectorAll(
            "[data-i18n-aria-label]"));
        if (scope.matches?.("[data-i18n-aria-label]"))
            ariaNodes.unshift(scope);
        for (const node of ariaNodes) {
            node.setAttribute("aria-label",
                translate(node.getAttribute("data-i18n-aria-label")));
        }
    }

    const I18n = {
        activate,
        apply,
        availableLocales,
        registerCatalog,
        registerLocale,
        resolveLocale,
        t: translate,
        validateMessages,
        get locale() { return activeLocale; },
        get lastLoadError() { return lastLoadError; },
        get ready() { return readyPromise; },
        BASE_LOCALE,
        LOAD_TIMEOUT_MS
    };

    NS.I18n = I18n;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { I18n, ENGLISH };
})(typeof globalThis !== "undefined" ? globalThis : this);

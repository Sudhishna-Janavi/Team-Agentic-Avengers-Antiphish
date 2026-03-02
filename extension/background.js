// 1. GLOBAL STATE & LISTENERS (Must be at top-level for MV3)
let session = null;
let isEnabled = true;
const proceedURLs = new Set();

const BLACKLIST = ['rnicrosoft.com', 'paypaI.com', 'amaz0n.com', 'gooogle.com', 'ntu-portal.net'];
const WHITELIST = ['ntu.edu.sg', 'google.com', 'github.com', 'microsoft.com'];

// Receiver for the "Proceed Anyway" Handshake
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "proceedToURL") {
        console.log("🔓 Whitelisting URL for session:", request.url);
        proceedURLs.add(request.url);
        sendResponse({ status: "whitelisted" });
    }
    if (request.action === "updateState") {
        isEnabled = request.state;
        sendResponse({ status: "updated" });
    }
    return true; // CRITICAL: Keeps channel open for the response
});

// 2. IMPORT LIBRARIES
importScripts('./lib/ort.min.js');

// 3. NAVIGATION SENTRY (Hybrid Logic)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const urlToCheck = changeInfo.url || tab.url;
    if (!urlToCheck || urlToCheck.startsWith('chrome://')) return;

    const domain = new URL(urlToCheck).hostname.toLowerCase();

    // Layer 1: Global Checks
    if (!isEnabled || proceedURLs.has(urlToCheck) || urlToCheck.includes("warning.html")) return;

    // Layer 2: Whitelist (Speed)
    if (WHITELIST.some(site => domain.endsWith(site))) return;

    // Layer 3: Blacklist (Immediate Block)
    if (BLACKLIST.some(site => domain.includes(site))) {
        console.warn("🚨 BLACKLIST MATCH:", domain);
        const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(urlToCheck);
        chrome.tabs.update(tabId, { url: warningUrl });
        return; 
    }

    // Layer 4: AI Inference (Zero-Day)
    if (session && changeInfo.status === 'complete') {
        runAIInference(tabId, urlToCheck);
    }
});

// 4. AI INITIALIZATION (Isolated to prevent script crash)
async function initModel() {
    try {
        const ortApi = self.ort;
        ortApi.env.wasm.proxy = false; // Fixes 'import()' error
        ortApi.env.wasm.wasmPaths = chrome.runtime.getURL('lib/');
        
        const modelUrl = chrome.runtime.getURL('model/antiphish_model.onnx');
        session = await ortApi.InferenceSession.create(modelUrl, { executionProviders: ['wasm'] });
        console.log("✅ AI Engine Loaded.");
    } catch (e) {
        console.error("❌ AI Error (Blacklist still active):", e);
    }
}

async function runAIInference(tabId, url) {
    const features = new Float32Array(12).fill(0.5); 
    const inputTensor = new self.ort.Tensor('float32', features, [1, 12]);
    const results = await session.run({ float_input: inputTensor });
    
    if (Number(results.label.data[0]) === 1) {
        const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(url);
        chrome.tabs.update(tabId, { url: warningUrl });
    }
}

initModel();
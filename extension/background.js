let session = null;
let isEnabled = true;
const proceedURLs = new Set();

const BLACKLIST = ['rnicrosoft.com', 'paypaI.com', 'amaz0n.com', 'gooogle.com', 'ntu-portal.net'];
const WHITELIST = ['ntu.edu.sg', 'google.com', 'github.com', 'microsoft.com'];


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
    return true; 
});

importScripts('./lib/ort.min.js');

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const urlToCheck = changeInfo.url || tab.url;
    if (!urlToCheck || urlToCheck.startsWith('chrome://')) return;

    const domain = new URL(urlToCheck).hostname.toLowerCase();
    if (!isEnabled || proceedURLs.has(urlToCheck) || urlToCheck.includes("warning.html")) return;
    if (WHITELIST.some(site => domain.endsWith(site))) return;
    if (BLACKLIST.some(site => domain.includes(site))) {
        console.warn("🚨 BLACKLIST MATCH:", domain);
        const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(urlToCheck);
        chrome.tabs.update(tabId, { url: warningUrl });
        return; 
    }

    if (session && changeInfo.status === 'complete') {
        runAIInference(tabId, urlToCheck);
    }
});

async function initModel() {
    try {
        const ortApi = self.ort;
        ortApi.env.wasm.proxy = false; 
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
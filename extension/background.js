import * as ort from 'onnxruntime-web';
let session = null;
const BLACKLIST = ['rnicrosoft.com', 'paypaI.com', 'amaz0n.com', 'gooogle.com', 'ntu-portal.net'];
const WHITELIST = ['ntu.edu.sg', 'google.com', 'github.com', 'microsoft.com'];

async function getAppState() {
    const data = await chrome.storage.local.get(['isEnabled', 'proceedURLs']);
    return {
        isEnabled: data.isEnabled !== false, 
        proceedURLs: new Set(data.proceedURLs || [])
    };
}

async function initModel() {
    if (session) return session;
    try {
        ort.env.wasm.wasmPaths = chrome.runtime.getURL('lib/');
        ort.env.wasm.proxy = false;
        ort.env.wasm.numThreads = 1;

        const modelUrl = chrome.runtime.getURL('model/antiphish_model.onnx');
        session = await ort.InferenceSession.create(modelUrl, { 
            executionProviders: ['wasm'] 
        });
        
        console.log("✅ AI Engine Loaded successfully!");
        return session;
    } catch (e) {
        console.error("❌ AI Loading Error:", e);
        return null;
    }
}
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleInternalMessages(request, sendResponse);
    return true; 
});

async function handleInternalMessages(request, sendResponse) {
    const state = await getAppState();

    if (request.action === "proceedToURL") {
        console.log("🔓 Whitelisting URL:", request.url);
        state.proceedURLs.add(request.url);
        await chrome.storage.local.set({ proceedURLs: Array.from(state.proceedURLs) });
        sendResponse({ status: "whitelisted" });
    }

    if (request.action === "updateState") {
        await chrome.storage.local.set({ isEnabled: request.state });
        sendResponse({ status: "updated" });
    }
}
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    const { isEnabled, proceedURLs } = await getAppState();
    const urlToCheck = changeInfo.url || tab.url;
    if (!urlToCheck || urlToCheck.startsWith('chrome://')) return;
    if (!isEnabled || proceedURLs.has(urlToCheck) || urlToCheck.includes("warning.html")) return;

    const domain = new URL(urlToCheck).hostname.toLowerCase();
    if (WHITELIST.some(site => domain.endsWith(site))) return;
    if (BLACKLIST.some(site => domain.includes(site))) {
        console.warn("🚨 BLACKLIST MATCH:", domain);
        redirectToWarning(tabId, urlToCheck);
        return; 
    }
    if (changeInfo.status === 'complete') {
        const activeSession = await initModel(); 
        if (activeSession) {
            runAIInference(tabId, urlToCheck);
        }
    }
});

async function runAIInference(tabId, url) {
    try {
        const features = new Float32Array(12).fill(0.5); 
        const inputTensor = new ort.Tensor('float32', features, [1, 12]);
        
        const results = await session.run({ float_input: inputTensor });
        if (Number(results.label.data[0]) === 1) {
            console.warn("🚩 AI flagged site as phishing:", url);
            redirectToWarning(tabId, url);
        }
    } catch (err) {
        console.error("Inference failed:", err);
    }
}
function redirectToWarning(tabId, url) {
    const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(url);
    chrome.tabs.update(tabId, { url: warningUrl });
}
initModel();
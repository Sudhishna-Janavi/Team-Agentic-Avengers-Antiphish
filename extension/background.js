import * as ort from 'onnxruntime-web';

// --- Global State & Constants ---
let session = null;
const BLACKLIST = ['rnicrosoft.com', 'paypaI.com', 'amaz0n.com', 'gooogle.com', 'ntu-portal.net'];
const WHITELIST = ['ntu.edu.sg', 'google.com', 'github.com', 'microsoft.com'];

// --- Helper: Persistence Layer ---
// Service Workers are ephemeral; we must use storage to keep state across "sleeps"
async function getAppState() {
    const data = await chrome.storage.local.get(['isEnabled', 'proceedURLs']);
    return {
        isEnabled: data.isEnabled !== false, // Defaults to true
        proceedURLs: new Set(data.proceedURLs || [])
    };
}

// --- 1. Initialize AI Model ---
async function initModel() {
    if (session) return session;

    try {
        // Point to the 'lib' folder created by your viteStaticCopy plugin
        ort.env.wasm.wasmPaths = chrome.runtime.getURL('lib/');
        ort.env.wasm.proxy = false;

        const modelUrl = chrome.runtime.getURL('model/antiphish_model.onnx');
        session = await ort.InferenceSession.create(modelUrl, { 
            executionProviders: ['wasm'] 
        });
        
        console.log("✅ AI Engine Loaded via Bundler.");
        return session;
    } catch (e) {
        console.error("❌ AI Loading Error:", e);
        return null;
    }
}

// --- 2. Message Listener (Communication with Popup/Warning page) ---
chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    const state = await getAppState();

    if (request.action === "proceedToURL") {
        console.log("🔓 Whitelisting URL:", request.url);
        state.proceedURLs.add(request.url);
        // Save back to storage
        await chrome.storage.local.set({ proceedURLs: Array.from(state.proceedURLs) });
        sendResponse({ status: "whitelisted" });
    }

    if (request.action === "updateState") {
        await chrome.storage.local.set({ isEnabled: request.state });
        sendResponse({ status: "updated" });
    }
    return true; 
});

// --- 3. Tab Monitor ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    const { isEnabled, proceedURLs } = await getAppState();
    const urlToCheck = changeInfo.url || tab.url;
    
    // Safety Guards
    if (!urlToCheck || urlToCheck.startsWith('chrome://')) return;
    if (!isEnabled || proceedURLs.has(urlToCheck) || urlToCheck.includes("warning.html")) return;

    const domain = new URL(urlToCheck).hostname.toLowerCase();

    // A. Whitelist Check
    if (WHITELIST.some(site => domain.endsWith(site))) return;

    // B. Blacklist Check (Instant Redirect)
    if (BLACKLIST.some(site => domain.includes(site))) {
        console.warn("🚨 BLACKLIST MATCH:", domain);
        redirectToWarning(tabId, urlToCheck);
        return; 
    }

    // C. AI Inference (Runs when page load is complete)
    if (changeInfo.status === 'complete') {
        const activeSession = await initModel(); 
        if (activeSession) {
            runAIInference(tabId, urlToCheck);
        }
    }
});

// --- 4. Run AI Inference ---
async function runAIInference(tabId, url) {
    try {
        // Replace with actual feature extraction logic later
        const features = new Float32Array(12).fill(0.5); 
        const inputTensor = new ort.Tensor('float32', features, [1, 12]);
        
        const results = await session.run({ float_input: inputTensor });
        
        // If label is 1, it's a phishing site
        if (Number(results.label.data[0]) === 1) {
            console.warn("🚩 AI flagged site as phishing:", url);
            redirectToWarning(tabId, url);
        }
    } catch (err) {
        console.error("Inference failed:", err);
    }
}

// Helper to handle redirection
function redirectToWarning(tabId, url) {
    const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(url);
    chrome.tabs.update(tabId, { url: warningUrl });
}

// Start-up initialization
initModel();
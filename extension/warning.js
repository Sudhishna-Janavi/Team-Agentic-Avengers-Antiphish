document.addEventListener('DOMContentLoaded', () => {
    const proceedBtn = document.getElementById('proceed');
    const safeBtn = document.getElementById('back-safe');

    // Handle "Proceed Anyway" with Handshake
    proceedBtn.addEventListener('click', () => {
        const urlParams = new URLSearchParams(window.location.search);
        const targetUrl = urlParams.get('url');

        if (targetUrl) {
            console.log("Requesting bypass for:", targetUrl);

            chrome.runtime.sendMessage({ 
                action: "proceedToURL", 
                url: targetUrl 
            }, (response) => {
                // Ensure background script acknowledged before redirecting
                if (chrome.runtime.lastError) {
                    console.error("Communication error:", chrome.runtime.lastError.message);
                    return;
                }
                
                if (response && response.status === "whitelisted") {
                    window.location.href = targetUrl;
                }
            });
        }
    });

    // Handle "Back to Safety"
    safeBtn.addEventListener('click', () => {
        window.location.href = "https://www.google.com";
    });
});
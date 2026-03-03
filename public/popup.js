document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('toggle-btn');
    const statusText = document.getElementById('status-text');

    // Load current state
    chrome.storage.sync.get('isEnabled', (data) => {
        updateUI(data.isEnabled);
    });

    btn.addEventListener('click', () => {
        chrome.storage.sync.get('isEnabled', (data) => {
            const newState = !data.isEnabled;
            chrome.storage.sync.set({ isEnabled: newState }, () => {
                updateUI(newState);
                // Tell background script the state changed
                chrome.runtime.sendMessage({ action: "updateState", state: newState });
            });
        });
    });

    function updateUI(enabled) {
        btn.textContent = enabled ? "Protection Enabled" : "Protection Disabled";
        btn.style.background = enabled ? "#3498db" : "#95a5a6";
        statusText.textContent = enabled ? "Sentry is Active" : "Sentry is Idle";
    }
});
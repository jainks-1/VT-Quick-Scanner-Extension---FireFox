const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

// Create the right-click menu option when the extension is installed
browserAPI.runtime.onInstalled.addListener(() => {
  browserAPI.contextMenus.create({
    id: "checkVTIntelligence",
    title: "Search VirusTotal for '%s'",
    contexts: ["link", "selection"]
  });
});

// Listen for the user clicking our right-click menu option
browserAPI.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "checkVTIntelligence") {
    // Prioritize text selection if available (hash/IP), fallback to link target URL
    const queryTarget = info.selectionText ? info.selectionText.trim() : info.linkUrl;

    if (!queryTarget) return;

    // Save the target to local storage temporarily
    browserAPI.storage.local.set({ pendingScanUrl: queryTarget }, () => {
      // Open the popup programmatically if supported, fallback cleanly if not
      if (browserAPI.action && typeof browserAPI.action.openPopup === 'function') {
        browserAPI.action.openPopup().catch((err) => {
          console.log("Auto-popup window not supported in this browser environment:", err);
        });
      }
    });
  }
});
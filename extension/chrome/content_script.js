chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "GET_SELECTION") {
    const text = window.getSelection ? String(window.getSelection().toString() || "") : "";
    sendResponse({ text });
    return true;
  }
});

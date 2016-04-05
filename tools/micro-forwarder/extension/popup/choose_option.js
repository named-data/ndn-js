function showConfig() {
  chrome.tabs.create(
    {
      url: chrome.extension.getURL("config.html")
    }
  );
}

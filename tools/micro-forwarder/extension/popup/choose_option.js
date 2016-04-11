function showConfig() {
    chrome.tabs.create({
	url: chrome.extension.getURL("config.html")
    });
}

document.addEventListener("DOMContentLoaded", function() {
    var btn = document.getElementById("showConfig");
    btn.addEventListener("click", function() {
	showConfig();
    });
});

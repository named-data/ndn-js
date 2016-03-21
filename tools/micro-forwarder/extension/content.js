var port = chrome.runtime.connect();
// Add a listener to wait for msg from background script
port.onMessage.addListener(function(msg) {
	window.postMessage({
		type: "FromMicroForwarderStub",
		buffer: msg
	}, "*");
});

// Add listener to wait for msg from app scripts
window.addEventListener("message", function(event) {
	// We only accept messages from ourselves
	if (event.source != window)
	  return;
	
	if (event.data.type && (event.data.type == "FromMicroForwarderTransport")) {
	  port.postMessage(event.data.buffer);
	}
}, false);

console.log("NDN Micro Forwarder stub is loaded.");

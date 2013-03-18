/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This is called from the NDN toolbar and the doorhanger popup on Firefox for Android.
 */

Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/NdnProtocolInfo.jsm");

function ndnToolbarGetVersion(selector) {
  NdnProtocolInfo.getVersion(selector, window, alert);
}

/*
 * This is called when the connected NDN hub changes.
 */
function onNdnHubChanged(host, port) {
  document.getElementById("ndnHubLabel").setAttribute("value", "Hub: " + host + ":" + port);
}

if (window) 
  window.addEventListener("load", function() { NdnProtocolInfo.addNdnHubChangedListener(onNdnHubChanged); }, 
                          false);

function ndnToolbarSetHub() {
  var message = NdnProtocolInfo.setHub(window);
  if (message != null)
    document.getElementById("ndnHubLabel").setAttribute("value", message);
}

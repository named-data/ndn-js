Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/NdnProtocolInfo.jsm");

function ndnToolbarGetVersion(selector) {
 try {
  if (window._content.document.location.protocol != "ndn:") {
    alert("The address must start with ndn:");
    return;
  }

  // Parse the same as in ndnProtocolService newChannel.
  var uriParts = NdnProtocolInfo.splitUri(window._content.document.location.href);
  var name = new Name(uriParts.name);
  var indexOfVersion = getIndexOfVersion(name);
  if (indexOfVersion < 0) {
    alert("The ndn address does not have a version");
    return;
  }
  
  var escapedVersion = Name.toEscapedString(name.components[indexOfVersion]);

  var childSelector;
  if (selector == "earliest")
      childSelector = "ndn.ChildSelector=0";
  else if (selector == "latest")
      childSelector = "ndn.ChildSelector=1";
  else if (selector == "previous")
      childSelector = "ndn.ChildSelector=1&ndn.Exclude=" + escapedVersion + ",*";
  else if (selector == "next")
      childSelector = "ndn.ChildSelector=0&ndn.Exclude=*," + escapedVersion;
  else
      // Don't expect this to happen.
      return;

  var nameWithoutVersion = new Name(name.components.slice(0, indexOfVersion));
  var searchWithChildSelector = (uriParts.search == "" ? "?" : uriParts.search + "&") + childSelector;
    
  var uri = "ndn:" + nameWithoutVersion.to_uri() + searchWithChildSelector + uriParts.hash;
  window._content.document.location = uri;
 } catch (ex) {
       dump("ndnToolbarGetVersion exception: " + ex + "\n" + ex.stack);
 }
} 

/*
 * Return the index of the last component that starts with 0xfd, or -1 if not found.
 */
function getIndexOfVersion(name) {
  for (var i = name.components.length - 1; i >= 0; --i) {
    if (name.components[i].length >= 1 && name.components[i][0] == 0xfd)
      return i;
  }

  return -1;
}

/*
 * This is called when the connected NDN hub changes.
 */
function onNdnHubChanged(host, port) {
   document.getElementById("ndnHubLabel").setAttribute("value", "Hub: " + host + ":" + port);
}

window.addEventListener("load", function() { NdnProtocolInfo.addNdnHubChangedListener(onNdnHubChanged); }, false);

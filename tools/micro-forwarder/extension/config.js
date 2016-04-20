var addRoutePrefixUri;
var addRouteUri;

// Note: The transport and handler belong to the window since there is only
// one communication channel from the window to the Micro Forwarder.
var transport;
function onReceivedObject(obj) {
    if (obj.type == "fib/list") {
        var text = "FIB:<br/>\n";
        for (var i = 0; i < obj.fib.length; ++i) {
            text += "&nbsp;&nbsp;" + obj.fib[i].name + " nexthops=";
            for (var j = 0; j < obj.fib[i].nextHops.length; ++j)
              text += "{faceId=" + obj.fib[i].nextHops[j].faceId + "} ";
            text += "<br/>\n";
        }

        document.getElementById('showStatusResult').innerHTML += text;
        // Now show the faces.
        transport.sendObject({ type: "faces/list" });
    }
    else if (obj.type == "faces/list") {
        var text = "Faces:<br/>\n";
        for (var i = 0; i < obj.faces.length; ++i)
            text += "&nbsp;&nbsp;faceId=" + obj.faces[i].faceId +
            " " + obj.faces[i].uri + "<br/>\n";

        document.getElementById('showStatusResult').innerHTML += text;
    }
    else if (obj.type == "faces/query") {
        if (obj.faceId != null) {
            // We have the obj.faceId. Create the route.
            transport.sendObject({
              type: "rib/register",
              nameUri: addRoutePrefixUri,
              faceId: obj.faceId
            });
        }
        else {
            // The face doesn't exist yet. Create it.
            transport.sendObject({
              type: "faces/create",
              uri: addRouteUri
            });
        }
    }
    else if (obj.type == "faces/create") {
        var lowestErrorCode = 400;
        if (obj.statusCode >= lowestErrorCode) {
            console.log("faces/create error code " + obj.statusCode);
            document.getElementById('showStatusResult').innerHTML =
              "Error in faces/create. Error code " + obj.statusCode + ".<br/>\n";
        }
        else {
            // We have the obj.faceId. Create the route.
            transport.sendObject({
              type: "rib/register",
              nameUri: addRoutePrefixUri,
              faceId: obj.faceId
            });
        }
    }
    else if (obj.type == "rib/register") {
        var lowestErrorCode = 400;
        if (obj.statusCode >= lowestErrorCode) {
            console.log("rib/register error code " + obj.statusCode);
            document.getElementById('showStatusResult').innerHTML =
              "Error in rib/register. Error code " + obj.statusCode + ".<br/>\n";
        }
        else {
            console.log("Registered " + addRoutePrefixUri + " to " + addRouteUri);
            // Show the new route.
            showStatus();
        }
    }
}

transport = new MicroForwarderTransport(onReceivedObject);

function addRoute() {
    addRoutePrefixUri = document.getElementById("prefix").value;
    var host = document.getElementById("uri").value;
    addRouteUri = "ws://" + host + ":9696";

    transport.sendObject({
      type: "faces/query",
      uri: addRouteUri
    });      
}

function showStatus() {
    // Clear the results text. onReceivedObject will fill it.
    document.getElementById('showStatusResult').innerHTML = "";
    transport.sendObject({ type: "fib/list" });
}

document.addEventListener("DOMContentLoaded", function() {
    var ssBtn = document.getElementById("showStatus");
    ssBtn.addEventListener("click", function() {
      showStatus();
    });
    var arBtn = document.getElementById("addRoute");
    arBtn.addEventListener("click", function() {
      addRoute();
    });
});

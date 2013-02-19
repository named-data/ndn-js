// Including js files to be used in the web pages
// Add your js source code reference here, rather than in the HTML files

// Find path to Helper.js
var scripts = document.getElementsByTagName('SCRIPT');
var path = '';

if(scripts && scripts.length>0) {
    for(var i in scripts) {
        if(scripts[i].src && scripts[i].src.match(/Helper\.js$/)) {
            path = scripts[i].src.replace(/(.*)Helper\.js$/, '$1');
        }
    }
}
console.log(path);

document.write('<script type="text/javascript" src="' + path + 'WebSocketTransport.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'util/CCNProtocolDTags.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'util/CCNTime.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'util/ExponentialReExpressClosure.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'Name.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'ContentObject.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/DateFormat.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'Interest.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'Key.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'PublisherID.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'PublisherPublicKeyDigest.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'FaceInstance.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'ForwardingEntry.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'Closure.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/DynamicUint8Array.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/BinaryXMLEncoder.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/BinaryXMLDecoder.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/BinaryXMLStructureDecoder.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/DataUtils.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'encoding/EncodingUtils.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'security/KeyManager.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'NDN.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/jsbn.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/jsbn2.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/rsa.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/rsa2.js"></script>');
//document.write('<script type="text/javascript" src="' + path + 'securityLib/sha1.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/sha256.js"></script>');
//document.write('<script type="text/javascript" src="' + path + 'securityLib/sha512.js"></script>');
//document.write('<script type="text/javascript" src="' + path + 'securityLib/md5.js"></script>');
//document.write('<script type="text/javascript" src="' + path + 'securityLib/ripemd160.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/base64.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/rsapem-1.1.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/rsasign-1.2.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/asn1hex-1.1.js"></script>');
document.write('<script type="text/javascript" src="' + path + 'securityLib/x509-1.1.js"></script>');

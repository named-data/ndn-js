// define a shim require function so that a node/browserify require calls dont cause errors when ndn-js is used via <script> tag

var ndn = ndn || {}
var exports = ndn;

var module = {}
function require(){return ndn;}

//wrap a require call to crypto to that we can redirect calls to this file to browserify.js when being built for the browser

module.exports = require('crypto')

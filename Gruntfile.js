module.exports = function(grunt) {


var opts = {
    pkg: grunt.file.readJSON('package.json'),
mochaSelenium: {
    options: {
      // Mocha options
      reporter: 'spec',
      timeout: 30e3,
      // Toggles wd's promises API, default:false
      usePromises: false
    },
    phantomjs: {
      src: ['tests/*.js'],
      options: {
        // phantomjs must be in the $PATH when invoked
        browserName: 'phantomjs'
      }
    }
  },
comments: {
    your_target: {
      // Target-specific file lists and/or options go here.
      options: {
          singleline: true,
          multiline: true
      },
      src: [ 'build/ndn.js'] // files to remove comments from
    },
  },
    concat: {
      options: {
        separator: ';',
        stripBanners: true
      },
      dist: {
        src: ["js/browserify.js",
              "contrib/securityLib/core.js",
              "contrib/securityLib/sha256.js",
              "contrib/securityLib/base64.js",
              "contrib/securityLib/rsa.js",
              "contrib/securityLib/rsa2.js",
              "contrib/securityLib/crypto-1.0.js",
              "contrib/securityLib/rsapem-1.1.js",
              "contrib/securityLib/rsasign-1.2.js",
              "contrib/securityLib/asn1hex-1.1.js",
              "contrib/securityLib/x509-1.1.js",
              "contrib/securityLib/jsbn.js",
              "contrib/securityLib/jsbn2.js",
              "js/log.js",
              "js/util/ndn-protoco-id-tags.js",
              "js/util/ndn-time.js",
              "js/util/exponential-re-express-closure.js",
              "js/util/blob.js",
              "js/util/signed-blob.js",
              "js/util/dynamic-buffer.js",
              "js/encoding/data-utils.js",
              "js/encoding/date-format.js",
              "js/encoding/decoding-exception.js",
              "js/encoding/binary-xml-encoder.js",
              "js/encoding/binary-xml-decoder.js",
              "js/encoding/binary-xml-structure-decoder.js",
              "js/encoding/tlv/tlv.js",
              "js/encoding/tlv/tlv-encoder.js",
              "js/encoding/tlv/tlv-decoder.js",
              "js/encoding/tlv/tlv-structure-decoder.js",
              "js/encoding/wire-format.js",
              "js/encoding/element-reader.js",
              "js/util/name-enumeration.js",
              "js/transport/web-socket-transport.js",
              "js/browserify-tcp-transport.js",
              "js/closure.js",
              "js/publisher-public-key-digest.js",
              "js/publisher-id.js",
              "js/name.js",
              "js/key.js",
              "js/key-locator.js",
              "js/security/key-manager.js",
              "js/meta-info.js",
              "js/signature.js",
              "js/data.js",
              "js/exclude.js",
              "js/interest.js",
              "js/face-instance.js",
              "js/forwarding-entry.js",
              "js/forwarding-flags.js",
              "js/encoding/binary-xml-wire-format.js",
              "js/encoding/tlv-0_1a2-wire-format.js",
              "js/encoding/tlv-wire-format.js",
              "js/encoding/encoding-utils.js",
              "js/face.js",
              "js/endbrowserify.js"],
        dest: 'build/ndn.js'
      }
    },
    "regex-replace": {
       ndn: { //specify a target with any name
          src: ['js/*.js','js/**/*.js','js/**/**/*.js'],
          actions: [
            {
                name: 'Buffer',
                search: ' Buffer',
                replace: ' customBuf',
                flags: 'gm'
            }
        ]
    }
},
    watch: {
      files: ['js/*.js', 'js/**/*.js', 'js/**/**/*.js'],
      tasks: ['concat', 'regex-replace' ]
    }
  };
  grunt.initConfig(opts)

  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-regex-replace');
  grunt.loadNpmTasks('grunt-mocha-selenium');
  grunt.loadNpmTasks('grunt-stripcomments')
  grunt.registerTask('w', ['watch']);
  grunt.registerTask('build', ['concat','comments', 'regex-replace', 'mochaSelenium']);

};

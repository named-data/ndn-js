# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.8.1'
APPNAME='ndnjs'

YUICOMPRESSOR_URL="http://github.com/downloads/yui/yuicompressor/"
YUICOMPRESSOR_NAME="yuicompressor-2.4.7"

CLOSURE_COMPILER="http://dl.google.com/closure-compiler/compiler-20140407.zip"

from waflib import Task, TaskGen, Utils, Logs
import urllib, subprocess, os, shutil

def options (opt):
    js = opt.add_option_group ("ndn.js compilation options")

    js.add_option('--no-js',action='store_false',default=True,dest='js',
                  help='''Disable ndn.js compilation and installation''')
    js.add_option('--js-dir',action='store',dest='jsdir',
                  help='''Directory where .js files will be installed (Default: ${PREFIX}/share/ndn-js)''')
    js.add_option('--yui',action='store_true',default=False,dest='yui',
                  help='''Download and use yuicompressor-2.4.7 (http://yui.github.com/yuicompressor/)''')
    js.add_option('--no-compiler',action='store_false',default=True,dest='compiler',
                  help='''Disable download and use of closure-compiler-r2388 (https://code.google.com/p/closure-compiler/)''')

    ws = opt.add_option_group ("ws-proxy options")
    ws.add_option ('--no-ws',action='store_false',default=True,dest='ws',
                   help='''Disable ws-proxy installation''')

def configure (conf):
    if conf.options.js:
        conf.env.JS = 1
        if not conf.env.JSDIR:
            if conf.options.jsdir or Utils.is_win32:
                conf.env.JSDIR=os.path.abspath (os.path.expanduser (conf.options.jsdir))
            else:
                conf.env.JSDIR=Utils.subst_vars ('${PREFIX}/bin',conf.env)

        if conf.options.yui:
            conf.start_msg ("Checking for yuicompressor")
            if os.path.exists('tools/yuicompressor.jar'):
                conf.end_msg('tools/yuicompressor.jar')
                conf.env.HAVE_YUI = 1
            else:
                conf.end_msg('not found','YELLOW')
                url="%s%s.zip" % (YUICOMPRESSOR_URL, YUICOMPRESSOR_NAME)
                Logs.info ("Downloading yuicompressor from %s..." % url)
                urllib.urlretrieve (url, "build/yuicompressor.zip")

                filename='%s/build/%s.jar' % (YUICOMPRESSOR_NAME,YUICOMPRESSOR_NAME)
                subprocess.check_call (['unzip', '-qq', '-o', '-j', 'build/yuicompressor.zip',
                                        filename, '-d', 'tools/'])
                os.rename ("tools/%s.jar" % YUICOMPRESSOR_NAME, "tools/yuicompressor.jar")
                conf.env.HAVE_YUI = 1

        if conf.options.compiler:
            conf.start_msg ("Checking for closure-compiler")
            if os.path.exists('tools/compiler.jar'):
                conf.end_msg('tools/compiler.jar')
                conf.env.HAVE_COMPILER = 1
            else:
                conf.end_msg('not found','YELLOW')
                Logs.info ("Downloading closure-compiler from %s..." % CLOSURE_COMPILER)
                urllib.urlretrieve (CLOSURE_COMPILER, "build/closure-compiler.zip")

                subprocess.check_call (['unzip', '-qq', '-o', '-j', 'build/closure-compiler.zip', 'compiler.jar', '-d', 'tools/'])
                conf.env.HAVE_COMPILER = 1

    if conf.options.ws:
        conf.env.WS = 1

def build (bld):
    if bld.env['JS']:
        securityLib = ["contrib/securityLib/core.js",
                       "contrib/securityLib/sha256.js",
                       "contrib/securityLib/hmac.js",
                       "contrib/securityLib/base64.js",
                       "contrib/securityLib/prng4.js",
                       "contrib/securityLib/rng.js",
                       "contrib/securityLib/rsa.js",
                       "contrib/securityLib/rsa2.js",
                       "contrib/securityLib/crypto-1.1.js",
                       "contrib/securityLib/rsapem-1.1.js",
                       "contrib/securityLib/rsasign-1.2.js",
                       "contrib/securityLib/ecdsa-modified-1.0.js",
                       "contrib/securityLib/asn1hex-1.1.js",
                       "contrib/securityLib/x509-1.1.js",
                       "contrib/securityLib/jsbn.js",
                       "contrib/securityLib/jsbn2.js"]

                 # Include stacktrace.js before browserify so that it's defined globally.
        ndnjs = ["contrib/stacktrace/stacktrace.js",
                 "js/browserify-header.js",
                 "js/browserify-require.js",
                 "js/browserify-stacktrace.js",
                 "js/use-subtle-crypto.js"] + securityLib + [
                 "js/browserify.js",
                 "contrib/feross/base64-js.js",
                 "contrib/feross/ieee754.js",
                 "contrib/feross/buffer.js",
                 "js/log.js",
                 "js/util/ndn-common.js",
                 "js/util/exponential-re-express.js",
                 "js/util/blob.js",
                 "js/util/signed-blob.js",
                 "js/util/dynamic-buffer.js",
                 "js/util/change-counter.js",
                 "js/util/sync-promise.js",
                 "js/encoding/data-utils.js",
                 "js/encoding/decoding-exception.js",
                 "js/encoding/tlv/tlv.js",
                 "js/encoding/tlv/tlv-encoder.js",
                 "js/encoding/tlv/tlv-decoder.js",
                 "js/encoding/tlv/tlv-structure-decoder.js",
                 "js/encoding/protobuf-tlv.js",
                 "js/encoding/oid.js",
                 "js/encoding/wire-format.js",
                 "js/encoding/element-reader.js",
                 "js/encoding/der/der-decoding-exception.js",
                 "js/encoding/der/der-encoding-exception.js",
                 "js/encoding/der/der-node-type.js",
                 "js/encoding/der/der-node.js",
                 "js/util/boost-info-parser.js",
                 "js/util/memory-content-cache.js",
                 "js/util/segment-fetcher.js",
                 "js/util/pipeline.js",
                 "js/util/pipeline-fixed.js",
                 "js/util/pipeline-cubic.js",
                 "js/util/rtt-estimator.js",
                 "js/util/data-fetcher.js",
                 "js/util/regex/ndn-regex-backref-manager.js",
                 "js/util/regex/ndn-regex-matcher-base.js",
                 "js/util/regex/ndn-regex-backref-matcher.js",
                 "js/util/regex/ndn-regex-component-matcher.js",
                 "js/util/regex/ndn-regex-component-set-matcher.js",
                 "js/util/regex/ndn-regex-pattern-list-matcher.js",
                 "js/util/regex/ndn-regex-pseudo-matcher.js",
                 "js/util/regex/ndn-regex-repeat-matcher.js",
                 "js/util/regex/ndn-regex-top-matcher.js",
                 "js/transport/transport.js",
                 "js/transport/micro-forwarder-transport.js",
                 "js/transport/runtime-port-transport.js",
                 "js/transport/web-socket-transport.js",
                 "js/browserify-tcp-transport.js",
                 "js/name.js",
                 "js/key-locator.js",
                 "js/meta-info.js",
                 "js/sha256-with-ecdsa-signature.js",
                 "js/sha256-with-rsa-signature.js",
                 "js/generic-signature.js",
                 "js/hmac-with-sha256-signature.js",
                 "js/digest-sha256-signature.js",
                 "js/data.js",
                 "js/security/security-exception.js",
                 "js/security/security-types.js",
                 "js/security/command-interest-preparer.js",
                 "js/security/command-interest-signer.js",
                 "js/security/key-id-type.js",
                 "js/security/key-params.js",
                 "js/security/safe-bag.js",
                 "js/security/signing-info.js",
                 "js/security/validity-period.js",
                 "js/security/verification-helpers.js",
                 "js/security/certificate/public-key.js",
                 "js/security/certificate/certificate-extension.js",
                 "js/security/certificate/certificate-subject-description.js",
                 "js/security/certificate/certificate.js",
                 "js/security/certificate/identity-certificate.js",
                 "js/security/identity/identity-storage.js",
                 "js/security/identity/indexeddb-identity-storage.js",
                 "js/security/identity/memory-identity-storage.js",
                 "js/security/identity/private-key-storage.js",
                 "js/security/identity/memory-private-key-storage.js",
                 "js/security/identity/indexeddb-private-key-storage.js",
                 "js/security/identity/identity-manager.js",
                 "js/security/pib/pib-certificate-container.js",
                 "js/security/pib/pib-identity-container.js",
                 "js/security/pib/pib-identity.js",
                 "js/security/pib/pib-impl.js",
                 "js/security/pib/pib-indexeddb.js",
                 "js/security/pib/pib-key-container.js",
                 "js/security/pib/pib-key.js",
                 "js/security/pib/pib-memory.js",
                 "js/security/pib/pib.js",
                 "js/security/pib/detail/pib-identity-impl.js",
                 "js/security/pib/detail/pib-key-impl.js",
                 "js/security/policy/validation-request.js",
                 "js/security/policy/policy-manager.js",
                 "js/security/policy/certificate-cache.js",
                 "js/security/policy/config-policy-manager.js",
                 "js/security/policy/no-verify-policy-manager.js",
                 "js/security/policy/self-verify-policy-manager.js",
                 "js/security/tpm/tpm-back-end.js",
                 "js/security/tpm/tpm-back-end-memory.js",
                 "js/security/tpm/tpm-key-handle.js",
                 "js/security/tpm/tpm-key-handle-memory.js",
                 "js/security/tpm/tpm-private-key.js",
                 "js/security/tpm/tpm.js",
                 "js/security/v2/validator-config/config-checker.js",
                 "js/security/v2/validator-config/config-filter.js",
                 "js/security/v2/validator-config/config-name-relation.js",
                 "js/security/v2/validator-config/config-rule.js",
                 "js/security/v2/trust-anchor-group.js",
                 "js/security/v2/validation-state.js",
                 "js/security/v2/certificate-cache-v2.js",
                 "js/security/v2/certificate-container-interface.js",
                 "js/security/v2/certificate-fetcher.js",
                 "js/security/v2/certificate-fetcher-from-network.js",
                 "js/security/v2/certificate-fetcher-offline.js",
                 "js/security/v2/certificate-request.js",
                 "js/security/v2/certificate-storage.js",
                 "js/security/v2/certificate-v2.js",
                 "js/security/v2/data-validation-state.js",
                 "js/security/v2/dynamic-trust-anchor-group.js",
                 "js/security/v2/interest-validation-state.js",
                 "js/security/v2/static-trust-anchor-group.js",
                 "js/security/v2/trust-anchor-container.js",
                 "js/security/v2/validation-error.js",
                 "js/security/v2/validation-policy.js",
                 "js/security/v2/validation-policy-accept-all.js",
                 "js/security/v2/validation-policy-command-interest.js",
                 "js/security/v2/validation-policy-config.js",
                 "js/security/v2/validation-policy-from-pib.js",
                 "js/security/v2/validation-policy-simple-hierarchy.js",
                 "js/security/v2/validator.js",
                 "js/security/key-chain.js",
                 "js/security/validator-config-error.js",
                 "js/security/validator-config.js",
                 "js/security/validator-null.js",
                 "js/exclude.js",
                 "js/interest.js",
                 "js/registration-options.js",
                 "js/forwarding-flags.js",
                 "js/control-parameters.js",
                 "js/control-response.js",
                 "js/interest-filter.js",
                 "js/delegation-set.js",
                 "js/link.js",
                 "js/network-nack.js",
                 "js/encoding/tlv-0_2-wire-format.js",
                 "js/encoding/tlv-0_1_1-wire-format.js",
                 "js/encoding/tlv-0_1-wire-format.js",
                 "js/encoding/tlv-wire-format.js",
                 "js/encoding/encoding-utils.js",
                 "js/in-memory-storage/in-memory-storage-retaining.js",
                 "js/encrypt/algo/aes-algorithm.js",
                 "js/encrypt/algo/encrypt-params.js",
                 "js/encrypt/algo/encryptor.js",
                 "js/encrypt/algo/rsa-algorithm.js",
                 "js/encrypt/consumer-db.js",
                 "js/encrypt/consumer.js",
                 "js/encrypt/decrypt-key.js",
                 "js/encrypt/decryptor-v2.js",
                 "js/encrypt/encrypt-error.js",
                 "js/encrypt/encrypt-key.js",
                 "js/encrypt/encrypted-content.js",
                 "js/encrypt/encryptor-v2.js",
                 "js/encrypt/group-manager-db.js",
                 "js/encrypt/group-manager.js",
                 "js/encrypt/interval.js",
                 "js/encrypt/producer-db.js",
                 "js/encrypt/producer.js",
                 "js/encrypt/repetitive-interval.js",
                 "js/encrypt/schedule.js",
                 "js/encrypt/indexeddb-consumer-db.js",
                 "js/encrypt/indexeddb-group-manager-db.js",
                 "js/encrypt/indexeddb-producer-db.js",
                 "js/sync/chrono-sync2013.js",
                 "js/sync/digest-tree.js",
                 "js/sync/sync-state.js",
                 "js/util/command-interest-generator.js",
                 "js/impl/interest-filter-table.js",
                 "js/impl/pending-interest-table.js",
                 "js/impl/registered-prefix-table.js",
                 "js/lp/congestion-mark.js",
                 "js/lp/incoming-face-id.js",
                 "js/lp/lp-packet.js",
                 "js/face.js",
                 "js/firefly-face.js",
                 "js/browserify-footer.js",
                 "contrib/dexie/Dexie.js"]

        ndnjs = bld (features="combine",
                     target="ndn",
                     source=ndnjs,
                     install_path="${JSDIR}")

        if bld.env['HAVE_YUI']:
            ndnjs.yui = True

        if bld.env['HAVE_COMPILER']:
            ndnjs.compiler = True

    if bld.env['WS']:
        bld.install_as ('${BINDIR}/ndnx-wsproxy-tcp.js', 'wsproxy/wsproxy-tcp.js', chmod=Utils.O755)
        bld.install_as ('${BINDIR}/ndnx-wsproxy-udp.js', 'wsproxy/wsproxy-udp.js', chmod=Utils.O755)

@TaskGen.extension('.js')
def js_hook(self, node):
    node.sig=Utils.h_file (node.abspath())

@TaskGen.feature('combine')
@TaskGen.after_method('process_source')
def apply_combine(self):
    out = "%s.js" % self.target
    tasks = []
    task = self.create_task ('combine', self.source)
    task.set_outputs (task.generator.path.find_or_declare (out))
    tasks.append (task)

    if getattr(self, 'yui', False):
        out_yui = "%s.min.yui.js" % self.target
        yui = self.create_task ('yuicompressor')
        yui.combine = task
        yui.set_outputs (yui.generator.path.find_or_declare (out_yui))
        tasks.append (yui)

    if getattr(self, 'compiler', False):
        out_min = "%s.min.js" % self.target
        compiler = self.create_task ('closure_compiler')
        compiler.combine = task
        compiler.set_outputs (compiler.generator.path.find_or_declare (out_min))
        tasks.append (compiler)

    try:
        for task in tasks:
            self.bld.install_files (self.install_path, task.outputs[:], env=self.env)
    except:
        pass

class combine (Task.Task):
    def run(self):
        outFile = self.outputs[0]
        self.outputs[0].write ("", "w") # make file empty
        for inFile in self.inputs:
            self.outputs[0].write (inFile.read (), 'a')

class yuicompressor (Task.Task):
    after="combine"
    color='PINK'
    def __str__(self):
        src_str=self.combine.outputs[0].nice_path()
        tgt_str=self.outputs[0].nice_path()
        return'%s: %s -> %s\n'%(self.__class__.__name__.replace('_task',''),src_str,tgt_str)

    def run(self):
        return self.exec_command(['java',
                                  '-jar', '../tools/yuicompressor.jar',
                                  '-o', self.outputs[0].abspath(),
                                  self.combine.outputs[0].abspath()])

class closure_compiler (Task.Task):
    after="combine"
    color='PINK'
    def __str__(self):
        src_str=self.combine.outputs[0].nice_path()
        tgt_str=self.outputs[0].nice_path()
        return'%s: %s -> %s\n'%(self.__class__.__name__.replace('_task',''),src_str,tgt_str)

    def run(self):
        return self.exec_command(['java',
                                  '-jar', '../tools/compiler.jar',
                                  '--language_in=ES5',
                                  '--js', self.combine.outputs[0].abspath(),
                                  '--js_output_file', self.outputs[0].abspath()])

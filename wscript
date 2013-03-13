# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.1'
APPNAME='ndnjs'

YUICOMPRESSOR_URL="http://github.com/downloads/yui/yuicompressor/"
YUICOMPRESSOR_NAME="yuicompressor-2.4.7"

CLOSURE_COMPILER="http://closure-compiler.googlecode.com/files/compiler-20121212.zip"

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
        securityLib = ["contrib/securityLib/sha256.js",
                       "contrib/securityLib/base64.js",
                       "contrib/securityLib/rsa.js",
                       "contrib/securityLib/rsa2.js",
                       "contrib/securityLib/rsapem-1.1.js",
                       "contrib/securityLib/rsasign-1.2.js",
                       "contrib/securityLib/asn1hex-1.1.js",
                       "contrib/securityLib/x509-1.1.js",
                       "contrib/securityLib/jsbn.js",
                       "contrib/securityLib/jsbn2.js"]

        ndnjs = ["js/Closure.js",
                 "js/WebSocketTransport.js",
                 "js/util/CCNProtocolDTags.js",
                 "js/util/CCNTime.js",
                 "js/util/ExponentialReExpressClosure.js",
                 "js/Name.js",
                 "js/ContentObject.js",
                 "js/encoding/DateFormat.js",
                 "js/Interest.js",
                 "js/Key.js",
                 "js/PublisherID.js",
                 "js/PublisherPublicKeyDigest.js",
                 "js/FaceInstance.js",
                 "js/ForwardingEntry.js",
                 "js/encoding/DynamicUint8Array.js",
                 "js/encoding/BinaryXMLEncoder.js",
                 "js/encoding/BinaryXMLDecoder.js",
                 "js/encoding/BinaryXMLStructureDecoder.js",
                 "js/encoding/DataUtils.js",
                 "js/encoding/EncodingUtils.js",
                 "js/security/KeyManager.js",
                 "js/security/Witness.js"] + securityLib + ["js/NDN.js"]

        ndnjs = bld (features="combine",
                     target="ndn-js",
                     source=ndnjs,
                     install_path="${JSDIR}")

        if bld.env['HAVE_YUI']:
            ndnjs.yui = True

        if bld.env['HAVE_COMPILER']:
            ndnjs.compiler = True

    if bld.env['WS']:
        bld.install_as ('${BINDIR}/ccnx-wsproxy-tcp.js', 'wsproxy/wsproxy-tcp.js', chmod=Utils.O755)
        bld.install_as ('${BINDIR}/ccnx-wsproxy-udp.js', 'wsproxy/wsproxy-udp.js', chmod=Utils.O755)

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
                                  '--js', self.combine.outputs[0].abspath(),
                                  '--js_output_file', self.outputs[0].abspath()])

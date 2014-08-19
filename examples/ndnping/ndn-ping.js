/*
  NDN Ping example, revised for ndn-tlv-ping

  Using ping responder on NDN testbed, which responds to Interests in
  /<topo-prefix>/ping/<random-number>

  Jeff Burke
  jburke@remap.ucla.edu

  See COPYING for copyright and distribution information.

*/

// One of NDN project default hubs

// TODO: Use NDN hub selection mechanism
// 
var hostip = "spurs.cs.ucla.edu";

var face = new Face({host:hostip});
    
var AsyncGetClosure = function AsyncGetClosure(T0) {
  this.T0 = T0;
  Closure.call(this);
};

AsyncGetClosure.prototype.upcall = function(kind, upcallInfo) {


  if (kind == Closure.UPCALL_FINAL) {
    // Do nothing.
  } else if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {

    nameStr = upcallInfo.interest.getName().toUri().split("/").slice(0,-2).join("/");
    document.getElementById('pingreport').innerHTML += '<tr><td width="50%">' + nameStr + ' </td><td align="right">timeout</td></tr>' ;
  } else if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED) {
    var T1 = new Date();
    var content = upcallInfo.data;
    nameStr = content.getName().toUri().split("/").slice(0,-2).join("/");
    strContent = DataUtils.toString(content.getContent().buf());
    
    // TODO: perhaps ndn-js should auto-handle the zero-terminated string? [jb]
    // 
    
    if (kind==Closure.UPCALL_CONTENT_UNVERIFIED) {
        nameStr += '<font color="gray" size="-1"> (unverified)</font>';
    }
         
    if (strContent=="NDN TLV Ping Response\0") {
      document.getElementById('pingreport').innerHTML += '<tr><td width="50%">' + nameStr + ' </td><td align="right">' + (T1-this.T0) + ' ms</td></tr>' ;
    } else {
      console.log("Unknown content received.");
    };
  }
  return Closure.RESULT_OK;
};

function ping(name) {
  pingname = name + "/ping/" + Math.floor(Math.random()*100000);
  face.expressInterest(new Name(pingname), new AsyncGetClosure(new Date()));
};

function dopings() {
    ping("/ndn/org/caida");
    ping("/ndn/cn/edu/bupt");	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/cn/edu/pku"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/cn/edu/tongji"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/arizona"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/colostate"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/memphis"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/neu"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/uci"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/ucla");	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/ucla/remap"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/uiuc"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/umich ");	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/edu/wustl");	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/fr/lip6"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
    ping("/ndn/fr/orange1"); 	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	 
};

window.onload = function() {
    document.getElementById("host").innerHTML=hostip;    
    dopings()
}
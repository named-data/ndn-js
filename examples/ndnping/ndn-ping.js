/* 
	NDN Ping example
	
	Using ping responder on NDN testbed, which responds to Interests in
	/<topo-prefix>/ping/<random-number>
	
	Jeff Burke
	jburke@remap.ucla.edu
	
	See COPYING for copyright and distribution information.

*/

		// One of NDN project default hubs
		hostip="A.ws.ndn.ucla.edu";

        var AsyncGetClosure = function AsyncGetClosure(T0) {
        	this.T0 = T0;
			Closure.call(this);
		};
		
		AsyncGetClosure.prototype.upcall = function(kind, upcallInfo) {
			if (kind == Closure.UPCALL_FINAL) {
				// Do nothing.
			} else if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
		
				nameStr = upcallInfo.interest.name.getName().split("/").slice(0,-2).join("/");
				document.getElementById('pingreport').innerHTML += '<tr><td width="65%">' + nameStr + ' </td><td align="right">timeout</td></tr>' ;
			} else if (kind == Closure.UPCALL_CONTENT) {
				var T1 = new Date();
				var content = upcallInfo.contentObject;
				nameStr = content.name.getName().split("/").slice(0,-2).join("/");
				strContent = DataUtils.toString(content.content);
				if (strContent=="ping ack") {
					document.getElementById('pingreport').innerHTML += '<tr><td width="65%">' + nameStr + ' </td><td align="right">' + (T1-this.T0) + ' ms</td></tr>' ;
				} else {
					console.log("Unknown content received.");
				};
			}
			return Closure.RESULT_OK;
		};
		
		function ping(name) {
			pingname = name + "/ping/" + Math.floor(Math.random()*100000);
			ndn.expressInterest(new Name(pingname), new AsyncGetClosure( new Date() ));
		};
	
	 	function dopings() {
     		ping("/ndn/arizona.edu");
     		ping("/ndn/caida.org");
     		ping("/ndn/colostate.edu/netsec")
     		ping("/ndn/memphis.edu/netlab")
     		ping("/ndn/neu.edu/northpole")
     		ping("/ndn/parc.com");
     		ping("/ndn/pku.edu");
     		ping("/ndn/uci.edu");
     		ping("/ndn/ucla.edu");
     		ping("/ndn/ucla.edu/apps");    		
     		ping("/ndn/uiuc.edu");
     		ping("/ndn/wustl.edu");
     		
		};
		
		openHandle = function() { dopings(); };
		var ndn = new NDN({host:hostip, onopen:openHandle});
		var T0 = 0;
        ndn.transport.connectWebSocket(ndn);
		

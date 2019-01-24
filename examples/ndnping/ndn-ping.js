/*
 * Copyright (C) 2013-2019 Regents of the University of California.
 * @author: Jeff Burke <jburke@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */
/*
  NDN Ping example, revised for ndn-tlv-ping

  Using ping responder on NDN testbed, which responds to Interests in
  /<topo-prefix>/ping/<random-number>

  Jeff Burke
  jburke@remap.ucla.edu
*/

// One of NDN project default hubs

// TODO: Use NDN hub selection mechanism
//
var hostip = "spurs.cs.ucla.edu";

var face = new Face({host:hostip});

function onTimeout(interest)
{
    var nameStr = interest.getName().toUri().split("/").slice(0,-2).join("/");
    document.getElementById('pingreport').innerHTML += '<tr><td width="50%">' + nameStr + ' </td><td align="right">timeout</td></tr>' ;
}

function onData(interest, content, T0)
{
    var T1 = new Date();
    var nameStr = content.getName().toUri().split("/").slice(0,-2).join("/");
    var strContent = DataUtils.toString(content.getContent().buf());

    nameStr += '<font color="gray" size="-1"> (unverified)</font>';

    if (strContent=="NDN TLV Ping Response\0") {
      document.getElementById('pingreport').innerHTML += '<tr><td width="50%">' + nameStr + ' </td><td align="right">' + (T1-T0) + ' ms</td></tr>' ;
    } else {
      console.log("Unknown content received.");
    }
}

function ping(name) {
  var pingname = name + "/ping/" + Math.floor(Math.random()*100000);
  var T0 = new Date();
  face.expressInterest
    (new Name(pingname),
     function(interest, content) { onData(interest, content, T0); },
     onTimeout);
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

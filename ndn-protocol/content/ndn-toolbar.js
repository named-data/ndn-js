/*
 * This is called from the NDN toolbar and the doorhanger popup on Firefox for Android.
 * Copyright (C) 2013-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/ndn-protocol-info.jsm");

function ndnToolbarGetVersion(selector)
{
  NdnProtocolInfo.getVersion(selector, window, alert);
}

/*
 * This is called when the connected NDN hub changes.
 */
function onNdnHubChanged(host, port)
{
  document.getElementById("ndnHubLabel").setAttribute("value", "Hub: " + host + ":" + port);
}

if (window)
  window.addEventListener("load", function() { NdnProtocolInfo.addNdnHubChangedListener(onNdnHubChanged); },
                          false);

function ndnToolbarSetHub()
{
  var message = NdnProtocolInfo.setHub(window, alert);
  if (message != null)
    document.getElementById("ndnHubLabel").setAttribute("value", message);
}

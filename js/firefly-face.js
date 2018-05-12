/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

/**
 * FireflyFace extends Face to override expressInterest, registerPrefix and
 * putData to interface with Google Firestore. In general, this converts each
 * NDN name like "/ndn/user/bob" to the Firestore path "/ndn/_/user/_/bob/_"
 * where each name component has a document named "_" and a collection having
 * the name of its child component. This updates the "_" document with fields
 * like "interestExpressTime" and "data" to simulate NDN messaging. (The "_"
 * document also has a "children" field with a set of the names of the children
 * nodes, which is necessary because Firestore doesn't allow enumerating
 * children.)
 * @param {firebase.firestore.Firestore} (optional) The Firestore object which
 * is already created. If omitted, use the default "ndn-firefly" project.
 */
var FireflyFace = function FireflyFace(db)
{
  // Call the base constructor.
  // Make Face.reconnectAndExpressInterest call expressInterestHelper directly.
  Face.call(new Transport(), { equals: function() { return true; } });
  this.readyStatus = Face.OPENED;

  if (db == undefined) {
    var config = {
      apiKey: "AIzaSyCDa5xAuQw78RwcpIDT0NmgmcJ9WVL60GY",
      authDomain: "ndn-firefly.firebaseapp.com",
      databaseURL: "https://ndn-firefly.firebaseio.com",
      projectId: "ndn-firefly",
      storageBucket: "",
      messagingSenderId: "225388759140"
    };
    firebase.initializeApp(config);

    db = firebase.firestore();
  }

  this.db_ = db;
  // The set of Name URIs corresponding to the collections where we have added
  // a snapshot listener to the "_" and "children" documents. The key is the URI
  // string and the value is true.
  this.listeningNameUris_ = {};
  this.pendingInterestTable_ = new PendingInterestTable();
  this.interestFilterTable_ = new InterestFilterTable();
};

FireflyFace.prototype = new Face(new Transport(), { equals: function() { return true; } });
FireflyFace.prototype.name = "FireflyFace";

/**
 * Override to do the work of expressInterest using Firestore. If a data packet
 * matching the interest is already in Firestore, call onData immediately,
 * Otherwise, add onSnapshot listeners at toFirestorePath(interest.getName())
 * and children to monitor for the addition of a "data" field.
 */
FireflyFace.prototype.expressInterestHelper = function
  (pendingInterestId, interest, onData, onTimeout, onNetworkNack, wireFormat)
{
  var thisFace = this;

  // First check if the Data packet is already in Firestore.
  // TODO: Check MustBeFresh.
  this.getMatchingDataPromise_(interest.getName(), interest.getMustBeFresh())
  .then(function(data) {
    if (data != null) {
      // Answer onData immediately.
      onData(interest, data);
      return SyncPromise.resolve();
    }
    else {
      if (thisFace.pendingInterestTable_.add
          (pendingInterestId, interest, onData, onTimeout, onNetworkNack) == null)
        // removePendingInterest was already called with the pendingInterestId.
        return SyncPromise.resolve();

      // Express an interest in Firestore.
      return thisFace.establishDocumentPromise_(interest.getName())
      .then(function(document) {
        // TODO: Monitor sub collections with a longer name.
        document.onSnapshot(function(document) {
          // TODO: Check MustBeFresh.
          if (document.data().data) {
            var data = new Data();
            data.wireDecode(new Blob(document.data().data.toUint8Array(), false));

            // Imitate Face.onReceivedElement.
            var pendingInterests = [];
            thisFace.pendingInterestTable_.extractEntriesForExpressedInterest
              (data, pendingInterests);
            // Process each matching PIT entry (if any).
            for (var i = 0; i < pendingInterests.length; ++i) {
              var pendingInterest = pendingInterests[i];
              try {
                pendingInterest.getOnData()(pendingInterest.getInterest(), data);
              } catch (ex) {
                console.log("Error in onData: " + NdnCommon.getErrorWithStackTrace(ex));
              }
            }
          }
        });

        // TODO: Check if an existing interestLifetime has a later expiration.
        return document.set({
          interestExpressTime: firebase.firestore.FieldValue.serverTimestamp(),
          interestLifetime: interest.getInterestLifetimeMilliseconds()
        }, { merge: true });
      });
    }
  }).catch(function(error) {
    console.log("Error in expressInterest:", error);
  });
};

/**
 * Override to do the work of registerPrefix using Firestore. Add onSnapshot
 * listeners at toFirestorePath(prefix.getName()) and children to monitor for
 * the addition of an "interestExpressTime" field. See addListeners_ for details.
 */
FireflyFace.prototype.nfdRegisterPrefix = function
  (registeredPrefixId, prefix, onInterest, flags, onRegisterFailed,
   onRegisterSuccess, commandKeyChain, commandCertificateName, wireFormat)
{
  var thisFace = this;

  this.establishDocumentPromise_(prefix)
  .then(function(document) {
    // Monitor this and all sub documents.

    // Imitate Face.RegisterResponse.onData .
    var interestFilterId = 0;
    if (onInterest != null)
      // registerPrefix was called with the "combined" form that includes the
      // callback, so add an InterestFilterEntry.
      interestFilterId = thisFace.setInterestFilter
        (new InterestFilter(prefix), onInterest);

    if (!thisFace.registeredPrefixTable_.add
        (registeredPrefixId, prefix, interestFilterId)) {
      // removeRegisteredPrefix was already called with the registeredPrefixId.
      if (interestFilterId > 0)
        // Remove the related interest filter we just added.
        this.parent.unsetInterestFilter(interestFilterId);
    }
    else {
      // TODO: Check onRegisterSuccess.
      thisFace.addListeners_(prefix.toUri(), document.parent);
    }
  });
};

/**
 * The OnInterest callback calls this to put a Data packet which satisfies an
 * Interest. Override to put the Data packet into Firestore.
 * @param {Data} data The Data packet which satisfies the interest.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Data packet. If omitted, use WireFormat.getDefaultWireFormat().
 * @throws Error If the encoded Data packet size exceeds getMaxNdnPacketSize().
 */
FireflyFace.prototype.putData = function(data, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var encoding = data.wireEncode(wireFormat);
  if (encoding.size() > Face.getMaxNdnPacketSize())
    throw new Error
      ("The encoded Data packet size exceeds the maximum limit getMaxNdnPacketSize()");

  // TODO: Check if we can remove Interest fields in Firestore.
  this.setDataPromise_(data)
  .catch(function(error) {
    console.log("Error in putData:", error);
  });
};

/**
 * Look in Firestore for an existing Data packet which matches the name.
 * @param {Name} name The Name.
 * @param {boolean} mustBeFresh If true, make sure the Data is not expired
 * according to the Firestore document "storeTime" and "freshnessPeriod".
 * @returns {Promise} A promise that returns the matching Data, or returns null
 * if not found.
 */
FireflyFace.prototype.getMatchingDataPromise_ = function(name, mustBeFresh)
{
  // TODO: Check mustBeFresh.
  // TODO: Do longest prefix match.
  return this.db_.doc(FireflyFace.toFirestorePath(name)).get()
  .then(function(document) {
    if (document.exists && document.data().data) {
      var data = new Data();
      // TODO: Check for decoding error.
      data.wireDecode(new Blob(document.data().data.toUint8Array(), false));
      return SyncPromise.resolve(data);
    }
    else
      return SyncPromise.resolve(null);
  });
};

/**
 * Get the Firestore path for the Name, for example "/ndn/_/user/_/bob/_" for
 * the NDN name "/ndn/user/bob".
 * @param {Name} name The Name.
 * @returns {string} The Firestore path.
 */
FireflyFace.toFirestorePath = function(name)
{
  var result = "";

  for (var i = 0; i < name.size(); ++i)
    result += "/"+ name.components[i].toEscapedString() + "/_";

  return result;
};

/**
 * Recursively add an onSnapshot listener at collection.doc("_") and all
 * children. When collection.doc("_") is updated with an "interestExpressTime"
 * field, onSnapshot processes as if we have received an interest and calls
 * OnInterest callbacks. Add nameUri to listeningNameUris_. However, if nameUri
 * is already in listeningNameUris_, do nothing.
 * @param {string} nameUri The URI of the name represented by collection.
 * @param {firebase.firestore.DocumentReference} collection The collection with
 * name nameUri.
 */
FireflyFace.prototype.addListeners_ = function(nameUri, collection)
{
  if (this.listeningNameUris_[nameUri])
    // We are already listening.
    return;

  this.listeningNameUris_[nameUri] = true;
  var thisFace = this;

  collection.doc("_").onSnapshot(function(document) {
    if (!document.exists)
      return;

    // TODO: Listen for added Data.

    // TODO: A better check if there is already a matching Data.
    if (document.data().interestExpressTime && !document.data().data) {
      var interestLifetime = document.data().interestLifetime;
      // TODO: Check interestLifetime for an expired interest.
      var interest = new Interest(new Name(nameUri));
      interest.setInterestLifetimeMilliseconds(interestLifetime);

      // Imitate Face.onReceivedElement.
      // Call all interest filter callbacks which match.
      var matchedFilters = [];
      thisFace.interestFilterTable_.getMatchedFilters(interest, matchedFilters);
      for (var i = 0; i < matchedFilters.length; ++i) {
        var entry = matchedFilters[i];
        try {
          entry.getOnInterest()
            (entry.getFilter().getPrefix(), interest, thisFace,
             entry.getInterestFilterId(), entry.getFilter());
        } catch (ex) {
          console.log("Error in onInterest: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      }
    }
  });

  collection.doc("children").onSnapshot(function(document) {
    if (!document.exists)
      return;

    for (var componentUri in document.data())
      // This will call onSnapshot and recursively add children.
      thisFace.addListeners_
        (nameUri + "/" + componentUri,
         collection.doc("_").collection(componentUri));
  });
};

/**
 * Set the "data", "storeTime" and "freshnessPeriod" fields in the Firestore
 * document based on data.getName(). If the freshnessPeriod is not specified,
 * this sets it to null. This replaces existing fields.
 * @param {Data} data The Data packet.
 * @param {WireFormat} wireFormat A WireFormat object used to encode the Data
 * packet.
 * @return {Promise} A promise that fulfills when the operation is complete.
 */
FireflyFace.prototype.setDataPromise_ = function(data, wireFormat)
{
  return this.establishDocumentPromise_(data.getName())
  .then(function(document) {
    return document.set({
      data: firebase.firestore.Blob.fromBase64String
        (data.wireEncode(wireFormat).buf().toString('base64')),
      storeTime: firebase.firestore.FieldValue.serverTimestamp(),
      freshnessPeriod: data.getMetaInfo().getFreshnessPeriod()
    }, { merge: true });
  });
};

/**
 * Get the Firestore document for the given name, creating the "children"
 * documents at each level in the collection tree as needed. For example, if
 * Firestore has the document /ndn/_/user/_/joe/_ and you ask for the document
 * for the name /ndn/role/doctor this returns the document
 * /ndn/_/role/_/doctor/_ and adds { role: null } to /ndn/children and adds
 * { doctor: null } to /ndn/_/role/children . (We represent the set of children
 * by an object with the set elements are the key and the value is null.)
 * @param {Name} name The Name for the document.
 * @returns {Promise} A promise that returns the
 * firebase.firestore.DocumentReference .
 */
FireflyFace.prototype.establishDocumentPromise_ = function(name)
{
  // Update the "children" document of the collection, and recursively call this
  // with each component until the collection for the final component and return
  // its "_" document.
  var establish = function(collection, iComponent) {
    if (iComponent >= name.size() - 1)
      // We're finished.
      return SyncPromise.resolve(collection.doc("_"));
    else {
      var childString = name.get(iComponent + 1).toEscapedString();
      // Update the "children" document.
      var content = {};
      content[childString] = null;
      return collection.doc("children").set(content, { merge: true })
      .then(function () {
        return establish(collection.doc("_").collection(childString), iComponent + 1);
      });
    }
  };

  return establish(this.db_.collection(name.get(0).toEscapedString()), 0);
};

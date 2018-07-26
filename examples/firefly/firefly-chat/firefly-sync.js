/*
 * Copyright (C) 2017-2017 Regents of the University of California.
 * @author: Peter Gusev <peter@remap.ucla.edu>
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

// Toggle this to turn the debug messages on or off.
var fireflySyncDebug = false;

/**
 * FireflySync provides sync mechanism similar to ChronoSync, only backed by Firestore backend.
 * @param {firebase.firestore.Firestore} An initialized Firestore object
 * @param syncDoc 	A dictionary with two keys: appName and syncId which together identify
 *					client's app sync entity (example: WhatsApp chatroom; appName='whatsapp',
 *					syncId='chatroom-id').
 * @param applicationPrefix 	Simliar to ChronoSync, this is an application prefix, which
 *								client code will use for data publishing.
 * @param onReceivedSyncState 	A callback (function({'prefix':<seq-no>})) which will be called
 *								whenever new updates (sequence numbres) are received.
 */
var FireflySync = function FireflySync(firestoreDb, syncDoc, applicationPrefix, onInitialized, onReceivedSyncState){
	this.firestoreDb = firestoreDb;
	this.onReceivedSyncState = onReceivedSyncState;
	this.onInitialized = onInitialized;
	this.applicationDataPrefixUri = applicationPrefix;
	this.syncDoc = syncDoc;
	this.lockDocName = this.docNameWithoutVersion()+'/lock';
	this.syncData = {};
	this.syncDocVersion = -1;
	this.mySeqNo = -1;
	this.initialized = false;
	var self = this;

	this.firestoreDb.doc('/sync/'+syncDoc.appName).collection(syncDoc.syncId).onSnapshot(function(snapshot){
		if (fireflySyncDebug) console.log("> firefly-sync: got collection snapshot: ", snapshot);

		if (snapshot.empty)
		{
			if (fireflySyncDebug) console.log("> firefly-sync: sync doc does not exist.");
			// self.createLockDoc();
			self.checkCallOnInitialized();
		}
		else
		{
			// get latest document version
			var lastDoc = self.sorted(snapshot.docChanges)[snapshot.docChanges.length-1].doc;
			if (lastDoc.id != 'lock')
			{
				var newDocVersion = parseInt(lastDoc.id);

				if (newDocVersion < self.syncDocVersion)
					console.error('> firefly-sync: something is wrong, latest doc version less than stored version '+
						newDocVersion +' vs '+self.syncDocVersion)
				else
				{
					self.syncDocVersion = newDocVersion;
					if (fireflySyncDebug) console.log("> firefly-sync: last sync doc version is ", self.syncDocVersion);
					self.processNewSyncState(lastDoc);
				}
			}
		}
	},function(error){
		console.error('> firefly-sync: error getting collection '+syncDoc.syncId+': ', error);
	})
};

FireflySync.prototype.processNewSyncState = function(doc){
	var delta = {}
	var syncData = doc.data();
	var self = this;

	for (var key in syncData)
	{
		var decodedKey = decodeURIComponent(key);
		var newValue = !(key in self.syncData) && decodedKey != self.applicationDataPrefixUri;
		if (!newValue) newValue = (syncData[key] > self.syncData[key]);
		if (newValue) delta[key] = syncData[key];

		// update our seq no if needed
		if (decodedKey == self.applicationDataPrefixUri && self.mySeqNo < syncData[key])
			self.mySeqNo = syncData[key];

		self.syncData[key] = syncData[key];
	}

	self.checkCallOnInitialized();

	if (Object.keys(delta).length)
	{
		// self.onReceivedSyncState(delta);
		// this if for backward compatibility with old ChronoChat code
		// if you don't need this compatibility, use the line above
		var syncStates = [];
		for (var key in delta)
		{
			var decodedKey = decodeURIComponent(key);
			syncStates.push(new ChronoSync2013.SyncState (decodedKey, 0, delta[key], new Blob()));
		}
		self.onReceivedSyncState(syncStates);
	}
	else
		if (fireflySyncDebug) console.log("> firefly-sync: no sync updates");
}

FireflySync.prototype.sorted = function(docChangesArray){
	return docChangesArray.sort(function(a,b){
		var aId = parseInt(a.doc.id);
		var bId = parseInt(b.doc.id);
		
		if(aId < bId) return -1;
    	if(aId > bId) return 1;
    	return 0;
	});
}

FireflySync.prototype.sortedDocs = function(docsArray){
	return docsArray.sort(function(a,b){
		var aId = parseInt(a.id);
		var bId = parseInt(b.id);
		
		if(aId < bId) return -1;
    	if(aId > bId) return 1;
    	return 0;
	});
}

FireflySync.prototype.fullDocName = function(){
	return this.docNameWithoutVersion()+'/'+this.syncDocVersion;
}

FireflySync.prototype.docNameWithoutVersion = function() {
	return '/sync/'+this.syncDoc.appName+'/'+this.syncDoc.syncId;
};

FireflySync.prototype.createLockDoc = function(){
	if (fireflySyncDebug) console.log("> firefly-sync: will create lock document", this.lockDocName);

	this.firestoreDb.doc(this.lockDocName).set({ version:this.syncDocVersion })
	.then(function(){
		if (fireflySyncDebug) console.log("> firefly-sync: lock doc created");
	})
	.catch(function(error){
		console.error('> firefly-sync: error creating lock doc: ', error);
	});
}

FireflySync.prototype.createSyncDoc = function(syncDocName) {
	if (fireflySyncDebug) console.log("> firefly-sync: will create ", syncDocName);
	// setup empty document
	var self = this;
	this.firestoreDb.doc(syncDocName).set(this.syncData)
	.then(function(){
		if (fireflySyncDebug) console.log("> firefly-sync: new sync doc created: ", syncDocName);
		if (fireflySyncDebug) console.log("> firefly-sync: contents: ", self.syncData);
		self.checkCallOnInitialized();
	})
	.catch(function(error){
		console.error('> firefly-sync: error creating sync doc: ', error);
	});
}

FireflySync.prototype.checkCallOnInitialized = function(){
	if (!this.initialized)
	{
		this.initialized = true
		this.onInitialized();
	}
}

/**
 * Simliar to ChronoSync, this will increment current sequence number and notify all other participants
 * through updating sync document.
 * @return New sequence number
 */
FireflySync.prototype.publishNextSequenceNo = function(){
	this.syncDocVersion++;
	this.mySeqNo++;
	this.syncData[encodeURIComponent(this.applicationDataPrefixUri)] = this.mySeqNo;

	this.createSyncDoc(this.fullDocName());

	// var lockDocRef = this.firestoreDb.doc(this.lockDocName)
	// var self = this;
	// var i = 1;
	// this.firestoreDb.runTransaction(function(transaction) {
	// 	if (fireflySyncDebug) console.log("transation run ", i++);
 //    	return transaction.get(lockDocRef).then(function(lockDoc) {
 //    		self.syncDocVersion = lockDoc.data().version; // get latest version

 //    		// now we need to read sync doc from db to update our syncData
 //    		var syncDocRef = self.firestoreDb.doc(self.fullDocName());
 //        	syncDocRef.get().then(function(doc){
 //        		var newVersion = self.syncDocVersion+1;

 //        		if (doc.exists)
 //        		{
 //        			self.processNewSyncState(doc); // update sync data from new sync doc
 //        			lockDoc.data().version + 1; // bump the version
 //        			transaction.update(syncDocRef, doc.data()); // dummy update to make firebase happy
 //        		}
 //        		else
 //        			transaction.update(syncDocRef, {}); // dummy update to make firebase happy
 //        		transaction.update(lockDocRef, { version: newVersion }); // save new version

 //        		self.syncDocVersion = newVersion;
 //        		self.createSyncDoc(self.fullDocName()); // create new sync doc
 //        	});
 //    	});
	// }).then(function() {
 //    	// if (fireflySyncDebug) console.log("> firefly-sync: transaction successfully committed!");
	// }).catch(function(error) {
 //    	console.error("> firefly-sync: transaction failed: ", error);
	// });

	return this.mySeqNo;
}

/**
 * Returns current sequence number
 */
FireflySync.prototype.getSequenceNo = function(){
	return this.mySeqNo;
}

FireflySync.prototype.getSyncStatesDelta = function(syncDocOld, syncDocNew) {
	var delta = {};

	for (var key in syncDocNew)
	{
		var newValue = !(key in syncDocOld);
		if (!newValue) newValue = (syncDocNew[key] > syncDocOld[key]);
		if (newValue) delta[key] = syncDocNew[key];
	}

	return delta;
};

FireflySync.prototype.getHistoricalSyncStates = function(onSyncStatesFetched) {
	var collRef = this.firestoreDb.doc('/sync/'+syncDoc.appName).collection(syncDoc.syncId);
	var self = this;
	var syncStates = [];

	collRef.get().then(function(snap){
		var sortedDocs = self.sortedDocs(snap.docs);

		if (sortedDocs.length)
			sortedDocs.forEach(function(docSnap, idx, arr){
				syncStates.push(docSnap.data());
				if (idx == arr.length-1) onSyncStatesFetched(syncStates);
			});
		else
			onSyncStatesFetched(syncStates);
	});
};

FireflySync.prototype.getHistoricalDeltas = function(onDeltasFetched) {
	var self = this;

	this.getHistoricalSyncStates(function(syncStates){
		var lastSyncState = null
		var deltas = []
		
		if (syncStates.length)
			syncStates.forEach(function(syncState, idx, arr){
				if (lastSyncState)
					deltas.push(self.getSyncStatesDelta(lastSyncState, syncState));
				else
					deltas.push(syncState);
				lastSyncState = syncState
				if (idx == arr.length-1) onDeltasFetched(deltas);
			});
		else
			onDeltasFetched(deltas);
	});
}

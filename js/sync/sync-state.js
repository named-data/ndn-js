var ProtoBuf = require("protobufjs");

var Sync = ProtoBuf.newBuilder().import({
    "package": "Sync",
    "messages": [
        {
            "name": "SyncState",
            "fields": [
                {
                    "rule": "required",
                    "type": "string",
                    "name": "name",
                    "id": 1,
                    "options": {}
                },
                {
                    "rule": "required",
                    "type": "ActionType",
                    "name": "type",
                    "id": 2,
                    "options": {}
                },
                {
                    "rule": "optional",
                    "type": "SeqNo",
                    "name": "seqno",
                    "id": 3,
                    "options": {}
                }
            ],
            "enums": [
                {
                    "name": "ActionType",
                    "values": [
                        {
                            "name": "UPDATE",
                            "id": 0
                        },
                        {
                            "name": "DELETE",
                            "id": 1
                        },
                        {
                            "name": "OTHER",
                            "id": 2
                        }
                    ],
                    "options": {}
                }
            ],
            "messages": [
                {
                    "name": "SeqNo",
                    "fields": [
                        {
                            "rule": "required",
                            "type": "uint32",
                            "name": "seq",
                            "id": 1,
                            "options": {}
                        },
                        {
                            "rule": "required",
                            "type": "uint32",
                            "name": "session",
                            "id": 2,
                            "options": {}
                        }
                    ],
                    "enums": [],
                    "messages": [],
                    "options": {}
                }
            ],
            "options": {}
        },
        {
            "name": "SyncStateMsg",
            "fields": [
                {
                    "rule": "repeated",
                    "type": "SyncState",
                    "name": "ss",
                    "id": 1,
                    "options": {}
                }
            ],
            "enums": [],
            "messages": [],
            "options": {}
        }
    ],
    "enums": [],
    "imports": [],
    "options": {}
}).build("Sync");

exports.SyncStateMsg = Sync.SyncStateMsg;
exports.SyncState = Sync.SyncState;
// Just define the SyncStateProto object. We do a Protobuf import dynamically
// when we need it so that protobufjs is optional.
var SyncStateProto = {
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
                },
                {
                    "rule": "optional",
                    "type": "bytes",
                    "name": "application_info",
                    "id": 4,
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
};

exports.SyncStateProto = SyncStateProto;

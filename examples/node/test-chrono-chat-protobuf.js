var ProtoBuf = require("protobufjs");

var SyncDemo = ProtoBuf.newBuilder().import({
    "package": "SyncDemo",
    "messages": [
        {
            "name": "ChatMessage",
            "fields": [
                {
                    "rule": "required",
                    "type": "string",
                    "name": "to",
                    "id": 1,
                    "options": {}
                },
                {
                    "rule": "required",
                    "type": "string",
                    "name": "from",
                    "id": 2,
                    "options": {}
                },
                {
                    "rule": "required",
                    "type": "ChatMessageType",
                    "name": "type",
                    "id": 3,
                    "options": {
                        "default": "CHAT"
                    }
                },
                {
                    "rule": "optional",
                    "type": "string",
                    "name": "data",
                    "id": 4,
                    "options": {}
                },
                {
                    "rule": "required",
                    "type": "int32",
                    "name": "timestamp",
                    "id": 5,
                    "options": {}
                }
            ],
            "enums": [
                {
                    "name": "ChatMessageType",
                    "values": [
                        {
                            "name": "CHAT",
                            "id": 0
                        },
                        {
                            "name": "HELLO",
                            "id": 1
                        },
                        {
                            "name": "LEAVE",
                            "id": 2
                        },
                        {
                            "name": "JOIN",
                            "id": 3
                        },
                        {
                            "name": "OTHER",
                            "id": 4
                        }
                    ],
                    "options": {}
                }
            ],
            "messages": [],
            "options": {}
        }
    ],
    "enums": [],
    "imports": [],
    "options": {}
}).build("SyncDemo");

exports.ChatMessage = SyncDemo.ChatMessage;
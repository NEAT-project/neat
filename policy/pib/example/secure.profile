{
    "uid":"secure",
    "description":"secure connection policy",
    "priority": 6,
    "replace_matched": false,
    "match":{
        "security ": {
            "value": true
        },
        "transport": {
            "value": ["TCP", "SCTP"]
        }
    },
    "properties":{
        "tls": {
            "value": true,
            "precedence": 2
        },
        "port": {
            "value": 443,
            "precedence": 1
        }
    }
}


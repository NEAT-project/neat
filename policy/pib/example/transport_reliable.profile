{
    "uid":"reliable_transport",
    "description":"select a reliable transport protocol",
    "priority": 2,
    "replace_matched": false,
    "match":{
        "transport": {
            "value": "reliable"
        }
    },
    "properties":{
        "transport": {
            "value": ["TCP", "SCTP", "MPTCP"],
            "precedence": 2
        }
    }
}


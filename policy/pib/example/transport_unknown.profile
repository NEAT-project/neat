{
    "uid":"transport_unknown",
    "description":"default transport options",
    "priority": 1,
    "replace_matched": true,
    "match":{
        "transport": {
            "value": "unkown"
        }
    },
    "properties":{
        "transport": [{
            "value": "SCTP",
            "precedence": 2,
            "score": 3
        },
        {
            "value": "MPTCP",
            "precedence": 2,
            "score": 1
        },
        {
            "value": "TCP",
            "precedence": 2,
            "score": 2
        }]
    }
}


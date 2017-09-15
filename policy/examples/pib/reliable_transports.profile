{
    "uid":"reliable_transports",
    "description":"reliable transport protocols profile",
    "policy_type": "profile",
    "priority": 2,
    "replace_matched": true,
    "match":{
        "transport": {"value": "reliable"}
    },
    "properties":[
        [{"transport": { "value": "SCTP", "precedence": 2, "score": 3}},
         {"transport": { "value": "TCP", "precedence": 2, "score": 2}},
         {"transport": { "value": "SCTP/UDP", "precedence": 2, "score": 1}}
         ]
    ]
}


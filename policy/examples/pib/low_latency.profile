{
    "uid":"low_latency",
    "policy_type": "profile",
    "description":"generic low latency profile",
    "priority": 1,
    "replace_matched": false,
    "match":{
        "low_latency": {
            "value": true
        }
    },
    "properties":{
        "RTT": {
            "precedence": 1,
            "value": {"start":0, "end":50},
            "score": 5
        },
        "low_latency_interface": 
            { "value": true, "precedence": 1},
        "is_wired_interface": {
            "precedence": 1,
            "value": true
        }
    }
}


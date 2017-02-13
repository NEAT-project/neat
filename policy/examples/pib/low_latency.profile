{
    "uid":"low_latency",
    "description":"low latency profile",
    "priority": 1,
    "replace_matched": true,
    "match":{
        "low_latency": {
            "precedence": 1,
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
            "precedence": 2,
            "value": true
        }
    }
}


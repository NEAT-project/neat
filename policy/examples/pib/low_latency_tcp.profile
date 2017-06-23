{
    "uid":"low_latency_tcp",
    "policy_type": "profile",
    "description":"TCP specific low latency profile",
    "priority": 3,
    "replace_matched": false,
    "match":{
        "low_latency": {"value": true},
        "transport": {"value": "TCP"}
    },
    "properties":[[
      {"transport": { "value": "TCP", "precedence": 2},
       "SO/SOL_SOCKET/TCP_NODELAY": { "value": 1, "precedence": 1}}
    ]]
}


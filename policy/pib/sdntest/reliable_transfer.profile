{
    "name":"Reliable transfer",
    "description":"use TCP or MPTCP",
    "priority": 5,
    "replace_matched": true,
    "match":{
        "transport": {
            "value": "reliable"
        }
    },
    "properties":{
        "transport": [{"precedence": 2,"value": "TCP"}, {"precedence": 2,"value": "MPTCP", "score": 2}] 
    }
}


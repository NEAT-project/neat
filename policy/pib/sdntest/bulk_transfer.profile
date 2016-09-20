{
    "name":"Bulk transfer",
    "description":"bulk file transfer profile (elephant flow)",
    "priority": 5,
    "replace_matched": false,
    "match":{
        "remote_ip": {
            "precedence": 2,
            "value": "203.0.113.23",
            "description":"remote backup server IP"
        }
    },
    "properties":{
        "elephant": {
		    "precedence": 2,
            "value": true
        },          
        "MTU": {
            "value": [9000, 1500]
        },
        "capacity": {
            "precedence": 2,
            "value": {"start":1000, "end":10000}
        }
    }
}


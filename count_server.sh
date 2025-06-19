jq '[.[] | to_entries[] | .key] | length' /www/wwwroot/Golang/autov2/clusters.json

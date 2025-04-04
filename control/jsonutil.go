package control

import "encoding/json"

func ToJson(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

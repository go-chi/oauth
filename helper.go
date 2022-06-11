package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
)

func StructToJson(bodybytes *bytes.Buffer) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bodybytes)
	var empJSON map[string]interface{}
	err := decoder.Decode(&empJSON)
	if err != nil {
		return nil, errors.New("Unable to convert request body")
	}

	return empJSON, nil
}

package main

import (
    "encoding/base64"
    "encoding/json"
    "log"
    "os"
)

type echKeyData struct {
    ConfigID      string `json:"config_id"`
    PublicName    string `json:"public_name"`
    PrivateKeyB64 string `json:"private_key_b64"`
    ECHConfigB64  string `json:"ech_config_b64"`
}

type echKeys struct {
    Config     []byte
    PrivateKey []byte
    PublicName string
}

func loadECHKeys(path string) *echKeys {
    data, err := os.ReadFile(path)
    if err != nil {
        log.Printf("ECH: no keys file, ECH disabled")
        return nil
    }
    var kd echKeyData
    if err := json.Unmarshal(data, &kd); err != nil {
        log.Printf("ECH: bad keys file")
        return nil
    }
    cfg, err := base64.StdEncoding.DecodeString(kd.ECHConfigB64)
    if err != nil {
        return nil
    }
    priv, err := base64.StdEncoding.DecodeString(kd.PrivateKeyB64)
    if err != nil {
        return nil
    }
    return &echKeys{Config: cfg, PrivateKey: priv, PublicName: kd.PublicName}
}

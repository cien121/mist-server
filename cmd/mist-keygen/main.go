// mist-keygen: generate a Mist account (CID + K_auth).
//
// Usage:
//   mist-keygen                       # print one account as JSON
//   mist-keygen -append accounts.json # append to an accounts file (creates it)
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"mist/mistcore"
)

func main() {
	appendPath := flag.String("append", "", "accounts JSON file to append to")
	flag.Parse()

	var cid [16]byte
	copy(cid[:], mistcore.RandomBytes(16))
	var ka [32]byte
	copy(ka[:], mistcore.RandomBytes(32))

	entry := map[string]string{
		hex.EncodeToString(cid[:]): base64.StdEncoding.EncodeToString(ka[:]),
	}

	if *appendPath == "" {
		out, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(out))
		return
	}

	accounts := map[string]string{}
	if b, err := os.ReadFile(*appendPath); err == nil {
		if err := json.Unmarshal(b, &accounts); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", *appendPath, err)
			os.Exit(1)
		}
	}
	for k, v := range entry {
		accounts[k] = v
	}
	out, _ := json.MarshalIndent(accounts, "", "  ")
	if err := os.WriteFile(*appendPath, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *appendPath, err)
		os.Exit(1)
	}
	fmt.Printf("appended account %s to %s\n", hex.EncodeToString(cid[:]), *appendPath)
}

// Command mkversion prints linker flags for a versioned Tailmix build.
package main

import (
	"fmt"
	"log"

	"github.com/maisem/tailmix/version/mkversion"
)

func main() {
	info, err := mkversion.InfoFrom(".")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("-X github.com/maisem/tailmix/version.shortStamp=%s ", info.Short)
	fmt.Printf("-X github.com/maisem/tailmix/version.longStamp=%s ", info.Long)
	fmt.Printf("-X github.com/maisem/tailmix/version.gitCommitStamp=%s\n", info.GitHash)
}

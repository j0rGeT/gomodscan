package pkg

import (
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"gomodscan/pkg/db"
	"gomodscan/pkg/scanner"
	"path/filepath"
)

func Scan(c *cli.Context) error {
	sourceDir := c.String("source-dir")
	modfile := filepath.Join(sourceDir, "go.mod")
	if flag, err := scanner.PathExists(modfile); !flag || err != nil {
		return errors.New("go mod file is not exists")
	}

	pkgMap := scanner.ReadModFile(modfile)

	err := db.Init("./db")
	if err != nil {
		return err
	}

	for pkgName, pkgVer := range pkgMap {
		vulns, err := scanner.GetVulns(pkgName, pkgVer)
		if err != nil {
			return err
		}
		if len(vulns) == 0 {
			fmt.Println(fmt.Sprintf("%s:%s no vulns", pkgName, pkgVer))
		} else {
			fmt.Println(vulns)
		}
	}

	return nil
}

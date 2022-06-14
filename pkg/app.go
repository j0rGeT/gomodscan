package pkg

import (
	"github.com/urfave/cli"
	"gomodscan/pkg/utils"
)

type AppConfig struct{}

func (ac *AppConfig) NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "go-mod-scan"
	app.Version = version
	app.Usage = "scan"

	app.Commands = []cli.Command{
		{
			Name:   "scan",
			Usage:  "scan",
			Action: Scan,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "source-dir",
					Usage: "source directory path",
					Value: utils.CacheDir(),
				},
			},
		},
	}
	return app
}

package downloader

import (
	_ "embed"
	"fmt"
	"io/fs"
	"io/ioutil"
	"path"

	"github.com/keyval-dev/offsets-tracker/utils"
)

const appName = "testapp"

var (
	//go:embed wrapper/go.mod.txt
	goMod string

	//go:embed wrapper/main.go.txt
	goMain string
)

func DownloadBinary(modName string, version string) (string, string, error) {
	fmt.Println("Creating temp dir")
	dir, err := ioutil.TempDir("", appName)
	if err != nil {
		return "", "", err
	}

	fmt.Println("Writing testapp go.mod")
	goModContent := fmt.Sprintf(goMod, modName, version)
	err = ioutil.WriteFile(path.Join(dir, "go.mod"), []byte(goModContent), fs.ModePerm)
	if err != nil {
		return "", "", err
	}

	fmt.Println("Writing testapp main.go")
	goMainContent := fmt.Sprintf(goMain, modName)
	err = ioutil.WriteFile(path.Join(dir, "main.go"), []byte(goMainContent), fs.ModePerm)
	if err != nil {
		return "", "", err
	}

	fmt.Println("Running go mod tidy")
	err, _, _ = utils.RunCommand("go mod tidy -compat=1.17", dir)
	if err != nil {
		return "", "", err
	}

	fmt.Println("Running go build")
	err, _, _ = utils.RunCommand("GOOS=linux GOARCH=amd64 go build", dir)
	if err != nil {
		return "", "", err
	}

	return path.Join(dir, appName), dir, nil
}

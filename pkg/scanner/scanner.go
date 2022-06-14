package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/go-version/pkg/version"
	"golang.org/x/xerrors"
	"gomodscan/pkg/db"
	"gomodscan/pkg/types"
	"io"
	"os"
	"strings"
)

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

type DetectedVulnerability struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	DataSource       *types.DataSource
}

func matchVersion(currentVersion, constraint string) (bool, error) {
	ver, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("constraint error (%s): %s", currentVersion, err)
	}

	return c.Check(ver), nil
}

func IsVulnerable(pkgVer string, advisory types.Advisory) bool {
	match := matchVersion
	// If one of vulnerable/patched versions is empty, we should detect it anyway.
	for _, v := range append(advisory.VulnerableVersions, advisory.PatchedVersions...) {
		if v == "" {
			return true
		}
	}
	var matched bool
	var err error

	if len(advisory.VulnerableVersions) != 0 {
		matched, err = match(pkgVer, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil {
			return false
		} else if !matched {
			// the version is not vulnerable
			return false
		}
	}

	secureVersions := append(advisory.PatchedVersions, advisory.UnaffectedVersions...)
	if len(secureVersions) == 0 {
		// the version matches vulnerable versions and patched/unaffected versions are not provided
		// or all values are empty
		return matched
	}

	matched, err = match(pkgVer, strings.Join(secureVersions, " || "))
	if err != nil {
		return false
	}
	return !matched
}

func ReadModFile(filename string) map[string]string {
	res := make(map[string]string)
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	var chunk []byte
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return nil
		}
		if n == 0 {
			break
		}
		chunk = append(chunk, buf[:n]...)
	}
	fmt.Println(string(chunk))

	lines := strings.Split(string(chunk), "\n")
	start_flag := false
	for _, line := range lines {
		if start_flag {
			pkginfo := strings.Split(line, " ")
			if len(pkginfo) < 2 {
				continue
			}
			pkgName := pkginfo[0]
			pkgVer := pkginfo[1]
			res[strings.TrimSpace(pkgName)] = strings.TrimSpace(pkgVer)
		}
		if strings.Contains(line, "(") {
			start_flag = true
		}
		if strings.Contains(line, ")") {
			start_flag = false
		}
	}
	return res
}

func GetVulns(pkgName string, pkgVer string) ([]DetectedVulnerability, error) {
	cfg := db.Config{}
	res, err := cfg.ForEach([]string{"go::", pkgName})

	var results []types.Advisory
	for vulnID, v := range res {
		var advisory types.Advisory
		if err = json.Unmarshal(v.Content, &advisory); err != nil {
			return nil, err
		}

		advisory.VulnerabilityID = vulnID
		if v.Source != (types.DataSource{}) {
			advisory.DataSource = &types.DataSource{
				ID:   v.Source.ID,
				Name: v.Source.Name,
				URL:  v.Source.URL,
			}
		}
		results = append(results, advisory)
	}

	var vulns []DetectedVulnerability
	for _, adv := range results {
		if !IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func createFixedVersions(advisory types.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return strings.Join(advisory.PatchedVersions, ", ")
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for _, s := range strings.Split(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}

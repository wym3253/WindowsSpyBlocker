package dnsres

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
)

// Timeout and URI templates for DNS resolutions external services
const (
	HttpTimeout  = 10
	CacheTimeout = 172800

	virusTotalAPIKeyEnv = "VT_API_KEY"
	virusTotalResPath   = "%s/%s/resolutions"
)

// GetDnsRes returns the DNS resolutions of an ip address or domain
func GetDnsRes(ipAddressOrDomain string) Resolutions {
	var result Resolutions

	resultFile := path.Join(pathu.Tmp, "resolutions.json")
	resultJson := make(map[string]Resolutions)

	if resultTmpInfo, err := os.Stat(resultFile); err == nil {
		resultTmpModified := time.Since(resultTmpInfo.ModTime()).Seconds()
		if resultTmpModified <= CacheTimeout {
			raw, err := os.ReadFile(resultFile)
			if err != nil {
				return result
			}
			err = json.Unmarshal(raw, &resultJson)
			if err != nil {
				return result
			}
			if result, found := resultJson[ipAddressOrDomain]; found {
				sort.Sort(result)
				return result
			}
		}
	}

	reportType := "domain"
	if net.ParseIP(ipAddressOrDomain) != nil {
		reportType = "ip"
	}

	result, err := getOnline(reportType, ipAddressOrDomain)
	if err != nil {
		return result
	}
	resultJson[ipAddressOrDomain] = result
	resultJsonMarsh, _ := json.Marshal(resultJson)
	_ = os.WriteFile(resultFile, resultJsonMarsh, 0644)
	return result
}

func getOnline(reportType string, ipOrDomain string) (Resolutions, error) {
	var result Resolutions

	apiKey := strings.TrimSpace(os.Getenv(virusTotalAPIKeyEnv))
	if apiKey == "" {
		return result, fmt.Errorf("%s is not set", virusTotalAPIKeyEnv)
	}

	collection := "domains"
	if reportType == "ip" {
		collection = "ip_addresses"
	}
	uri := vt.URL(virusTotalResPath, collection, url.PathEscape(ipOrDomain))

	client := vt.NewClient(apiKey, vt.WithHTTPClient(&http.Client{
		Timeout: HttpTimeout * time.Second,
	}))
	it, err := client.Iterator(uri, vt.IteratorBatchSize(40))
	if err != nil {
		return result, err
	}
	defer it.Close()

	for it.Next() {
		obj := it.Get()
		ipOrDomain, _ := obj.GetString("ip_address")
		if reportType == "ip" {
			ipOrDomain, _ = obj.GetString("host_name")
		}
		ipOrDomain = strings.TrimSpace(ipOrDomain)
		if ipOrDomain == "" {
			continue
		}

		lastResolved, err := obj.GetTime("date")
		if err != nil {
			continue
		}

		result = append(result, Resolution{
			Source:       obj.Links().Self,
			LastResolved: lastResolved.UTC(),
			IpOrDomain:   ipOrDomain,
		})
	}
	if err := it.Error(); err != nil {
		return result, err
	}

	if len(result) == 0 {
		return result, errors.New("No data available")
	}

	sort.Sort(result)
	return result, nil
}

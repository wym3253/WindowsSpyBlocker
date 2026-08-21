package dnsres

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOnlineUsesVirusTotalPagination(t *testing.T) {
	t.Cleanup(func() {
		vt.SetHost("https://www.virustotal.com")
	})
	t.Setenv(virusTotalAPIKeyEnv, "test-key")

	var requests []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-key", r.Header.Get("x-apikey"))
		requests = append(requests, r.URL.RequestURI())

		if r.URL.Query().Get("cursor") == "next" {
			writeVirusTotalResolutionPage(t, w, "", virusTotalResolution{
				Date:      200,
				HostName:  "example.com",
				IPAddress: "2.2.2.2",
			})
			return
		}

		writeVirusTotalResolutionPage(t, w, server.URL+"/api/v3/domains/example.com/resolutions?cursor=next", virusTotalResolution{
			Date:      100,
			HostName:  "example.com",
			IPAddress: "1.1.1.1",
		})
	}))
	defer server.Close()

	vt.SetHost(server.URL)

	result, err := getOnline("domain", "example.com")
	require.NoError(t, err)

	require.Len(t, requests, 2)
	assert.True(t, strings.HasPrefix(requests[0], "/api/v3/domains/example.com/resolutions"))
	assert.Equal(t, "/api/v3/domains/example.com/resolutions?cursor=next", requests[1])

	want := Resolutions{
		{LastResolved: time.Unix(200, 0).UTC(), IpOrDomain: "2.2.2.2"},
		{LastResolved: time.Unix(100, 0).UTC(), IpOrDomain: "1.1.1.1"},
	}
	require.Len(t, result, len(want))
	for i, expected := range want {
		assert.Equal(t, expected.LastResolved, result[i].LastResolved)
		assert.Equal(t, expected.IpOrDomain, result[i].IpOrDomain)
	}
}

type virusTotalResolution struct {
	Date      int64
	HostName  string
	IPAddress string
}

func writeVirusTotalResolutionPage(t *testing.T, w http.ResponseWriter, next string, resolution virusTotalResolution) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")

	response := struct {
		Data []struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				Date      int64  `json:"date"`
				HostName  string `json:"host_name"`
				IPAddress string `json:"ip_address"`
			} `json:"attributes"`
			Links struct {
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links"`
	}{}

	response.Data = append(response.Data, struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Date      int64  `json:"date"`
			HostName  string `json:"host_name"`
			IPAddress string `json:"ip_address"`
		} `json:"attributes"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	}{
		Type: "resolution",
		ID:   resolution.IPAddress + resolution.HostName,
	})
	response.Data[0].Attributes.Date = resolution.Date
	response.Data[0].Attributes.HostName = resolution.HostName
	response.Data[0].Attributes.IPAddress = resolution.IPAddress
	response.Data[0].Links.Self = "/api/v3/resolutions/" + response.Data[0].ID
	response.Links.Next = next

	assert.NoError(t, json.NewEncoder(w).Encode(response))
}

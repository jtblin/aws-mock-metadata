package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

// Custom HTTP client, that defines the redirect behavior.
// Don't follow 301s, return them so the tests can correctly identify and validate responses
func testHttpClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DRY
func doBodyTest(t *testing.T, uri string, expected_body string) {
	client := testHttpClient()
	res, err := client.Get(testServer.URL + uri)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expected_body {
		t.Errorf("%s : Expected\n\n%s\n\ngot\n\n%s", uri, expected_body, string(body))
	}
}

// Some URIs have 301 redirects on the real metadata service
func doRedirectTest(t *testing.T, uri string, expected_location_uri string) {
	client := testHttpClient()
	res, err := client.Get(testServer.URL + uri)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 301 {
		t.Errorf("%s : Expected HTTP Status Code 301, got %d\n", uri, res.StatusCode)
	}
	if res.Header.Get("Location") == "" {
		t.Errorf("%s : Expected a 'Location' HTTP response header, none found\n", uri)
	}
	expected_location := fmt.Sprintf("http://169.254.169.254%s", expected_location_uri)
	if res.Header.Get("Location") != expected_location {
		t.Errorf("%s : Expected 'Location' HTTP response header of %s, got %s\n", uri, expected_location, res.Header.Get("Location"))
	}
}

func TestRoot(t *testing.T) {
	expected_body := `1.0
2007-01-19
2007-03-01
2007-08-29
2007-10-10
2007-12-15
2008-02-01
2008-09-01
2009-04-04
2011-01-01
2011-05-01
2012-01-12
2014-02-25
2014-11-05
2015-10-20
2016-04-19
2016-06-30
2016-09-02
latest`

	doBodyTest(t, "", expected_body)
	doBodyTest(t, "/", expected_body)
}

func TestLatest(t *testing.T) {
	expected_body := `dynamic
meta-data
user-data`

	doRedirectTest(t, "/latest", "/latest/")
	doBodyTest(t, "/latest/", expected_body)
}

func TestLatestDynamic(t *testing.T) {
	expected_body := `instance-identity/
`

	doRedirectTest(t, "/latest/dynamic", "/latest/dynamic/")
	doBodyTest(t, "/latest/dynamic/", expected_body)
}

func TestLatestDynamicInstanceIdentity(t *testing.T) {
	expected_body := `document
pkcs7
signature
`

	doRedirectTest(t, "/latest/dynamic/instance-identity", "/latest/dynamic/instance-identity/")
	doBodyTest(t, "/latest/dynamic/instance-identity/", expected_body)
}

func TestLatestDynamicInstanceIdentityDocument(t *testing.T) {
	expected_body := `{
  "instanceId" : "i-asdfasdf",
  "billingProducts" : null,
  "imageId" : "ami-asdfasdf",
  "architecture" : "x86_64",
  "pendingTime" : "",
  "instanceType" : "t2.micro",
  "accountId" : "",
  "kernelId" : null,
  "ramdiskId" : null,
  "region" : "us-east-1",
  "version" : "2010-08-31",
  "availabilityZone" : "us-east-1a",
  "devpayProductCodes" : null,
  "privateIp" : "10.20.30.40"
}`

	doBodyTest(t, "/latest/dynamic/instance-identity/document", expected_body)
	doBodyTest(t, "/latest/dynamic/instance-identity/document/", expected_body)
}

func TestLatestDynamicInstanceIdentityPkcs7(t *testing.T) {
	expected_body := `TODO-correct-output`

	doBodyTest(t, "/latest/dynamic/instance-identity/pkcs7", expected_body)
	doBodyTest(t, "/latest/dynamic/instance-identity/pkcs7/", expected_body)
}

func TestLatestDynamicInstanceIdentitySignature(t *testing.T) {
	expected_body := `TODO-correct-output`

	doBodyTest(t, "/latest/dynamic/instance-identity/signature", expected_body)
	doBodyTest(t, "/latest/dynamic/instance-identity/signature/", expected_body)
}

func TestLatestMetaData(t *testing.T) {
	// NOTE: iam/ only appears if there is an IAM Instance Profile attached to the instance. assuming available for simulation purposes for now.
	expected_body := `ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
reservation-id
security-groups
services/`

	doRedirectTest(t, "/latest/meta-data", "/latest/meta-data/")
	doBodyTest(t, "/latest/meta-data/", expected_body)
}

func TestLatestMetaDataAmiId(t *testing.T) {
	expected_body := `ami-asdfasdf`

	doBodyTest(t, "/latest/meta-data/ami-id", expected_body)
	doBodyTest(t, "/latest/meta-data/ami-id/", expected_body)
}

func TestLatestMetaDataAmiLaunchIndex(t *testing.T) {
	expected_body := `0`

	doBodyTest(t, "/latest/meta-data/ami-launch-index", expected_body)
	doBodyTest(t, "/latest/meta-data/ami-launch-index/", expected_body)
}

func TestLatestMetaDataAmiManifestPath(t *testing.T) {
	expected_body := `(unknown)`

	doBodyTest(t, "/latest/meta-data/ami-manifest-path", expected_body)
	doBodyTest(t, "/latest/meta-data/ami-manifest-path/", expected_body)
}

func TestLatestMetaDataBlockDeviceMapping(t *testing.T) {
	expected_body := `ami
root`

	doRedirectTest(t, "/latest/meta-data/block-device-mapping", "/latest/meta-data/block-device-mapping/")
	doBodyTest(t, "/latest/meta-data/block-device-mapping/", expected_body)
}

func TestLatestMetaDataBlockDeviceMappingAmi(t *testing.T) {
	expected_body := `/dev/xvda`

	doBodyTest(t, "/latest/meta-data/block-device-mapping/ami", expected_body)
	doBodyTest(t, "/latest/meta-data/block-device-mapping/ami/", expected_body)
}

func TestLatestMetaDataBlockDeviceMappingRoot(t *testing.T) {
	expected_body := `/dev/xvda`

	doBodyTest(t, "/latest/meta-data/block-device-mapping/root", expected_body)
	doBodyTest(t, "/latest/meta-data/block-device-mapping/root/", expected_body)
}

func TestLatestMetaDataHostname(t *testing.T) {
	expected_body := `testhostname`

	doBodyTest(t, "/latest/meta-data/hostname", expected_body)
	doBodyTest(t, "/latest/meta-data/hostname/", expected_body)
}

func TestLatestUserData(t *testing.T) {
	// TODO: /latest/user-data returns a 404 if none exists... or if one exists, will return it?
	// should we expose this in the API? not implemented right now. could be useful...
}

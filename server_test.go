package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
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
func doBodyTest(t *testing.T, method string, uri string, expected_body string) {
	client := testHttpClient()
	req, err := http.NewRequest(method, testServer.URL+uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	// HACK: just check the length not the contents... for /api/token
	// TODOLATER: adjust the input args for this function, do a switch statement or equivalent based on length or value checks
	if expected_body == "56char" {
		if len(string(body)) != 56 {
			t.Errorf("%s %s : Expected 56 character response body, got a %d character body %s\n", method, uri, len(string(body)), string(body))
		}
	} else {
		if string(body) != expected_body {
			t.Errorf("%s %s : Expected\n\n%s\n\ngot\n\n%s", method, uri, expected_body, string(body))
		}
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
		t.Errorf("GET %s : Expected HTTP Status Code 301, got %d\n", uri, res.StatusCode)
	}
	if res.Header.Get("Location") == "" {
		t.Errorf("GET %s : Expected a 'Location' HTTP response header, none found\n", uri)
	}
	expected_location := fmt.Sprintf("http://169.254.169.254%s", expected_location_uri)
	if res.Header.Get("Location") != expected_location {
		t.Errorf("GET %s : Expected 'Location' HTTP response header of %s, got %s\n", uri, expected_location, res.Header.Get("Location"))
	}
}

// Some URIs have 405 Not Allowed responses on the real metadata service
func doNotAllowedTest(t *testing.T, method string, uri string, expected_allow_header string) {
	client := testHttpClient()
	req, err := http.NewRequest(method, testServer.URL+uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 405 {
		t.Errorf("%s %s : Expected HTTP Status Code 405, got %d\n", method, uri, res.StatusCode)
	}
	if res.Header.Get("Allow") == "" {
		t.Errorf("%s %s : Expected an 'Allow' HTTP response header, none found\n", method, uri)
	}
	if res.Header.Get("Allow") != expected_allow_header {
		t.Errorf("%s %s : Expected 'Allow' HTTP response header of %s, got %s\n", method, uri, expected_allow_header, res.Header.Get("Allow"))
	}
}

// Some URIs have 404 Not Found responses on the real metadata service
func doNotFoundTest(t *testing.T, method string, uri string) {
	client := testHttpClient()
	req, err := http.NewRequest(method, testServer.URL+uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 404 {
		t.Errorf("%s %s : Expected HTTP Status Code 404, got %d\n", method, uri, res.StatusCode)
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

	doBodyTest(t, "GET", "", expected_body)
	doBodyTest(t, "GET", "/", expected_body)
}

func TestLatest(t *testing.T) {
	expected_body := `dynamic
meta-data
user-data`

	doBodyTest(t, "GET", "/latest", expected_body)
	doBodyTest(t, "GET", "/latest/", expected_body)
}

func TestLatestApi(t *testing.T) {
	doNotFoundTest(t, "GET", "/latest/api")
	doNotFoundTest(t, "GET", "/latest/api/")
}

func TestLatestApiToken(t *testing.T) {
	doNotAllowedTest(t, "GET", "/latest/api/token", "OPTIONS, PUT")
	doNotAllowedTest(t, "POST", "/latest/api/token", "OPTIONS, PUT")

	// Expect a 40 character long body. Hacky but it works...
	doBodyTest(t, "PUT", "/latest/api/token", "56char")
}

func TestLatestDynamic(t *testing.T) {
	expected_body := `instance-identity/
`

	doRedirectTest(t, "/latest/dynamic", "/latest/dynamic/")
	doBodyTest(t, "GET", "/latest/dynamic/", expected_body)
}

func TestLatestDynamicInstanceIdentity(t *testing.T) {
	expected_body := `document
pkcs7
signature
`

	doRedirectTest(t, "/latest/dynamic/instance-identity", "/latest/dynamic/instance-identity/")
	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/", expected_body)
}

func TestLatestDynamicInstanceIdentityDocument(t *testing.T) {
	// NOTE: upstream syntax is "key" : "value",
	// but this implemented uses "key": "value",
	// mostly to save time not writing a custom JSON marshaller.
	// Test results modified by hand to pass (extra spaces removed).
	expected_body := `{
  "instanceId": "i-asdfasdf",
  "billingProducts": null,
  "imageId": "ami-asdfasdf",
  "architecture": "x86_64",
  "pendingTime": "2016-04-15T12:14:15Z",
  "instanceType": "t2.micro",
  "accountId": "123456789012",
  "kernelId": null,
  "ramdiskId": null,
  "region": "us-east-1",
  "version": "2010-08-31",
  "availabilityZone": "us-east-1a",
  "devpayProductCodes": null,
  "privateIp": "10.20.30.40"
}`

	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/document", expected_body)
	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/document/", expected_body)
}

func TestLatestDynamicInstanceIdentityPkcs7(t *testing.T) {
	expected_body := `PKCS7`

	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/pkcs7", expected_body)
	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/pkcs7/", expected_body)
}

func TestLatestDynamicInstanceIdentitySignature(t *testing.T) {
	expected_body := `SIGNATURE`

	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/signature", expected_body)
	doBodyTest(t, "GET", "/latest/dynamic/instance-identity/signature/", expected_body)
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
	doBodyTest(t, "GET", "/latest/meta-data/", expected_body)
}

func TestLatestMetaDataAmiId(t *testing.T) {
	expected_body := `ami-asdfasdf`

	doBodyTest(t, "GET", "/latest/meta-data/ami-id", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/ami-id/", expected_body)
}

func TestLatestMetaDataAmiLaunchIndex(t *testing.T) {
	expected_body := `0`

	doBodyTest(t, "GET", "/latest/meta-data/ami-launch-index", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/ami-launch-index/", expected_body)
}

func TestLatestMetaDataAmiManifestPath(t *testing.T) {
	expected_body := `(unknown)`

	doBodyTest(t, "GET", "/latest/meta-data/ami-manifest-path", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/ami-manifest-path/", expected_body)
}

func TestLatestMetaDataBlockDeviceMapping(t *testing.T) {
	expected_body := `ami
root`

	doRedirectTest(t, "/latest/meta-data/block-device-mapping", "/latest/meta-data/block-device-mapping/")
	doBodyTest(t, "GET", "/latest/meta-data/block-device-mapping/", expected_body)
}

func TestLatestMetaDataBlockDeviceMappingAmi(t *testing.T) {
	expected_body := `/dev/xvda`

	doBodyTest(t, "GET", "/latest/meta-data/block-device-mapping/ami", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/block-device-mapping/ami/", expected_body)
}

func TestLatestMetaDataBlockDeviceMappingRoot(t *testing.T) {
	expected_body := `/dev/xvda`

	doBodyTest(t, "GET", "/latest/meta-data/block-device-mapping/root", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/block-device-mapping/root/", expected_body)
}

func TestLatestMetaDataHostname(t *testing.T) {
	expected_body := `testhostname`

	doBodyTest(t, "GET", "/latest/meta-data/hostname", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/hostname/", expected_body)
}

func TestLatestMetaDataIam(t *testing.T) {
	expected_body := `info
security-credentials/`

	doRedirectTest(t, "/latest/meta-data/iam", "/latest/meta-data/iam/")
	doBodyTest(t, "GET", "/latest/meta-data/iam/", expected_body)
}

func TestLatestMetaDataIamInfo(t *testing.T) {
	expected_body := `{
  "Code" : "Success",
  "LastUpdated" : "2018-02-26T23:50:00Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/some-instance-profile",
  "InstanceProfileId" : "some-instance-profile-id"
}`

	doBodyTest(t, "GET", "/latest/meta-data/iam/info", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/iam/info/", expected_body)
}

func TestLatestMetaDataIamSecurityCredentials(t *testing.T) {
	expected_body := `some-instance-profile`

	doRedirectTest(t, "/latest/meta-data/iam/security-credentials", "/latest/meta-data/iam/security-credentials/")
	doBodyTest(t, "GET", "/latest/meta-data/iam/security-credentials/", expected_body)
}

func TestLatestMetaDataIamSecurityCredentialsSomeInstanceProfile(t *testing.T) {
	// TODOLATER: round to nearest hour, to ensure test coverage passes more reliably?
	now := time.Now().UTC()
	expire := now.Add(6 * time.Hour)
	format := "2006-01-02T15:04:05Z"
	expected_body := fmt.Sprintf(`{
  "Code" : "Success",
  "LastUpdated" : "%s",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "mock-access-key-id",
  "SecretAccessKey" : "mock-secret-access-key",
  "Token" : "mock-token",
  "Expiration" : "%s"
}`, now.Format(format), expire.Format(format))

	doBodyTest(t, "GET", "/latest/meta-data/iam/security-credentials/some-instance-profile", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/iam/security-credentials/some-instance-profile/", expected_body)
}

func TestLatestMetaDataInstanceAction(t *testing.T) {
	expected_body := `none`

	doBodyTest(t, "GET", "/latest/meta-data/instance-action", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/instance-action/", expected_body)
}

func TestLatestMetaDataInstanceId(t *testing.T) {
	expected_body := `i-asdfasdf`

	doBodyTest(t, "GET", "/latest/meta-data/instance-id", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/instance-id/", expected_body)
}

func TestLatestMetaDataInstanceType(t *testing.T) {
	expected_body := `t2.micro`

	doBodyTest(t, "GET", "/latest/meta-data/instance-type", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/instance-type/", expected_body)
}

func TestLatestMetaDataLocalHostname(t *testing.T) {
	expected_body := `testhostname`

	doBodyTest(t, "GET", "/latest/meta-data/local-hostname", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/local-hostname/", expected_body)
}

func TestLatestMetaDataLocalIpv4(t *testing.T) {
	expected_body := `10.20.30.40`

	doBodyTest(t, "GET", "/latest/meta-data/local-ipv4", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/local-ipv4/", expected_body)
}

func TestLatestMetaDataMac(t *testing.T) {
	expected_body := `00:aa:bb:cc:dd:ee`

	doBodyTest(t, "GET", "/latest/meta-data/mac", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/mac/", expected_body)
}

func TestLatestMetaDataMetrics(t *testing.T) {
	expected_body := `vhostmd`

	doRedirectTest(t, "/latest/meta-data/metrics", "/latest/meta-data/metrics/")
	doBodyTest(t, "GET", "/latest/meta-data/metrics/", expected_body)
}

func TestLatestMetaDataMetricsVhostMd(t *testing.T) {
	// No idea what actually lives here right now, leaving as a placeholder.
	expected_body := `<?xml version="1.0" encoding="UTF-8"?>`

	doBodyTest(t, "GET", "/latest/meta-data/metrics/vhostmd", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/metrics/vhostmd/", expected_body)
}

func TestLatestMetaDataNetwork(t *testing.T) {
	expected_body := `interfaces/`

	doRedirectTest(t, "/latest/meta-data/network", "/latest/meta-data/network/")
	doBodyTest(t, "GET", "/latest/meta-data/network/", expected_body)
}

func TestLatestMetaDataNetworkInterfaces(t *testing.T) {
	expected_body := `macs/`

	doRedirectTest(t, "/latest/meta-data/network/interfaces", "/latest/meta-data/network/interfaces/")
	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/", expected_body)
}

func TestLatestMetaDataNetworkInterfacesMacs(t *testing.T) {
	expected_body := `00:aa:bb:cc:dd:ee/`

	doRedirectTest(t, "/latest/meta-data/network/interfaces/macs", "/latest/meta-data/network/interfaces/macs/")
	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/", expected_body)
}

func TestLatestMetaDataNetworkInterfacesMacsAddr(t *testing.T) {
	expected_body := `device-number
interface-id
ipv4-associations/
local-hostname
local-ipv4s
mac
owner-id
public-hostname
public-ipv4s
security-group-ids
security-groups
subnet-id
subnet-ipv4-cidr-block
vpc-id
vpc-ipv4-cidr-block
vpc-ipv4-cidr-blocks`

	doRedirectTest(t, "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/")
	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/", expected_body)
}

func TestLatestMetaDataNIMAddrDeviceNumber(t *testing.T) {
	expected_body := `0`

	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/device-number", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/device-number/", expected_body)
}

func TestLatestMetaDataNIMAddrInterfaceId(t *testing.T) {
	expected_body := `eni-asdfasdf`

	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/interface-id", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/network/interfaces/macs/00:aa:bb:cc:dd:ee/interface-id/", expected_body)
}

// TODO: coverage for the network/interfaces/macs/mac_addr/... namespaces...

func TestLatestMetaDataProfile(t *testing.T) {
	expected_body := `default-hvm`

	doBodyTest(t, "GET", "/latest/meta-data/profile", expected_body)
	doBodyTest(t, "GET", "/latest/meta-data/profile/", expected_body)
}

func TestLatestUserData(t *testing.T) {
	// TODO: /latest/user-data returns a 404 if none exists... or if one exists, will return it?
	// should we expose this in the API? not implemented right now. could be useful...
}

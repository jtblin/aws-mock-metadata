package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/mux"
)

// StartServer starts a newly created http server
func (app *App) StartServer() {
	log.Infof("Listening on port %s:%s", app.AppInterface, app.AppPort)
	if err := http.ListenAndServe(app.AppInterface+":"+app.AppPort, app.NewServer()); err != nil {
		log.Fatalf("Error creating http server: %+v", err)
	}
}

func (app *App) apiVersionPrefixes() []string {
	return []string{"1.0",
		"2007-01-19",
		"2007-03-01",
		"2007-08-29",
		"2007-10-10",
		"2007-12-15",
		"2008-02-01",
		"2008-09-01",
		"2009-04-04",
		"2011-01-01",
		"2011-05-01",
		"2012-01-12",
		"2014-02-25",
		"2014-11-05",
		"2015-10-20",
		"2016-04-19",
		"2016-06-30",
		"2016-09-02",
		"latest",
	}
}

// NewServer creates a new http server (starting handled separately to allow test suites to reuse)
func (app *App) NewServer() *mux.Router {
	r := mux.NewRouter()
	r.Handle("", appHandler(app.rootHandler))
	r.Handle("/", appHandler(app.rootHandler))

	for _, v := range app.apiVersionPrefixes() {
		app.versionSubRouter(r.PathPrefix(fmt.Sprintf("/%s", v)).Subrouter(), v)
	}

	r.Handle("/{path:.*}", appHandler(app.notFoundHandler))

	return r
}

// Provides the versioned (normally 1.0, YYYY-MM-DD or latest) prefix routes
// TODO: conditional out the namespaces that don't exist on selected API versions
func (app *App) versionSubRouter(sr *mux.Router, version string) {
	//sr.Handle("", appHandler(app.trailingSlashRedirect))
	sr.Handle("", appHandler(app.secondLevelHandler))
	sr.Handle("/", appHandler(app.secondLevelHandler))

	// For IMDSv2, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
	a := sr.PathPrefix("/api").Subrouter()
	a.Handle("", appHandler(app.notFoundHandler))
	a.Handle("/", appHandler(app.notFoundHandler))
	a.Handle("/token", appHandler(app.apiTokenHandler)).Methods("PUT")
	// TODO: return 405 for everything but PUT
	/*
		HTTP/1.1 405 Not Allowed
		Allow: OPTIONS, PUT
		Content-Length: 0
		Date: Tue, 07 Apr 2020 03:56:56 GMT
		Server: EC2ws
		Connection: close
		Content-Type: text/plain
	*/
	a.Handle("/token", appHandler(app.apiTokenNotPutHandler)).Methods("GET", "POST", "DELETE")

	d := sr.PathPrefix("/dynamic").Subrouter()
	d.Handle("", appHandler(app.trailingSlashRedirect))
	d.Handle("/", appHandler(app.dynamicHandler))

	ii := d.PathPrefix("/instance-identity").Subrouter()
	ii.Handle("", appHandler(app.trailingSlashRedirect))
	ii.Handle("/", appHandler(app.instanceIdentityHandler))
	ii.Handle("/document", appHandler(app.instanceIdentityDocumentHandler))
	ii.Handle("/document/", appHandler(app.instanceIdentityDocumentHandler))
	ii.Handle("/pkcs7", appHandler(app.instanceIdentityPkcs7Handler))
	ii.Handle("/pkcs7/", appHandler(app.instanceIdentityPkcs7Handler))
	ii.Handle("/signature", appHandler(app.instanceIdentitySignatureHandler))
	ii.Handle("/signature/", appHandler(app.instanceIdentitySignatureHandler))

	m := sr.PathPrefix("/meta-data").Subrouter()
	m.Handle("", appHandler(app.trailingSlashRedirect))
	m.Handle("/", appHandler(app.metaDataHandler))
	m.Handle("/ami-id", appHandler(app.amiIdHandler))
	m.Handle("/ami-id/", appHandler(app.amiIdHandler))
	m.Handle("/ami-launch-index", appHandler(app.amiLaunchIndexHandler))
	m.Handle("/ami-launch-index/", appHandler(app.amiLaunchIndexHandler))
	m.Handle("/ami-manifest-path", appHandler(app.amiManifestPathHandler))
	m.Handle("/ami-manifest-path/", appHandler(app.amiManifestPathHandler))

	bdm := m.PathPrefix("/block-device-mapping").Subrouter()
	bdm.Handle("", appHandler(app.trailingSlashRedirect))
	bdm.Handle("/", appHandler(app.blockDeviceMappingHandler))
	bdm.Handle("/ami", appHandler(app.blockDeviceMappingAmiHandler))
	bdm.Handle("/ami/", appHandler(app.blockDeviceMappingAmiHandler))
	bdm.Handle("/root", appHandler(app.blockDeviceMappingRootHandler))
	bdm.Handle("/root/", appHandler(app.blockDeviceMappingRootHandler))

	m.Handle("/hostname", appHandler(app.hostnameHandler))
	m.Handle("/hostname/", appHandler(app.hostnameHandler))

	i := m.PathPrefix("/iam").Subrouter()
	i.Handle("", appHandler(app.trailingSlashRedirect))
	i.Handle("/", appHandler(app.iamHandler))
	i.Handle("/info", appHandler(app.infoHandler))
	i.Handle("/info/", appHandler(app.infoHandler))
	isc := i.PathPrefix("/security-credentials").Subrouter()
	isc.Handle("", appHandler(app.trailingSlashRedirect))
	isc.Handle("/", appHandler(app.securityCredentialsHandler))
	if app.MockInstanceProfile == true {
		isc.Handle("/"+app.RoleName, appHandler(app.mockRoleHandler))
		isc.Handle("/"+app.RoleName+"/", appHandler(app.mockRoleHandler))
	} else {
		isc.Handle("/"+app.RoleName, appHandler(app.roleHandler))
		isc.Handle("/"+app.RoleName+"/", appHandler(app.roleHandler))
	}

	m.Handle("/instance-action", appHandler(app.instanceActionHandler))
	m.Handle("/instance-action/", appHandler(app.instanceActionHandler))
	m.Handle("/instance-id", appHandler(app.instanceIDHandler))
	m.Handle("/instance-id/", appHandler(app.instanceIDHandler))
	m.Handle("/instance-type", appHandler(app.instanceTypeHandler))
	m.Handle("/instance-type/", appHandler(app.instanceTypeHandler))
	m.Handle("/local-hostname", appHandler(app.localHostnameHandler))
	m.Handle("/local-hostname/", appHandler(app.localHostnameHandler))
	m.Handle("/local-ipv4", appHandler(app.privateIpHandler))
	m.Handle("/local-ipv4/", appHandler(app.privateIpHandler))
	m.Handle("/mac", appHandler(app.macHandler))
	m.Handle("/mac/", appHandler(app.macHandler))

	me := m.PathPrefix("/metrics").Subrouter()
	me.Handle("", appHandler(app.trailingSlashRedirect))
	me.Handle("/", appHandler(app.metricsHandler))
	me.Handle("/vhostmd", appHandler(app.metricsVhostmdHandler))
	me.Handle("/vhostmd/", appHandler(app.metricsVhostmdHandler))

	n := m.PathPrefix("/network").Subrouter()
	n.Handle("", appHandler(app.trailingSlashRedirect))
	n.Handle("/", appHandler(app.networkHandler))
	ni := n.PathPrefix("/interfaces").Subrouter()
	ni.Handle("", appHandler(app.trailingSlashRedirect))
	ni.Handle("/", appHandler(app.networkInterfacesHandler))
	nim := ni.PathPrefix("/macs").Subrouter()
	nim.Handle("", appHandler(app.trailingSlashRedirect))
	nim.Handle("/", appHandler(app.networkInterfacesMacsHandler))
	nimaddr := nim.PathPrefix("/" + app.MacAddress).Subrouter()
	nimaddr.Handle("", appHandler(app.trailingSlashRedirect))
	nimaddr.Handle("/", appHandler(app.networkInterfacesMacsAddrHandler))
	nimaddr.Handle("/device-number", appHandler(app.nimAddrDeviceNumberHandler))
	nimaddr.Handle("/device-number/", appHandler(app.nimAddrDeviceNumberHandler))
	nimaddr.Handle("/interface-id", appHandler(app.nimAddrInterfaceIdHandler))
	nimaddr.Handle("/interface-id/", appHandler(app.nimAddrInterfaceIdHandler))
	// TODO: expand API coverage
	nimaddr.Handle("/vpc-id", appHandler(app.vpcHandler))

	p := m.PathPrefix("/placement").Subrouter()
	p.Handle("/availability-zone", appHandler(app.availabilityZoneHandler))
	p.Handle("/region", appHandler(app.regionHandler))

	m.Handle("/profile", appHandler(app.profileHandler))
	m.Handle("/profile/", appHandler(app.profileHandler))
	m.Handle("/public-hostname", appHandler(app.hostnameHandler))
	m.Handle("/public-hostname/", appHandler(app.hostnameHandler))

	sr.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	a.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	d.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	ii.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	m.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	bdm.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	i.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	isc.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	me.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	n.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	ni.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	nim.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	nimaddr.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	p.Handle("/{path:.*}", appHandler(app.notFoundHandler))
}

type appHandler func(http.ResponseWriter, *http.Request)

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("Requesting %s", r.RequestURI)
	w.Header().Set("Server", "EC2ws")
	fn(w, r)
}

func (app *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	write(w, strings.Join(app.apiVersionPrefixes(), "\n"))
}

func (app *App) trailingSlashRedirect(w http.ResponseWriter, r *http.Request) {
	location := ""
	if app.NoSchemeHostRedirects == false {
		location = "http://169.254.169.254"
	}
	location = fmt.Sprintf("%s%s/", location, r.URL.String())
	w.Header().Set("Location", location)
	w.WriteHeader(301)
}

func (app *App) secondLevelHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `dynamic
meta-data
user-data`)
}

func (app *App) dynamicHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `instance-identity/
`)
}

func (app *App) apiTokenNotPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "OPTIONS, PUT")
	w.WriteHeader(405)
}

// NOTE: no API methods actually check the X-aws-ec2-metadata-token request header right now...
func (app *App) apiTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Check for X-aws-ec2-metadata-token-ttl-seconds request header
	if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
		// Not set, 400 Bad Request
		w.WriteHeader(400)
	}

	// Check X-aws-ec2-metadata-token-ttl-seconds is an integer
	seconds_int, err := strconv.Atoi(r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
	if err != nil {
		log.Errorf("apiTokenHandler: Error converting X-aws-ec2-metadata-token-ttl-seconds to integer: %+v", err)
		w.WriteHeader(400)
	}

	// Generate a token, 40 character string, base64 encoded
	token := base64.StdEncoding.EncodeToString([]byte(RandStringBytesMaskImprSrc(40)))

	w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", strconv.Itoa(seconds_int))
	write(w, token)
}

func (app *App) instanceIdentityHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `document
pkcs7
signature
`)
}

type InstanceIdentityDocument struct {
	InstanceId         string  `json:"instanceId"`
	BillingProducts    *string `json:"billingProducts"`
	ImageId            string  `json:"imageId"`
	Architecture       string  `json:"architecture"`
	PendingTime        string  `json:"pendingTime"`
	InstanceType       string  `json:"instanceType"`
	AccountId          string  `json:"accountId"`
	KernelId           *string `json:"kernelId"`
	RamdiskId          *string `json:"ramdiskId"`
	Region             string  `json:"region"`
	Version            string  `json:"version"`
	AvailabilityZone   string  `json:"availabilityZone"`
	DevpayProductCodes *string `json:"devpayProductCodes"`
	PrivateIp          string  `json:"privateIp"`
}

func (app *App) instanceIdentityDocumentHandler(w http.ResponseWriter, r *http.Request) {
	document := InstanceIdentityDocument{
		AvailabilityZone:   app.AvailabilityZone,
		Region:             app.AvailabilityZone[:len(app.AvailabilityZone)-1],
		DevpayProductCodes: nil,
		PrivateIp:          app.PrivateIp,
		Version:            "2010-08-31",
		InstanceId:         app.InstanceID,
		BillingProducts:    nil,
		InstanceType:       app.InstanceType,
		AccountId:          app.AccountID,
		ImageId:            app.AmiID,
		PendingTime:        "2016-04-15T12:14:15Z",
		Architecture:       "x86_64",
		KernelId:           nil,
		RamdiskId:          nil,
	}
	result, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		log.Errorf("Error marshalling json %+v", err)
		http.Error(w, err.Error(), 500)
	}
	write(w, string(result))
}

// We cannot impersonate AWS and generate matching signatures here.
// Just return placeholder data instead.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
func (app *App) instanceIdentityPkcs7Handler(w http.ResponseWriter, r *http.Request) {
	write(w, `PKCS7`)
}

// We cannot impersonate AWS and generate matching signatures here.
// Just return placeholder data instead.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
func (app *App) instanceIdentitySignatureHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `SIGNATURE`)
}

func (app *App) metaDataHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: if IAM Role/Instance Profile is disabled, don't add iam/ to the list (same behavior as real metadata service)
	write(w, `ami-id
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
services/`)
}

func (app *App) amiIdHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.AmiID)
}

func (app *App) amiLaunchIndexHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "0")
}

func (app *App) amiManifestPathHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "(unknown)")
}

func (app *App) blockDeviceMappingHandler(w http.ResponseWriter, r *http.Request) {
	// Not exposing any extra volumes for now, this is pretty standard for an EBS backed EC2 instance.
	write(w, `ami
root`)
}

func (app *App) blockDeviceMappingAmiHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "/dev/xvda")
}

func (app *App) blockDeviceMappingRootHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "/dev/xvda")
}

func (app *App) hostnameHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.Hostname)
}

func (app *App) iamHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `info
security-credentials/`)
}

func (app *App) infoHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `{
  "Code" : "Success",
  "LastUpdated" : "2018-02-26T23:50:00Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/some-instance-profile",
  "InstanceProfileId" : "some-instance-profile-id"
}`)
}

func (app *App) instanceActionHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `none`)
}

func (app *App) instanceIDHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.InstanceID)
}

func (app *App) instanceTypeHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.InstanceType)
}

func (app *App) localHostnameHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.Hostname)
}

func (app *App) privateIpHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.PrivateIp)
}

func (app *App) macHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.MacAddress)
}

func (app *App) metricsHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `vhostmd`)
}

func (app *App) metricsVhostmdHandler(w http.ResponseWriter, r *http.Request) {
	// No idea what actually lives here right now, leaving as a placeholder.
	write(w, `<?xml version="1.0" encoding="UTF-8"?>`)
}

func (app *App) networkHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `interfaces/`)
}

func (app *App) networkInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `macs/`)
}

func (app *App) availabilityZoneHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.AvailabilityZone)
}

func (app *App) regionHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.AvailabilityZone[:len(app.AvailabilityZone)-1])
}

func (app *App) securityCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.RoleName)
}

func (app *App) networkInterfacesMacsHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.MacAddress+"/")
}

func (app *App) networkInterfacesMacsAddrHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `device-number
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
vpc-ipv4-cidr-blocks`)
}

func (app *App) nimAddrDeviceNumberHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `0`)
}

func (app *App) nimAddrInterfaceIdHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `eni-asdfasdf`)
}

func (app *App) profileHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `default-hvm`)
}

func (app *App) vpcHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.VpcID)
}

// Credentials represent the security credentials response
type Credentials struct {
	Code            string
	LastUpdated     string
	Type            string
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	Token           string
	Expiration      string
}

func (app *App) mockRoleHandler(w http.ResponseWriter, r *http.Request) {
	// TODOLATER: round to nearest hour, to ensure test coverage passes more reliably?
	now := time.Now().UTC()
	expire := now.Add(6 * time.Hour)
	format := "2006-01-02T15:04:05Z"
	write(w, fmt.Sprintf(`{
  "Code" : "Success",
  "LastUpdated" : "%s",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "mock-access-key-id",
  "SecretAccessKey" : "mock-secret-access-key",
  "Token" : "mock-token",
  "Expiration" : "%s"
}`, now.Format(format), expire.Format(format)))
}

func (app *App) roleHandler(w http.ResponseWriter, r *http.Request) {
	svc := sts.New(session.New(), &aws.Config{LogLevel: aws.LogLevel(2)})
	resp, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(app.RoleArn),
		RoleSessionName: aws.String("aws-mock-metadata"),
	})
	if err != nil {
		log.Errorf("Error assuming role %+v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	log.Debugf("STS response %+v", resp)
	credentials := Credentials{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		Code:            "Success",
		Expiration:      resp.Credentials.Expiration.Format("2006-01-02T15:04:05Z"),
		LastUpdated:     time.Now().Format("2006-01-02T15:04:05Z"),
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		Token:           *resp.Credentials.SessionToken,
		Type:            "AWS-HMAC",
	}
	if err := json.NewEncoder(w).Encode(credentials); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), 500)
	}
}

func (app *App) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	w.WriteHeader(404)
	write(w, `<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>404 - Not Found</title>
</head>
<body>
<h1>404 - Not Found</h1>
</body>
</html>`)
	log.Errorf("Not found " + path)
}

func write(w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		log.Errorf("Error writing response: %+v", err)
	}
}

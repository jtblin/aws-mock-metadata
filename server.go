package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	log.Infof("Listening on port %s", app.AppPort)
	if err := http.ListenAndServe(":"+app.AppPort, app.NewServer()); err != nil {
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
		d := r.PathPrefix(fmt.Sprintf("/%s", v)).Subrouter()
		app.versionSubRouter(d, v)
	}

	r.Handle("/{path:.*}", appHandler(app.notFoundHandler))

	return r
}

// Provides the versioned (normally 1.0, YYYY-MM-DD or latest) prefix routes
func (app *App) versionSubRouter(sr *mux.Router, version string) {
	sr.Handle("", appHandler(app.trailingSlashRedirect))
	sr.Handle("/", appHandler(app.secondLevelHandler))

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
	m.Handle("/instance-id", appHandler(app.instanceIDHandler))
	m.Handle("/instance-id/", appHandler(app.instanceIDHandler))
	m.Handle("/local-hostname", appHandler(app.localHostnameHandler))
	m.Handle("/local-hostname/", appHandler(app.localHostnameHandler))
	m.Handle("/local-ipv4", appHandler(app.privateIpHandler))
	m.Handle("/local-ipv4/", appHandler(app.privateIpHandler))

	p := m.PathPrefix("/placement").Subrouter()
	p.Handle("/availability-zone", appHandler(app.availabilityZoneHandler))

	i := m.PathPrefix("/iam").Subrouter()
	i.Handle("/security-credentials", appHandler(app.trailingSlashRedirect))
	i.Handle("/security-credentials/", appHandler(app.securityCredentialsHandler))
	i.Handle("/security-credentials/"+app.RoleName, appHandler(app.roleHandler))

	n := m.PathPrefix("/network/interfaces").Subrouter()
	n.Handle("/macs", appHandler(app.macHandler))
	n.Handle("/macs/"+app.Hostname+"/vpc-id", appHandler(app.vpcHandler))

	sr.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	d.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	ii.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	m.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	bdm.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	p.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	i.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	n.Handle("/{path:.*}", appHandler(app.notFoundHandler))
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

func (app *App) secondLevelHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `dynamic
meta-data
user-data`)
}

func (app *App) dynamicHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `instance-identity/
`)
}

func (app *App) instanceIdentityHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `document
pkcs7
signature
`)
}

// NOTE: order of keys here differs from real metadata service, in theory most (proper) JSON parsers should be fine with it though...
type InstanceIdentityDocument struct {
	AvailabilityZone   string  `json:"availabilityZone"`
	Region             string  `json:"region"`
	DevpayProductCodes *string `json:"devpayProductCodes"`
	PrivateIp          string  `json:"privateIp"`
	Version            string  `json:"version"`
	InstanceId         string  `json:"instanceId"`
	BillingProducts    *string `json:"billingProducts"`
	InstanceType       string  `json:"instanceType"`
	AccountId          string  `json:"accountId"`
	ImageId            string  `json:"imageId"`
	PendingTime        string  `json:"pendingTime"`
	Architecture       string  `json:"architecture"`
	KernelId           *string `json:"kernelId"`
	RamdiskId          *string `json:"ramdiskId"`
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
		InstanceType:       "t2.micro",
		AccountId:          "1234567890",
		ImageId:            app.AmiID,
		PendingTime:        "2016-04-15T12:14:15Z",
		Architecture:       "x86_64",
		KernelId:           nil,
		RamdiskId:          nil,
	}
	if err := json.NewEncoder(w).Encode(document); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), 500)
	}
}

func (app *App) instanceIdentityPkcs7Handler(w http.ResponseWriter, r *http.Request) {
	// TODO: adjust output to suit
	write(w, `
`)
}

func (app *App) instanceIdentitySignatureHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: adjust output to suit
	write(w, `
`)
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

func (app *App) instanceIDHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.InstanceID)
}

func (app *App) localHostnameHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.Hostname)
}

func (app *App) privateIpHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.PrivateIp)
}

func (app *App) availabilityZoneHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.AvailabilityZone)
}

func (app *App) securityCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.RoleName)
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

func (app *App) macHandler(w http.ResponseWriter, r *http.Request) {
	write(w, app.Hostname+"/")
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

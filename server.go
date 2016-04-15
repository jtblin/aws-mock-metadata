package main

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/mux"
)

// NewServer creates and starts a new http server
func (app *App) NewServer() {
	r := mux.NewRouter()
	r.Handle("/", appHandler(app.rootHandler))
	s := r.PathPrefix("/latest/meta-data").Subrouter()
	s.Handle("/instance-id", appHandler(app.instanceIDHandler))
	s.Handle("/local-hostname", appHandler(app.localHostnameHandler))
	s.Handle("/local-ipv4", appHandler(app.privateIpHandler))

	p := s.PathPrefix("/placement").Subrouter()
	p.Handle("/availability-zone", appHandler(app.availabilityZoneHandler))
	i := s.PathPrefix("/iam").Subrouter()
	i.Handle("/security-credentials", appHandler(app.trailingSlashRedirect))
	i.Handle("/security-credentials/", appHandler(app.securityCredentialsHandler))
	i.Handle("/security-credentials/"+app.RoleName, appHandler(app.roleHandler))

	n := s.PathPrefix("/network/interfaces").Subrouter()
	n.Handle("/macs", appHandler(app.macHandler))
	n.Handle("/macs/"+app.Hostname+"/vpc-id", appHandler(app.vpcHandler))

	d := r.PathPrefix("/latest/dynamic/instance-identity").Subrouter()
	d.Handle("/document", appHandler(app.instanceIdentityHandler))

	r.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	s.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	p.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	i.Handle("/{path:.*}", appHandler(app.notFoundHandler))
	n.Handle("/{path:.*}", appHandler(app.notFoundHandler))

	log.Infof("Listening on port %s", app.AppPort)
	if err := http.ListenAndServe(":"+app.AppPort, r); err != nil {
		log.Fatalf("Error creating http server: %+v", err)
	}
}

type appHandler func(http.ResponseWriter, *http.Request)

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("Requesting %s", r.RequestURI)
	fn(w, r)
}

func (app *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	write(w, `1.0
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
latest`)
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
	http.Redirect(w, r, r.URL.String()+"/", 301)
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

func (app *App) instanceIdentityHandler(w http.ResponseWriter, r *http.Request) {
	document := InstanceIdentityDocument{
		AvailabilityZone:   app.AvailabilityZone,
		Region:             app.AvailabilityZone[:len(app.AvailabilityZone)-1],
		DevpayProductCodes: nil,
		PrivateIp:          "127.0.0.1",
		Version:            "2010-08-31",
		InstanceId:         "i-wxyz1234",
		BillingProducts:    nil,
		InstanceType:       "t2.micro",
		AccountId:          "1234567890",
		ImageId:            "ami-123456",
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

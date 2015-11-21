package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/mux"
)

func main() {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	r := mux.NewRouter()
	r.Handle("/", appHandler(rootHandler))
	s := r.PathPrefix("/latest/meta-data").Subrouter()
	s.Handle("/instance-id", appHandler(instanceIDHandler))
	s.Handle("/local-hostname", appHandler(localHostnameHandler))
	p := s.PathPrefix("/placement").Subrouter()
	p.Handle("/availability-zone", appHandler(availabilityZoneHandler))
	i := s.PathPrefix("/iam").Subrouter()
	i.Handle("/security-credentials", appHandler(securityCredentialsHandler))
	i.Handle("/security-credentials/local", appHandler(roleHandler))

	r.Handle("/{path:.*}", appHandler(notFoundHandler))
	p.Handle("/{path:.*}", appHandler(notFoundHandler))
	i.Handle("/{path:.*}", appHandler(notFoundHandler))

	log.Infof("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Error creating http server: %+v", err)
	}
}

type appHandler func(http.ResponseWriter, *http.Request)

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("Requesting %s", r.RequestURI)
	fn(w, r)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
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

func instanceIDHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "i-efcbaf30")
}

func localHostnameHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "ip-10-116-44-6.ec2.compute.internal")
}

func availabilityZoneHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "ap-southeast-2b")
}

func securityCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	write(w, "local")
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

func roleHandler(w http.ResponseWriter, r *http.Request) {
	svc := sts.New(session.New(), &aws.Config{LogLevel: aws.LogLevel(2)})
	resp, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::123456789012:role/platform-dev-kubernetes-NodeIAMRole-1CBET3YCT9M74"),
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

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	w.WriteHeader(404)
	write(w, "Not found "+path)
	log.Errorf("Not found " + path)
}

func write(w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		log.Errorf("Error writing response: %+v", err)
	}
}

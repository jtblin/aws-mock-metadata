package main

import (
	"runtime"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/pflag"
)

// App encapsulates all of the parameters necessary for starting up
// an aws mock metadata server. These can either be set via command line or directly.
type App struct {
	AmiID                 string
	AvailabilityZone      string
	AppPort               string
	Hostname              string
	InstanceID            string
	PrivateIp             string
	RoleArn               string
	RoleName              string
	Verbose               bool
	VpcID                 string
	NoSchemeHostRedirects bool
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	app := &App{}
	app.addFlags(pflag.CommandLine)
	pflag.Parse()

	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	app.StartServer()
}

func (app *App) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&app.AmiID, "ami-id", app.AmiID, "EC2 Instance AMI ID")
	fs.StringVar(&app.AvailabilityZone, "availability-zone", app.AvailabilityZone, "Availability Zone")
	fs.StringVar(&app.AppPort, "app-port", app.AppPort, "HTTP Port")
	fs.StringVar(&app.Hostname, "hostname", app.Hostname, "EC2 Instance Hostname")
	fs.StringVar(&app.InstanceID, "instance-id", app.InstanceID, "EC2 instance id")
	fs.StringVar(&app.PrivateIp, "private-ip", app.PrivateIp, "Private IP")
	fs.StringVar(&app.RoleArn, "role-arn", app.RoleArn, "IAM Role ARN")
	fs.StringVar(&app.RoleName, "role-name", app.RoleName, "IAM Role Name")
	fs.BoolVar(&app.Verbose, "verbose", false, "Verbose")
	fs.StringVar(&app.VpcID, "vpc-id", app.VpcID, "VPC ID")
	fs.BoolVar(&app.NoSchemeHostRedirects, "no-scheme-host-redirects", app.NoSchemeHostRedirects, "Disable the scheme://host prefix in Location redirect headers")
}

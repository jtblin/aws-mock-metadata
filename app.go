package main

import (
	"runtime"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/pflag"
)

// App encapsulates all of the parameters necessary for starting up
// an aws mock metadata server. These can either be set via command line or directly.
type App struct {
	AvailabilityZone string
	AppPort          string
	Hostname         string
	InstanceID       string
	PrivateIp	     string
	RoleArn          string
	RoleName         string
	Verbose          bool
	VpcID	         string
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	app := &App{}
	app.addFlags(pflag.CommandLine)
	pflag.Parse()

	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	app.NewServer()
}

func (app *App) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&app.AvailabilityZone, "availability-zone", app.AvailabilityZone, "Availability zone")
	fs.StringVar(&app.AppPort, "app-port", app.AppPort, "Http port")
	fs.StringVar(&app.Hostname, "hostname", app.Hostname, "ec2 instance hostname")
	fs.StringVar(&app.InstanceID, "instance-id", app.InstanceID, "ec2 instance id")
	fs.StringVar(&app.PrivateIp, "private-ip", app.PrivateIp, "Private ip")
	fs.StringVar(&app.RoleArn, "role-arn", app.RoleArn, "IAM role Arn")
	fs.StringVar(&app.RoleName, "role-name", app.RoleName, "IAM role name")
	fs.BoolVar(&app.Verbose, "verbose", false, "Verbose")
	fs.StringVar(&app.VpcID, "vpc-id", app.VpcID, "VPC id")
}

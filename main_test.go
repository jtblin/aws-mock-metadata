package main

import (
	"net/http/httptest"
	"os"
	"testing"
)

// Not a fan of globals, but it's the only sane way to pass an httptest instance into each of the tests...
var (
	testServer *httptest.Server
)

func TestMain(m *testing.M) {
	// Setup the test API
	app := &App{}
	// Mock parameters
	app.AmiID = "ami-asdfasdf"
	app.AvailabilityZone = "us-east-1a"
	// AppPort not required
	app.Hostname = "testhostname"
	app.InstanceID = "i-asdfasdf"
	app.InstanceType = "t2.micro"
	app.MacAddress = "00:aa:bb:cc:dd:ee"
	app.MockInstanceProfile = true
	app.PrivateIp = "10.20.30.40"
	app.RoleName = "some-instance-profile"
	// No RoleArn or RoleName needed for current test coverage
	app.VpcID = "vpc-asdfasdf"
	testServer = httptest.NewServer(app.NewServer())
	defer testServer.Close()

	// Run the tests
	os.Exit(m.Run())
}

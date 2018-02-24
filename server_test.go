package main

import (
	"io/ioutil"
	"net/http"
	"testing"
)

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

	res, err := http.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expected_body {
		t.Errorf("Expected\n%s\ngot\n%s", expected_body, string(body))
	}
}

// TODO: iam/ subdirectory only appears in latest/ (and other date namespaces) if an IAM instance profile is attached, omitted otherwise. handle elegantly

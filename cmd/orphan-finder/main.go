package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

var (
	pemOrphan    = regexp.MustCompile(`pem=\[(.+)\]`)
	b64derOrphan = regexp.MustCompile(`b64der=\[(.+)\]`)
	regOrphan    = regexp.MustCompile(`regID=\[\d+\]`)
)

func parseLine(sa *rpc.StorageAuthorityClient, logger *blog.AuditLogger, line string) (found bool, added bool) {
	var der []byte
	regID := 0
	switch {
	case strings.Contains(line, "pem="):
		// Compatible with previous orphan logging format
		pemStr := pemOrphan.FindString(line)
		if pemStr == "" {
			logger.Err(fmt.Sprintf("pem variable is empty, [%s]", line))
			return true, false
		}
		pem, rest := pem.Decode([]byte(pemStr))
		if pem == nil {
			logger.Err(fmt.Sprintf("Couldn't decode PEM, [%s]", line))
			return true, false
		}
		if len(rest) > 0 {
			logger.Err(fmt.Sprintf("PEM block contains trailing garbage, [%s]", line))
			return true, false // fail out or carry on?
		}
		der = pem.Bytes
		regID = -99 // pre-regID logging format sentinel value
	case strings.Contains(line, "b64der="):
		derStr := b64derOrphan.FindString(line)
		if derStr == "" {
			logger.Err(fmt.Sprintf("b64der variable is empty, [%s]", line))
			return true, false
		}
		var err error
		der, err = base64.StdEncoding.DecodeString(derStr)
		if err != nil {
			logger.Err(fmt.Sprintf("Couldn't decode b64: %s, [%s]", err, line))
			return true, false
		}
		// extract the regID
		regStr := regOrphan.FindString(line)
		if regStr == "" {
			logger.Err(fmt.Sprintf("regID variable is empty, [%s]", line))
			return true, false
		}
		regID, err = strconv.Atoi(regStr)
		if err != nil {
			logger.Err(fmt.Sprintf("Couldn't parse regID: %s, [%s]", err, line))
			return true, false
		}
	default:
		return false, false
	}
	_, err := sa.AddCertificate(der, int64(regID))
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to store certificate: %s, [%s]", err, line))
		return true, false
	}
	return true, true
}

func main() {
	app := cli.NewApp()
	app.Name = "orphan-finder"
	app.Usage = "Reads orphaned certificates from a boulder-ca log and adds them to the database"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Boulder JSON configuration file",
		},
		cli.StringFlag{
			Name:  "log-file",
			Usage: "Path to boulder-ca log file",
		},
	}

	app.Action = func(c *cli.Context) {
		configJSON, err := ioutil.ReadFile(c.GlobalString("config"))
		cmd.FailOnError(err, "Failed to read config file")
		var config cmd.Config
		err = json.Unmarshal(configJSON, &config)
		cmd.FailOnError(err, "Failed to parse config file")

		logData, err := ioutil.ReadFile(c.GlobalString("log-file"))
		cmd.FailOnError(err, "Failed to read log file")

		stats, logger := cmd.StatsAndLogging(config.Statsd, config.Syslog)

		sa, err := rpc.NewStorageAuthorityClient("orphan-finder", config.OrphanFinder.AMQP, stats)
		cmd.FailOnError(err, "Failed to create SA client")

		orphansFound := int64(0)
		orphansAdded := int64(0)
		for _, line := range strings.Split(string(logData), "\n") {
			found, added := parseLine(sa, logger, line)
			if found {
				orphansFound++
				if added {
					orphansAdded++
				}
			}
		}
		logger.Info(fmt.Sprintf("Found %d orphans and added %d to the database\n", orphansFound, orphansAdded))
		stats.Inc("orphaned-certificates.found", orphansFound, 1.0)
		stats.Inc("orphaned-certificates.added", orphansAdded, 1.0)
		stats.Inc("orphaned-certificates.adding-failed", orphansFound-orphansAdded, 1.0)
	}

	app.Run(os.Args)
}

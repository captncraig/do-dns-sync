package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/providers/digitalocean"
	"github.com/miekg/dns/dnsutil"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/digitalocean/godo"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2"
)

var token = os.Getenv("DO_TOKEN")

type TokenSource struct {
	AccessToken string
}

func (t *TokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.AccessToken,
	}
	return token, nil
}

func runOnce() error {
	tokenSource := &TokenSource{
		AccessToken: token,
	}
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	client := godo.NewClient(oauthClient)

	drops, err := DropletList(client)
	if err != nil {
		return err
	}

	rules, err := LoadRules()
	if err != nil {
		return err
	}

	domains := map[string]*models.DomainConfig{}

	for _, drop := range drops {
		for _, rule := range rules {
			if rule.Label != "" {
				hasTag := false
				for _, t := range drop.Tags {
					if t == rule.Label {
						hasTag = true
						break
					}
				}
				if !hasTag {
					continue
				}
			}
			var matches []string
			if rule.Regex != nil {
				matches = rule.Regex.FindStringSubmatch(drop.Name)
				if len(matches) == 0 {
					continue
				}
			}
			rec := &models.RecordConfig{
				Type:     rule.Type,
				NameFQDN: replace(rule.FQDN, drop, matches),
				Target:   replace(rule.Target, drop, matches),
				TTL:      100,
			}
			sld, err := publicsuffix.EffectiveTLDPlusOne(rec.NameFQDN)
			if err != nil {
				return err
			}
			rec.Name = dnsutil.TrimDomainName(rec.NameFQDN, sld)
			if rule.Type == "SRV" {
				rec.SrvPort = uint16(rule.Port)
				rec.SrvWeight = 10
				rec.SrvPriority = 10
			}
			if domains[sld] == nil {
				domains[sld] = &models.DomainConfig{
					Name: sld,
				}
			}
			domains[sld].Records = append(domains[sld].Records, rec)
		}
	}
	provider, err := digitalocean.NewDo(map[string]string{"token": token}, nil)
	if err != nil {
		return err
	}
	for _, dc := range domains {
		fmt.Println("-----", dc.Name)
		corrs, err := provider.GetDomainCorrections(dc)
		if err != nil {
			return err
		}
		for _, c := range corrs {
			if strings.Contains(c.Msg, "DELETE NS") {
				continue
			}
			err = c.F()
			fmt.Println(c.Msg, err)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	if token == "" {
		log.Fatal("DO_TOKEN env var is required")
	}
	for {
		start := time.Now()
		err := runOnce()
		if err != nil {
			log.Printf("Error running dns sync: %s", err)
		}
		log.Printf("Synced records in %s", time.Now().Sub(start))
		time.Sleep(30 * time.Second)
	}
}

func replace(base string, drop godo.Droplet, matches []string) string {
	base = strings.Replace(base, "$DROP", drop.Name, -1)
	pub4, _ := drop.PublicIPv4()
	base = strings.Replace(base, "$PUB4", pub4, -1)
	pri4, _ := drop.PrivateIPv4()
	base = strings.Replace(base, "$PRI4", pri4, -1)
	pub6, _ := drop.PublicIPv6()
	base = strings.Replace(base, "$PUB6", pub6, -1)
	for i := 1; i < len(matches); i++ {
		base = strings.Replace(base, fmt.Sprintf("$%d", i), matches[i], -1)
	}
	return base
}

func DropletList(client *godo.Client) ([]godo.Droplet, error) {
	list := []godo.Droplet{}
	opt := &godo.ListOptions{}
	for {
		droplets, resp, err := client.Droplets.List(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		list = append(list, droplets...)
		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return list, nil
}

type NameRule struct {
	Type   string
	FQDN   string
	Target string
	Port   int
	Label  string
	Regex  *regexp.Regexp
}

func LoadRules() ([]*NameRule, error) {
	// TODO: test this harder
	dat, err := ioutil.ReadFile("names.cfg")
	if err != nil {
		return nil, err
	}
	rules := []*NameRule{}
	for _, line := range strings.Split(string(dat), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			return nil, fmt.Errorf("Each name rule needs at least '$TYPE $FQDN $TARGET")
		}
		rule := &NameRule{
			Type:   parts[0],
			FQDN:   parts[1],
			Target: parts[2],
		}
		parts = parts[3:]
		if rule.Type != "A" && rule.Type != "AAAA" && rule.Type != "SRV" {
			return nil, fmt.Errorf("Unknown rule record type '%s'", rule.Type)
		}
		if len(parts) == 0 && rule.Type == "SRV" {
			return nil, fmt.Errorf("SRV rule needs at least '$TYPE $FQDN $TARGET $PORT")
		}
		if rule.Type == "SRV" {
			rule.Port, err = strconv.Atoi(parts[0])
			if err != nil {
				return nil, err
			}
			parts = parts[1:]
		}
		if len(parts) > 1 {
			return nil, fmt.Errorf("Too many parts in rule")
		}
		if len(parts) == 1 {
			if label := strings.TrimSuffix(strings.TrimPrefix(parts[0], "["), "]"); label != parts[0] {
				rule.Label = label
			} else if rex := strings.Trim(parts[0], "`"); rex != parts[0] {
				rule.Regex, err = regexp.Compile(rex)
				if err != nil {
					return nil, err
				}
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

/*

A $DROP.ssdv.win $PUB4
A $DROP.pvt.ssdv.win $PRI4
AAAA $DROP.ssdv.win $PUB6
SRV _mysql._tcp.pvt.ssdv.win $DROP.pvt.ssdv.win. 9104 [mysql]
SRV _node._tcp.pvt.ssdv.win $DROP.pvt.ssdv.win. 9100
A *.$1.ssdv.win $PUB4 `[a-z][a-z]\-([a-z]+)\d\d`
# dc-service.ssdv.win only (essentially without number)
#A $1.ssdv.win $PUB4 `([a-z][a-z]\-[a-z]+)\d\d`
#A $1.pvt.ssdv.win $PRI4 `([a-z][a-z]\-[a-z]+)\d\d`
# service.ssdv.win (across all dcs)
#A $1.ssdv.win $PUB4 `[a-z][a-z]\-([a-z]+)\d\d`
#A $1.pvt.ssdv.win $PRI4 `[a-z][a-z]\-([a-z]+)\d\d`

*/

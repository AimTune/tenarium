package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// route53API is the subset of the Route 53 client the plugin uses; tests
// substitute a fake.
type route53API interface {
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListHostedZonesByName(context.Context, *route53.ListHostedZonesByNameInput, ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
	GetChange(context.Context, *route53.GetChangeInput, ...func(*route53.Options)) (*route53.GetChangeOutput, error)
}

type route53Backend struct {
	api  route53API
	zone string
	cfg  *Route53Config

	mu     sync.Mutex
	zoneID string
}

// newRoute53 builds the client. It does not contact AWS.
func newRoute53(ctx context.Context, zone string, c *Route53Config) (*route53Backend, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(c.Region)}
	if c.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	client := route53.NewFromConfig(awsCfg, func(o *route53.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	return &route53Backend{api: client, zone: zone, cfg: c, zoneID: c.HostedZoneID}, nil
}

// hostedZoneID returns the configured hosted zone ID or looks it up by name
// (once).
func (b *route53Backend) hostedZoneID(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.zoneID != "" {
		return b.zoneID, nil
	}
	out, err := b.api.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(b.zone + "."), MaxItems: aws.Int32(10),
	})
	if err != nil {
		return "", fmt.Errorf("look up hosted zone %s: %w", b.zone, err)
	}
	var ids []string
	for _, z := range out.HostedZones {
		if normalizeR53Name(aws.ToString(z.Name)) == b.zone {
			ids = append(ids, strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"))
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("hosted zone %s not found", b.zone)
	case 1:
		b.zoneID = ids[0]
		return b.zoneID, nil
	default:
		return "", fmt.Errorf("several hosted zones are named %s (%s); set route53.hosted_zone_id", b.zone, strings.Join(ids, ", "))
	}
}

// normalizeR53Name lowercases a Route 53 name, drops the trailing dot and
// decodes the "\052" escape Route 53 uses for "*".
func normalizeR53Name(s string) string {
	s = strings.ReplaceAll(s, `\052`, "*")
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

func (b *route53Backend) lookup(ctx context.Context, name string) (map[string]*rrset, error) {
	zid, err := b.hostedZoneID(ctx)
	if err != nil {
		return nil, err
	}
	sets := map[string]*rrset{}
	in := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zid), StartRecordName: aws.String(name + "."), MaxItems: aws.Int32(100),
	}
	for {
		out, err := b.api.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, rs := range out.ResourceRecordSets {
			if normalizeR53Name(aws.ToString(rs.Name)) != name {
				continue
			}
			typ := string(rs.Type)
			s := &rrset{Name: name, Type: typ, TTL: aws.ToInt64(rs.TTL), raw: rs}
			for _, r := range rs.ResourceRecords {
				s.Values = append(s.Values, decodeR53Value(typ, aws.ToString(r.Value)))
			}
			if rs.AliasTarget != nil || rs.SetIdentifier != nil {
				// Alias and routing-policy sets never match a plain set.
				s.Values = append(s.Values, "<alias or routing policy>")
			}
			if _, dup := sets[typ]; !dup {
				sets[typ] = s
			}
		}
		if !out.IsTruncated || normalizeR53Name(aws.ToString(out.NextRecordName)) != name {
			return sets, nil
		}
		in.StartRecordName = out.NextRecordName
		in.StartRecordType = out.NextRecordType
		in.StartRecordIdentifier = out.NextRecordIdentifier
	}
}

func decodeR53Value(typ, v string) string {
	switch typ {
	case TypeTXT:
		return txtDecode(v)
	case TypeCNAME:
		return strings.TrimSuffix(strings.ToLower(v), ".")
	case TypeA, TypeAAAA:
		if n, err := normalizeValue(typ, v); err == nil {
			return n
		}
	}
	return v
}

func toR53(s rrset) *types.ResourceRecordSet {
	rs := &types.ResourceRecordSet{Name: aws.String(s.Name + "."), Type: types.RRType(s.Type), TTL: aws.Int64(s.TTL)}
	for _, v := range s.Values {
		if s.Type == TypeTXT {
			v = txtEncode(v)
		}
		rs.ResourceRecords = append(rs.ResourceRecords, types.ResourceRecord{Value: aws.String(v)})
	}
	return rs
}

// apply submits markers and records in one atomic change batch: CREATE for
// new sets (so the batch fails if someone created one meanwhile) and UPSERT
// for existing ones.
func (b *route53Backend) apply(ctx context.Context, tenantID string, markers, records []change) error {
	var changes []types.Change
	for _, c := range append(append([]change(nil), markers...), records...) {
		switch {
		case c.have == nil:
			changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: toR53(c.want)})
		case !sameSet(c.want, c.have):
			changes = append(changes, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: toR53(c.want)})
		}
	}
	return b.submit(ctx, changes, "tenarium: provision tenant "+tenantID)
}

// remove deletes the sets with their exact current values in one batch.
func (b *route53Backend) remove(ctx context.Context, records, markers []*rrset) error {
	var changes []types.Change
	for _, s := range append(append([]*rrset(nil), records...), markers...) {
		rs, ok := s.raw.(types.ResourceRecordSet)
		if !ok {
			return fmt.Errorf("route53: no current state for %s %s", s.Type, s.Name)
		}
		changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &rs})
	}
	return b.submit(ctx, changes, "tenarium: deprovision")
}

func (b *route53Backend) submit(ctx context.Context, changes []types.Change, comment string) error {
	if len(changes) == 0 {
		return nil
	}
	zid, err := b.hostedZoneID(ctx)
	if err != nil {
		return err
	}
	out, err := b.api.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zid),
		ChangeBatch:  &types.ChangeBatch{Changes: changes, Comment: aws.String(comment)},
	})
	if err != nil {
		return fmt.Errorf("route53 change batch: %w", err)
	}
	if !b.cfg.Wait || out.ChangeInfo == nil || out.ChangeInfo.Status == types.ChangeStatusInsync {
		return nil
	}
	w := route53.NewResourceRecordSetsChangedWaiter(b.api, func(o *route53.ResourceRecordSetsChangedWaiterOptions) {
		o.MinDelay = 2 * time.Second
		o.MaxDelay = 30 * time.Second
	})
	if err := w.Wait(ctx, &route53.GetChangeInput{Id: out.ChangeInfo.Id}, b.cfg.waitTimeout); err != nil {
		return fmt.Errorf("route53 wait for change %s: %w", aws.ToString(out.ChangeInfo.Id), err)
	}
	return nil
}

func (b *route53Backend) health(ctx context.Context) error {
	zid, err := b.hostedZoneID(ctx)
	if err != nil {
		return err
	}
	out, err := b.api.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zid)})
	if err != nil {
		return err
	}
	if out.HostedZone == nil || normalizeR53Name(aws.ToString(out.HostedZone.Name)) != b.zone {
		return errors.New("route53: hosted zone " + zid + " is not zone " + b.zone)
	}
	return nil
}

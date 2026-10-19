package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// fakeDNS is the view tests have on a fake provider.
type fakeDNS interface {
	seed(name, typ string, values ...string)
	values(name, typ string) []string
	writes() int
}

// fakeRoute53 is an in-memory Route 53 with atomic change batches.
type fakeRoute53 struct {
	mu     sync.Mutex
	zoneID string
	zone   string // with trailing dot
	sets   map[string]types.ResourceRecordSet
	nwrite int
}

func newFakeRoute53() *fakeRoute53 {
	return &fakeRoute53{zoneID: "Z123", zone: "example.com.", sets: map[string]types.ResourceRecordSet{}}
}

func r53Key(name string, typ types.RRType) string {
	return normalizeR53Name(name) + "|" + string(typ)
}

// r53Name stores names as Route 53 reports them: trailing dot, "*" escaped.
func r53Name(name string) string {
	return strings.ReplaceAll(strings.TrimSuffix(strings.ToLower(name), ".")+".", "*", `\052`)
}

func (f *fakeRoute53) seed(name, typ string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := types.ResourceRecordSet{Name: aws.String(r53Name(name)), Type: types.RRType(typ), TTL: aws.Int64(60)}
	for _, v := range values {
		if typ == TypeTXT {
			v = txtEncode(v)
		}
		rs.ResourceRecords = append(rs.ResourceRecords, types.ResourceRecord{Value: aws.String(v)})
	}
	f.sets[r53Key(name, rs.Type)] = rs
}

func (f *fakeRoute53) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs, ok := f.sets[r53Key(name, types.RRType(typ))]
	if !ok {
		return nil
	}
	var out []string
	for _, r := range rs.ResourceRecords {
		out = append(out, decodeR53Value(typ, aws.ToString(r.Value)))
	}
	slices.Sort(out)
	return out
}

func (f *fakeRoute53) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nwrite
}

func (f *fakeRoute53) checkZone(id *string) error {
	if strings.TrimPrefix(aws.ToString(id), "/hostedzone/") != f.zoneID {
		return &types.NoSuchHostedZone{Message: aws.String("no such zone")}
	}
	return nil
}

func (f *fakeRoute53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkZone(in.HostedZoneId); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(f.sets))
	for k := range f.sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	start := normalizeR53Name(aws.ToString(in.StartRecordName)) + "|" + string(in.StartRecordType)
	limit := int(aws.ToInt32(in.MaxItems))
	if limit == 0 {
		limit = 100
	}
	// Keep pages tiny to exercise pagination.
	limit = min(limit, 2)
	out := &route53.ListResourceRecordSetsOutput{}
	for _, k := range keys {
		if k < start {
			continue
		}
		if len(out.ResourceRecordSets) == limit {
			out.IsTruncated = true
			out.NextRecordName = f.sets[k].Name
			out.NextRecordType = f.sets[k].Type
			break
		}
		out.ResourceRecordSets = append(out.ResourceRecordSets, f.sets[k])
	}
	return out, nil
}

func sameR53(a, b types.ResourceRecordSet) bool {
	if aws.ToInt64(a.TTL) != aws.ToInt64(b.TTL) || len(a.ResourceRecords) != len(b.ResourceRecords) {
		return false
	}
	for i := range a.ResourceRecords {
		if aws.ToString(a.ResourceRecords[i].Value) != aws.ToString(b.ResourceRecords[i].Value) {
			return false
		}
	}
	return true
}

func (f *fakeRoute53) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkZone(in.HostedZoneId); err != nil {
		return nil, err
	}
	next := map[string]types.ResourceRecordSet{}
	for k, v := range f.sets {
		next[k] = v
	}
	for _, c := range in.ChangeBatch.Changes {
		rs := *c.ResourceRecordSet
		rs.Name = aws.String(r53Name(aws.ToString(rs.Name)))
		k := r53Key(aws.ToString(rs.Name), rs.Type)
		cur, exists := next[k]
		switch c.Action {
		case types.ChangeActionCreate:
			if exists {
				return nil, &types.InvalidChangeBatch{Message: aws.String("Tried to create resource record set " + k + " but it already exists")}
			}
			next[k] = rs
		case types.ChangeActionUpsert:
			next[k] = rs
		case types.ChangeActionDelete:
			if !exists || !sameR53(cur, rs) {
				return nil, &types.InvalidChangeBatch{Message: aws.String("Tried to delete resource record set " + k + " but it was not found or values do not match")}
			}
			delete(next, k)
		}
		// A CNAME cannot coexist with other records.
		name := normalizeR53Name(aws.ToString(rs.Name))
		var typesAt []string
		for kk := range next {
			if n, t, _ := strings.Cut(kk, "|"); n == name {
				typesAt = append(typesAt, t)
			}
		}
		if len(typesAt) > 1 && slices.Contains(typesAt, TypeCNAME) {
			return nil, &types.InvalidChangeBatch{Message: aws.String("RRSet of type CNAME with DNS name " + name + " is not permitted as it conflicts with other records")}
		}
	}
	f.sets = next
	f.nwrite++
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/C" + strconv.Itoa(f.nwrite)), Status: types.ChangeStatusPending}}, nil
}

func (f *fakeRoute53) GetHostedZone(_ context.Context, in *route53.GetHostedZoneInput, _ ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	if err := f.checkZone(in.Id); err != nil {
		return nil, err
	}
	return &route53.GetHostedZoneOutput{HostedZone: &types.HostedZone{Id: aws.String("/hostedzone/" + f.zoneID), Name: aws.String(f.zone)}}, nil
}

func (f *fakeRoute53) ListHostedZonesByName(_ context.Context, in *route53.ListHostedZonesByNameInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	// Route 53 lists zones in order starting at DNSName, so a non-matching
	// zone can be returned too.
	return &route53.ListHostedZonesByNameOutput{HostedZones: []types.HostedZone{
		{Id: aws.String("/hostedzone/" + f.zoneID), Name: aws.String(f.zone)},
		{Id: aws.String("/hostedzone/ZOTHER"), Name: aws.String("example.net.")},
	}}, nil
}

func (f *fakeRoute53) GetChange(_ context.Context, in *route53.GetChangeInput, _ ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	return &route53.GetChangeOutput{ChangeInfo: &types.ChangeInfo{Id: in.Id, Status: types.ChangeStatusInsync}}, nil
}

// fakeCloudflare is an in-memory Cloudflare API v4.
type fakeCloudflare struct {
	mu      sync.Mutex
	srv     *httptest.Server
	token   string
	zoneID  string
	zone    string
	records map[string]cfRecord
	nextID  int
	nwrite  int
	// failPost makes record creation fail for this name.
	failPost string
}

func newFakeCloudflare(t *testing.T) *fakeCloudflare {
	f := &fakeCloudflare{token: "tok", zoneID: "zone1", zone: "example.com", records: map[string]cfRecord{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCloudflare) seed(name, typ string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range values {
		f.nextID++
		f.records[strconv.Itoa(f.nextID)] = cfRecord{ID: strconv.Itoa(f.nextID), Type: typ, Name: name, Content: encodeCFContent(typ, v), TTL: 60}
	}
}

func (f *fakeCloudflare) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		if r.Name == name && r.Type == typ {
			out = append(out, decodeCFContent(typ, r.Content))
		}
	}
	slices.Sort(out)
	return out
}

func (f *fakeCloudflare) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nwrite
}

func (f *fakeCloudflare) reply(w http.ResponseWriter, status int, result any, info any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{"success": status < 300, "errors": []any{}, "result": result}
	if info != nil {
		body["result_info"] = info
	}
	if status >= 300 {
		body["errors"] = []any{map[string]any{"code": status, "message": fmt.Sprint(result)}}
		body["result"] = nil
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCloudflare) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.reply(w, http.StatusForbidden, "Invalid API Token", nil)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "zones":
		var out []map[string]string
		if n := r.URL.Query().Get("name"); n == "" || n == f.zone {
			out = append(out, map[string]string{"id": f.zoneID, "name": f.zone})
		}
		f.reply(w, 200, out, nil)
	case len(parts) >= 2 && parts[0] == "zones" && parts[1] != f.zoneID:
		f.reply(w, http.StatusNotFound, "zone not found", nil)
	case r.Method == http.MethodGet && len(parts) == 2:
		f.reply(w, 200, map[string]string{"id": f.zoneID, "name": f.zone}, nil)
	case r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "dns_records":
		name := r.URL.Query().Get("name")
		var all []cfRecord
		for _, rec := range f.records {
			if name == "" || rec.Name == name {
				all = append(all, rec)
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		const per = 1 // tiny pages exercise pagination
		total := max((len(all)+per-1)/per, 1)
		from, to := min((page-1)*per, len(all)), min(page*per, len(all))
		f.reply(w, 200, all[from:to], map[string]int{"page": page, "total_pages": total})
	case r.Method == http.MethodPost && len(parts) == 3:
		var rec cfRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			f.reply(w, 400, err.Error(), nil)
			return
		}
		if f.failPost != "" && rec.Name == f.failPost {
			f.reply(w, 500, "injected failure", nil)
			return
		}
		for _, o := range f.records {
			if o.Name != rec.Name {
				continue
			}
			if o.Type == TypeCNAME || rec.Type == TypeCNAME {
				f.reply(w, 400, "A CNAME record with that host already exists", nil)
				return
			}
			if o.Type == rec.Type && o.Content == rec.Content {
				f.reply(w, 400, "An identical record already exists", nil)
				return
			}
		}
		if rec.TTL == 0 {
			rec.TTL = 1
		}
		f.nextID++
		rec.ID = strconv.Itoa(f.nextID)
		f.records[rec.ID] = rec
		f.nwrite++
		f.reply(w, 200, rec, nil)
	case r.Method == http.MethodPatch && len(parts) == 4:
		rec, ok := f.records[parts[3]]
		if !ok {
			f.reply(w, 404, "record not found", nil)
			return
		}
		var patch cfRecord
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			f.reply(w, 400, err.Error(), nil)
			return
		}
		if patch.TTL != 0 {
			rec.TTL = patch.TTL
		}
		if patch.Proxied != nil {
			rec.Proxied = patch.Proxied
		}
		rec.Comment = patch.Comment
		f.records[rec.ID] = rec
		f.nwrite++
		f.reply(w, 200, rec, nil)
	case r.Method == http.MethodDelete && len(parts) == 4:
		if _, ok := f.records[parts[3]]; !ok {
			f.reply(w, 404, "record not found", nil)
			return
		}
		delete(f.records, parts[3])
		f.nwrite++
		f.reply(w, 200, map[string]string{"id": parts[3]}, nil)
	default:
		f.reply(w, 404, "no route "+r.Method+" "+r.URL.Path, nil)
	}
}

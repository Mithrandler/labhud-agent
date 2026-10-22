package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// What the host verbs (target "images") do: `inventory` lists the host's images, volumes and
// networks with their sizes and what uses them (read only); `prune` removes the unused images
// (logs.go), `prune-dangling` the untagged layers, `prune-networks` the user-made networks no
// container is on, `prune-volumes` the anonymous volumes no container uses. A volume with a name
// holds someone's data on purpose: it is listed, never removed.
func (d *Docker) host(ctx context.Context, verb, target string) (string, error) {
	if target != PruneTarget {
		return "", fmt.Errorf("docker: %s takes %q", verb, PruneTarget)
	}
	switch verb {
	case "inventory":
		return d.inventory(ctx)
	case "prune":
		return d.prune(ctx, target)
	case "prune-dangling":
		return d.pruneDangling(ctx)
	case "prune-networks":
		return d.pruneNetworks(ctx)
	case "prune-volumes":
		return d.pruneVolumes(ctx)
	}
	return "", fmt.Errorf("docker: no read verb %q", verb)
}

// Inventory is `inventory`'s answer: the biggest first, at most inventoryMax of each, so that it
// stays under the 48 KiB an answer may have; `more` counts what was left out.
type Inventory struct {
	Images   []ImageInfo    `json:"images"`
	Volumes  []VolumeInfo   `json:"volumes"`
	Networks []NetworkInfo  `json:"networks"`
	More     map[string]int `json:"more,omitempty"`
}

type ImageInfo struct {
	ID       string   `json:"id"` // the first 12 characters, as `docker images` shows
	Tags     []string `json:"tags"`
	Size     int64    `json:"size"`
	Created  int64    `json:"created"`
	Used     int      `json:"used"` // containers (stopped ones too) made from it
	Dangling bool     `json:"dangling"`
	UsedBy   []string `json:"used_by,omitempty"` // their names, at most usedByMax
}

type VolumeInfo struct {
	Name      string   `json:"name"`
	Driver    string   `json:"driver"`
	Size      int64    `json:"size"` // -1: not known
	Used      int      `json:"used"`
	Anonymous bool     `json:"anonymous"` // 64 hex characters: made without a name; the only kind prune-volumes removes
	UsedBy    []string `json:"used_by,omitempty"`
}

type NetworkInfo struct {
	Name    string   `json:"name"`
	Driver  string   `json:"driver"`
	Scope   string   `json:"scope"`
	Used    int      `json:"used"` // containers on it
	Builtin bool     `json:"builtin"`
	UsedBy  []string `json:"used_by,omitempty"`
}

const (
	inventoryMax = 100
	usedByMax    = 8
)

var anonymousVolume = regexp.MustCompile(`^[0-9a-f]{64}$`)

func builtin(name string) bool { return name == "bridge" || name == "host" || name == "none" }

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

type df struct {
	Images []struct {
		ID         string `json:"Id"`
		RepoTags   []string
		Created    int64
		Size       int64
		Containers int64
	}
	Volumes []struct {
		Name, Driver string
		UsageData    *struct{ Size, RefCount int64 }
	}
}

func (d *Docker) usageOf(ctx context.Context) (df, error) {
	var out df
	return out, d.call(ctx, "GET", "/system/df", &out)
}

func (d *Docker) inventory(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	u, err := d.usageOf(ctx)
	if err != nil {
		return "", err
	}
	var nets []struct{ Name, Driver, Scope string }
	if err := d.call(ctx, "GET", "/networks", &nets); err != nil {
		return "", err
	}
	var boxes []struct {
		Names           []string
		ImageID         string
		Mounts          []struct{ Name string }
		NetworkSettings struct{ Networks map[string]any }
	}
	if err := d.call(ctx, "GET", "/containers/json?all=1", &boxes); err != nil {
		return "", err
	}
	onNet := map[string]int{}
	byNet, byImage, byVolume := map[string][]string{}, map[string][]string{}, map[string][]string{}
	add := func(m map[string][]string, key, name string) {
		if key != "" && name != "" && len(m[key]) < usedByMax {
			m[key] = append(m[key], name)
		}
	}
	for _, b := range boxes {
		name := ""
		if len(b.Names) > 0 {
			name = strings.TrimPrefix(b.Names[0], "/")
		}
		for n := range b.NetworkSettings.Networks {
			onNet[n]++
			add(byNet, n, name)
		}
		add(byImage, b.ImageID, name)
		for _, m := range b.Mounts {
			add(byVolume, m.Name, name)
		}
	}
	for _, l := range []map[string][]string{byNet, byImage, byVolume} {
		for k := range l {
			sort.Strings(l[k])
		}
	}
	inv := Inventory{Images: []ImageInfo{}, Volumes: []VolumeInfo{}, Networks: []NetworkInfo{}, More: map[string]int{}}
	for _, i := range u.Images {
		tags := []string{}
		for _, t := range i.RepoTags {
			if t != "<none>:<none>" {
				tags = append(tags, t)
			}
		}
		used := int(i.Containers)
		if used < 0 {
			used = 0
		}
		inv.Images = append(inv.Images, ImageInfo{ID: shortID(i.ID), Tags: tags, Size: i.Size, Created: i.Created,
			Used: used, Dangling: len(tags) == 0, UsedBy: byImage[i.ID]})
	}
	for _, v := range u.Volumes {
		vi := VolumeInfo{Name: v.Name, Driver: v.Driver, Size: -1, Anonymous: anonymousVolume.MatchString(v.Name), UsedBy: byVolume[v.Name]}
		if v.UsageData != nil {
			vi.Size, vi.Used = v.UsageData.Size, int(v.UsageData.RefCount)
		}
		inv.Volumes = append(inv.Volumes, vi)
	}
	for _, n := range nets {
		inv.Networks = append(inv.Networks, NetworkInfo{Name: n.Name, Driver: n.Driver, Scope: n.Scope,
			Used: onNet[n.Name], Builtin: builtin(n.Name), UsedBy: byNet[n.Name]})
	}
	sort.SliceStable(inv.Images, func(a, b int) bool { return inv.Images[a].Size > inv.Images[b].Size })
	sort.SliceStable(inv.Volumes, func(a, b int) bool { return inv.Volumes[a].Size > inv.Volumes[b].Size })
	sort.SliceStable(inv.Networks, func(a, b int) bool { return inv.Networks[a].Name < inv.Networks[b].Name })
	if n := len(inv.Images) - inventoryMax; n > 0 {
		inv.Images, inv.More["images"] = inv.Images[:inventoryMax], n
	}
	if n := len(inv.Volumes) - inventoryMax; n > 0 {
		inv.Volumes, inv.More["volumes"] = inv.Volumes[:inventoryMax], n
	}
	if n := len(inv.Networks) - inventoryMax; n > 0 {
		inv.Networks, inv.More["networks"] = inv.Networks[:inventoryMax], n
	}
	if len(inv.More) == 0 {
		inv.More = nil
	}
	b, err := json.Marshal(inv)
	return string(b), err
}

// pruneDangling removes the layers no tag points to and no container uses.
func (d *Docker) pruneDangling(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	var out struct {
		ImagesDeleted  []struct{ Deleted string }
		SpaceReclaimed uint64
	}
	if err := d.call(ctx, "POST", "/images/prune?filters="+url.QueryEscape(`{"dangling":["true"]}`), &out); err != nil {
		return "", err
	}
	n := 0
	for _, i := range out.ImagesDeleted {
		if i.Deleted != "" {
			n++
		}
	}
	return fmt.Sprintf("freed %s (%d untagged layers)", size(out.SpaceReclaimed), n), nil
}

// pruneNetworks removes the networks no container is on, made at least PruneAge ago (a compose
// project being brought up has its network a moment before its containers).
func (d *Docker) pruneNetworks(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	var out struct{ NetworksDeleted []string }
	if err := d.call(ctx, "POST", "/networks/prune?filters="+url.QueryEscape(`{"until":["`+PruneAge+`"]}`), &out); err != nil {
		return "", err
	}
	return fmt.Sprintf("removed %d unused networks", len(out.NetworksDeleted)), nil
}

// pruneVolumes removes the anonymous volumes (a 64-character hexadecimal name) nothing uses. It
// does the choosing itself rather than ask the engine: older engines remove every unused volume,
// the named ones too, and a named volume is somebody's data.
func (d *Docker) pruneVolumes(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	u, err := d.usageOf(ctx)
	if err != nil {
		return "", err
	}
	n, freed := 0, int64(0)
	for _, v := range u.Volumes {
		if !anonymousVolume.MatchString(v.Name) || v.UsageData == nil || v.UsageData.RefCount != 0 {
			continue
		}
		if err := d.call(ctx, "DELETE", "/volumes/"+url.PathEscape(v.Name), nil); err != nil {
			continue // it got used in the meantime: the engine refuses
		}
		n++
		if v.UsageData.Size > 0 {
			freed += v.UsageData.Size
		}
	}
	return fmt.Sprintf("freed %s (%d anonymous volumes)", size(uint64(freed)), n), nil
}

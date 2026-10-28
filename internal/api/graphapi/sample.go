package graphapi

import "sort"

// SampleGraph ports graph_sample.sample_graph: keep roughly limit nodes,
// ranked by degree and balanced by type (quota split evenly across the
// types present, leftovers filled by global degree). Returns the kept nodes,
// the links whose both ends were kept, and meta {sample, total_nodes,
// total_links}. Deterministic: ties break on the string form of the id.
func SampleGraph(nodes, links []map[string]any, limit int) ([]map[string]any, []map[string]any, map[string]any) {
	totalNodes, totalLinks := len(nodes), len(links)
	limit = max(1, limit)
	if totalNodes <= limit {
		return nodes, links, map[string]any{"sample": false, "total_nodes": totalNodes, "total_links": totalLinks}
	}

	degree := map[any]int{}
	for _, l := range links {
		if s := l["source"]; s != nil {
			degree[s]++
		}
		if t := l["target"]; t != nil {
			degree[t]++
		}
	}
	less := func(a, b map[string]any) bool {
		da, db := degree[a["id"]], degree[b["id"]]
		if da != db {
			return da > db
		}
		return pyFmt(a["id"]) < pyFmt(b["id"])
	}

	buckets := map[string][]map[string]any{}
	var order []string // first-seen type order (python dict insertion order)
	for _, n := range nodes {
		t, _ := n["type"].(string)
		if t == "" {
			t = "unknown"
		}
		if _, ok := buckets[t]; !ok {
			order = append(order, t)
		}
		buckets[t] = append(buckets[t], n)
	}
	for _, b := range buckets {
		sort.SliceStable(b, func(i, j int) bool { return less(b[i], b[j]) })
	}
	sort.SliceStable(order, func(i, j int) bool { return len(buckets[order[i]]) > len(buckets[order[j]]) })
	quota := max(1, limit/len(order))

	kept := make([]map[string]any, 0, limit)
	for _, t := range order {
		b := buckets[t]
		kept = append(kept, b[:min(quota, len(b))]...)
	}

	if len(kept) < limit {
		chosen := make(map[any]struct{}, len(kept))
		for _, n := range kept {
			chosen[n["id"]] = struct{}{}
		}
		var rest []map[string]any
		for _, n := range nodes {
			if _, ok := chosen[n["id"]]; !ok {
				rest = append(rest, n)
			}
		}
		sort.SliceStable(rest, func(i, j int) bool { return less(rest[i], rest[j]) })
		kept = append(kept, rest[:min(limit-len(kept), len(rest))]...)
	}

	keptIDs := make(map[any]struct{}, len(kept))
	for _, n := range kept {
		keptIDs[n["id"]] = struct{}{}
	}
	keptLinks := []map[string]any{}
	for _, l := range links {
		_, okS := keptIDs[l["source"]]
		_, okT := keptIDs[l["target"]]
		if okS && okT {
			keptLinks = append(keptLinks, l)
		}
	}
	return kept, keptLinks, map[string]any{"sample": true, "total_nodes": totalNodes, "total_links": totalLinks}
}

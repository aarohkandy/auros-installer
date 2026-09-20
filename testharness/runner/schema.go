package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// result.schema.json, ACTUALLY EVALUATED
//
// README §6 lists four things that make the boot check hard to skip, and the first of them is:
//
//	"boot_check is a required property in result.schema.json; a result without it does not validate,
//	 and runner report counts anything that does not validate as a failed run"
//
// That was false. The schema file existed, three comments referred to it, and no line of Go ever
// opened it. `cmdReport` did a single json.Unmarshal into RunResult, where every absent field becomes
// a zero value: a hand-written `{"kind":"clean","checks":[{"id":"P1","status":"pass"}]}` dropped into
// the results tree was counted as a clean PASS, with BootCheck a nil pointer and no corpus
// verification at all.
//
// So the schema is now loaded — embedded, so it cannot be missing at runtime — and evaluated.
//
// WHAT THIS VALIDATOR IMPLEMENTS, exactly: $schema, $id, title, description, type, required,
// properties, additionalProperties (false only), enum, pattern, items, minItems, minimum, maximum,
// format (parsed, deliberately not enforced — see below).
//
// WHY A SUBSET IS SAFE HERE. The obvious objection to a hand-written validator is that the schema will
// grow a keyword it silently ignores, and an ignored constraint is worse than an absent one because the
// document still claims it. So the supported set is not a comment: schemaKeywords below is the list,
// TestSchemaUsesOnlySupportedKeywords walks every node of result.schema.json and fails the build if it
// finds anything outside it, and unsupportedKeyword() fails validation at runtime for the same reason.
// Adding `oneOf` to the schema breaks the test on the commit that adds it, which is the only moment
// anybody is in a position to implement it.
//
// `format` is the one keyword parsed and not enforced. JSON Schema defines format as an annotation
// rather than an assertion by default, and "started_at is not RFC 3339" is not a way a run result lies
// about whether a check ran. It is listed here rather than left implicit so the gap is a decision.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

//go:embed result.schema.json
var resultSchemaJSON []byte

// schemaKeywords is the complete set this validator understands. See TestSchemaUsesOnlySupportedKeywords.
var schemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true,
	"type": true, "required": true, "properties": true, "additionalProperties": true,
	"enum": true, "pattern": true, "items": true, "minItems": true,
	"minimum": true, "maximum": true, "format": true,
}

type schemaNode map[string]any

// ResultSchema returns the embedded schema, parsed. It returns an error rather than panicking because
// the caller is a reporter whose job is to turn problems into failed runs, not to crash.
func ResultSchema() (schemaNode, error) {
	var n schemaNode
	if err := json.Unmarshal(resultSchemaJSON, &n); err != nil {
		return nil, fmt.Errorf("result.schema.json does not parse: %w", err)
	}
	return n, nil
}

// ValidateResultJSON checks one result.json's raw bytes against the schema.
//
// It returns every problem it finds rather than the first, because a result that is wrong in four ways
// is more useful to read than a result that is wrong in one way four times.
func ValidateResultJSON(raw []byte) []string {
	schema, err := ResultSchema()
	if err != nil {
		return []string{err.Error()}
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"does not parse as JSON: " + err.Error()}
	}
	v := &schemaValidator{}
	v.node(schema, doc, "")
	sort.Strings(v.problems)
	return v.problems
}

type schemaValidator struct{ problems []string }

func (v *schemaValidator) failf(path, format string, args ...any) {
	where := path
	if where == "" {
		where = "(root)"
	}
	v.problems = append(v.problems, where+": "+fmt.Sprintf(format, args...))
}

func (v *schemaValidator) node(s schemaNode, doc any, path string) {
	for k := range s {
		if !schemaKeywords[k] {
			// Fails closed. An unimplemented keyword is a constraint the document advertises and the
			// code does not apply, which is the exact failure this whole file exists to end.
			v.failf(path, "result.schema.json uses %q, which this validator does not implement", k)
			return
		}
	}

	if t, ok := s["type"]; ok && !v.matchesType(t, doc) {
		v.failf(path, "type is %s, want %v", jsonTypeOf(doc), t)
		return
	}
	if e, ok := s["enum"].([]any); ok {
		match := false
		for _, want := range e {
			if fmt.Sprintf("%v", want) == fmt.Sprintf("%v", doc) {
				match = true
				break
			}
		}
		if !match {
			v.failf(path, "%v is not one of %v", doc, e)
		}
	}
	if p, ok := s["pattern"].(string); ok {
		if str, isStr := doc.(string); isStr {
			re, err := regexp.Compile(p)
			if err != nil {
				v.failf(path, "schema pattern %q does not compile: %v", p, err)
			} else if !re.MatchString(str) {
				v.failf(path, "%q does not match %s", str, p)
			}
		}
	}
	if m, ok := s["minimum"].(float64); ok {
		if n, isNum := doc.(float64); isNum && n < m {
			v.failf(path, "%v is below the minimum %v", n, m)
		}
	}
	if m, ok := s["maximum"].(float64); ok {
		if n, isNum := doc.(float64); isNum && n > m {
			v.failf(path, "%v is above the maximum %v", n, m)
		}
	}

	switch obj := doc.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				val, present := obj[name]
				if !present {
					v.failf(path, "required property %q is missing", name)
					continue
				}
				if val == nil {
					// `"boot_check": null` is how a result would claim the check exists while saying
					// nothing about it. Null satisfies "the key is there" and nothing else.
					if sub, ok := props[name].(map[string]any); ok && !v.matchesType(sub["type"], nil) {
						v.failf(joinPath(path, name), "required property is null")
					}
				}
			}
		}
		if ap, ok := s["additionalProperties"]; ok {
			if allow, isBool := ap.(bool); isBool && !allow {
				for name := range obj {
					if _, known := props[name]; !known {
						v.failf(joinPath(path, name), "property is not in the schema and "+
							"additionalProperties is false")
					}
				}
			} else if !isBool {
				v.failf(path, "additionalProperties is only supported as false")
			}
		}
		for name, sub := range props {
			val, present := obj[name]
			if !present || val == nil {
				continue
			}
			subNode, ok := sub.(map[string]any)
			if !ok {
				v.failf(joinPath(path, name), "schema entry is not an object")
				continue
			}
			v.node(subNode, val, joinPath(path, name))
		}
	case []any:
		if mi, ok := s["minItems"].(float64); ok && float64(len(obj)) < mi {
			v.failf(path, "has %d items, minimum is %v", len(obj), mi)
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, el := range obj {
				v.node(items, el, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

func (v *schemaValidator) matchesType(t any, doc any) bool {
	switch want := t.(type) {
	case nil:
		return true
	case string:
		return jsonTypeMatches(want, doc)
	case []any:
		for _, w := range want {
			if s, ok := w.(string); ok && jsonTypeMatches(s, doc) {
				return true
			}
		}
		return false
	}
	return true
}

func jsonTypeMatches(want string, doc any) bool {
	switch want {
	case "object":
		_, ok := doc.(map[string]any)
		return ok
	case "array":
		_, ok := doc.([]any)
		return ok
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "number":
		_, ok := doc.(float64)
		return ok
	case "integer":
		n, ok := doc.(float64)
		return ok && n == math.Trunc(n)
	case "null":
		return doc == nil
	}
	return false
}

func jsonTypeOf(doc any) string {
	switch doc.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case nil:
		return "null"
	}
	return "unknown"
}

func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// SchemaKeywordsUsed walks the schema and returns every keyword name that appears in a schema position.
// It exists for the test that keeps schemaKeywords honest.
func SchemaKeywordsUsed(s schemaNode) []string {
	seen := map[string]bool{}
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		for k, val := range n {
			seen[k] = true
			switch k {
			case "properties":
				if props, ok := val.(map[string]any); ok {
					for _, sub := range props {
						if m, ok := sub.(map[string]any); ok {
							walk(m)
						}
					}
				}
			case "items":
				if m, ok := val.(map[string]any); ok {
					walk(m)
				}
			}
		}
	}
	walk(s)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// UnsupportedSchemaKeywords is the difference the test asserts is empty.
func UnsupportedSchemaKeywords(s schemaNode) []string {
	var bad []string
	for _, k := range SchemaKeywordsUsed(s) {
		if !schemaKeywords[k] {
			bad = append(bad, k)
		}
	}
	return bad
}

func init() {
	// Loading the schema is not optional and not deferred to the first report. A binary whose embedded
	// schema does not parse cannot enforce anything it claims to, and finding that out at the end of a
	// 120-run suite is finding it out at the worst moment.
	if _, err := ResultSchema(); err != nil {
		panic(err)
	}
	if bad := func() []string {
		s, _ := ResultSchema()
		return UnsupportedSchemaKeywords(s)
	}(); len(bad) > 0 {
		panic("result.schema.json uses keywords this validator does not implement: " + strings.Join(bad, ", "))
	}
}

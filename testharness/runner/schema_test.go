package main

// result.schema.json is now loaded and evaluated. These tests keep it that way, and keep the
// hand-written subset validator honest about what it does not implement.

import (
	"encoding/json"
	"strings"
	"testing"
)

// The validator implements a SUBSET of JSON Schema. A keyword it does not implement is a constraint
// the document advertises and the code never applies, which is worse than no constraint at all. This
// test breaks on the commit that adds one, which is the only moment anybody is in a position to
// implement it.
func TestSchemaUsesOnlySupportedKeywords(t *testing.T) {
	s, err := ResultSchema()
	if err != nil {
		t.Fatal(err)
	}
	if bad := UnsupportedSchemaKeywords(s); len(bad) > 0 {
		t.Fatalf("result.schema.json uses %v, which schema.go does not implement. Implement them or "+
			"remove them — do not widen schemaKeywords without implementing the keyword", bad)
	}
}

// MAJOR, runner.go:669 — the exact payload from the audit.
func TestHandWrittenMinimalResultIsMalformedAgainstTheSchema(t *testing.T) {
	raw := []byte(`{"kind":"clean","checks":[{"id":"P1","status":"pass"}]}`)
	problems := ValidateResultJSON(raw)
	if len(problems) == 0 {
		t.Fatal("README §6 defence #1 claims this does not validate; it must actually not validate")
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"boot_check", "corpus_verify", "archive_verify", "run_id", "harness"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the refusal should name the missing %q:\n%s", want, joined)
		}
	}
}

// `"boot_check": null` satisfies "the key is there" and nothing else.
func TestSchemaRejectsANullBootCheck(t *testing.T) {
	r := passingResult("clean", 1, "")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["boot_check"] = nil
	nulled, _ := json.Marshal(doc)
	problems := ValidateResultJSON(nulled)
	if len(problems) == 0 {
		t.Fatal("a null boot_check must not validate")
	}
	if !strings.Contains(strings.Join(problems, "\n"), "boot_check") {
		t.Fatalf("the refusal should name boot_check: %v", problems)
	}
}

// A check with a status the schema does not define, and a stray property, must both be caught.
func TestSchemaRejectsAnUnknownCheckStatusAndStrayProperties(t *testing.T) {
	r := passingResult("clean", 1, "")
	b, _ := json.Marshal(r)
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	doc["checks"].([]any)[0].(map[string]any)["status"] = "skip"
	doc["definitely_not_in_the_schema"] = true
	mutated, _ := json.Marshal(doc)
	problems := strings.Join(ValidateResultJSON(mutated), "\n")
	if !strings.Contains(problems, "skip") {
		t.Errorf(`"skip" is not a status — there is no skip. Got: %s`, problems)
	}
	if !strings.Contains(problems, "definitely_not_in_the_schema") {
		t.Errorf("additionalProperties is false at the root; got: %s", problems)
	}
}

// The control: what the harness actually writes must validate, or the validator is a trap rather than
// a check and the first honest suite fails 120 runs on a technicality.
func TestWhatTheHarnessWritesValidates(t *testing.T) {
	for _, r := range []*RunResult{
		passingResult("clean", 1, ""),
		passingResult("fault", 2, "F02"),
		passingResult("fault", 10, "F10"),
	} {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if problems := ValidateResultJSON(append(b, '\n')); len(problems) > 0 {
			t.Errorf("%s does not validate against its own schema:\n  %s",
				r.RunID, strings.Join(problems, "\n  "))
		}
	}
}

module github.com/aarohkandy/auros-installer/testharness

// No third-party dependencies, deliberately.
//
// This harness is the evidence-producing half of a tool that deletes people's only copy of their work.
// Every dependency is a thing that can change under us between the run that produced REPORT.md and the
// run a customer's auditor re-executes. Config that wants comments uses the `$comment` key convention
// already used by auros.config.json; the fault catalogue is Go source precisely so that it compiles or
// it does not.

go 1.22

package gate3

import "unsafe"

// EVENT_TRACE_PROPERTIES is 120 bytes on amd64; the names must start right after it.
// Both lines fail to compile if the layout drifts in either direction.
var (
	_ [120 - unsafe.Offsetof(eventTraceProperties{}.names)]byte
	_ [unsafe.Offsetof(eventTraceProperties{}.names) - 120]byte
	_ [112 - unsafe.Offsetof(eventTraceProperties{}.LogFileNameOffset)]byte
	_ [unsafe.Offsetof(eventTraceProperties{}.LogFileNameOffset) - 112]byte
)

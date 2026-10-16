package window

import "github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"

// The kernel sketch only exists on Linux; this fails to compile if its
// methods drift from Source.
var _ Source = (*heavykeeper.Sketch)(nil)

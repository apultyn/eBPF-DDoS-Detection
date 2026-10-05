# Heavy keeper notes

## Questions

- what to do with blocked IP's?
  - chat suggests that IP's should be blocked for specified time
  - we'll probably use LRU (last recently used) map
- how to include IQR into this code? So far the thresholds are constants
- in general, how to merge it with IQR and Count-min

## Notes

- `static` and `__always_inline` are mandatory in functions
- IPv4 and IPv6 are stored in the same key struct, IPv4 in this format `::ffff:a.b.c.d`
- `#pragma unroll` - compiler unrolls the loop
- IP masking
  - before IP is hashed, only some of it's most important bits are taken
  - close IP addresses are treated as equal
- `bpf_ktime_get_coarse_ns()` - sort of timestamp
- each CPU has to have it's own sketch without doing some acrobatics but code can sum through all the sketches
- maybe use the `HK_CHECK_EVERY` trick
  - when estimating on one CPU and being below the threshold, attack can still occur when the NIC spreads attack on all CPU's
  - given value is amount of packets of a source on CPU that is summed over all CPU's

## TODO

- need to change the map type to LRU
- modify the threshold to be read from user-space

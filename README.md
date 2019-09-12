
## Temp Repo for benchmark
Checking if string builder pool is really necessary.

### Run
```
$ git clone git@github.com:gerardmrk/sbpx.git
$ cd sbpx && make
```

Vendored mode to save you the trouble.


### Results on MacOS i7 - 16gb
```bash
go test -bench . -benchtime=10s
goos: darwin
goarch: amd64
pkg: github.com/gerardmrk/sbpx
BenchmarkEncodeToString-8             	   30423	    391191 ns/op	  255406 B/op	      51 allocs/op
BenchmarkEncodeToStringWithSBPool-8   	   31222	    363343 ns/op	  255249 B/op	      44 allocs/op
PASS
ok  	github.com/gerardmrk/sbpx	31.140s
```
Performance diff was negligible.

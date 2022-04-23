# bin-callgraph
Tiny call graph and performance analysis for compiled ELF files

### Build
```
$ mkdir build && cd build
```

Build with Zydis (currently, capstone isn't supported):
```
cmake .. -DENGINE:STRING=zydis
```

And finally, run make:
```
$ make
```

### Run tests
From build/ directory:

Run all tests:
```
$ ../test/run.sh
```

Or run a specific test:
```
../test/test.sh test/single_func_modify_ecx
```

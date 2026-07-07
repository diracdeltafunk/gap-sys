# gap-sys

This crate contains bindings to GAP - Groups, Algorithms, Programming - a System for Computational Discrete Algebra. It is currently in a very early state, and contribution is encouraged.

## GAP discovery

`gap-sys` tries to discover a local GAP installation at build time. By default it runs `gap --print-gaproot` using `gap` from `PATH`; for older GAP versions that do not support that option, it falls back to querying `GAPInfo.RootPaths` for a root containing `lib/init.g`. It then infers GAP's header and library directories from that root.

The build supports both common header layouts:

- installed headers such as `/usr/local/include/gap/libgap-api.h`
- source/Homebrew-style headers such as `/opt/homebrew/opt/gap/libexec/src/libgap-api.h` plus generated headers under `build/`

You can override discovery with environment variables:

- `GAP_SYS_ROOT`: GAP root directory containing `lib/init.g`
- `GAP_SYS_GAP_BIN`: GAP executable used for `--print-gaproot`
- `GAP_SYS_INCLUDE_DIRS`: path-list of include directories
- `GAP_SYS_LIB_DIRS`: path-list of directories containing `libgap`

`GAP_SYS_INCLUDE_DIRS` and `GAP_SYS_LIB_DIRS` use the platform path-list separator (`:` on Unix/macOS, `;` on Windows).

For a Homebrew GAP installation on macOS, automatic discovery should normally work when `gap` is on `PATH`. An explicit configuration looks like:

```sh
GAP_SYS_ROOT=/opt/homebrew/opt/gap/libexec \
GAP_SYS_INCLUDE_DIRS=/opt/homebrew/opt/gap/libexec/src:/opt/homebrew/opt/gap/libexec/build \
GAP_SYS_LIB_DIRS=/opt/homebrew/opt/gap/libexec \
cargo build
```

For a custom installation with installed headers, use the GAP root and the installation prefix:

```sh
GAP_SYS_ROOT=/usr/local/lib/gap \
GAP_SYS_INCLUDE_DIRS=/usr/local/include \
GAP_SYS_LIB_DIRS=/usr/local/lib \
cargo build
```

At runtime, `Gap::init()` uses `GAP_SYS_ROOT` if it is set, otherwise it uses the GAP root detected at build time. Use `Gap::try_init()` or `Gap::try_init_with_root(...)` for fallible initialization with better diagnostics.

#### Example showing how to create a Group
```
let mut gap = Gap::init();
let gap_element = gap.eval("Group((1,2,3),(1,2));").unwrap();
assert_eq!(gap.elem_string(&gap_element), "Group( [ (1,2,3), (1,2) ] )");
```

#### Example showing how to access elements of a list
```
let mut gap = Gap::init();
let outer_list = gap.eval("[[1, 2, 3], [4, 5, 6]];;").unwrap();
let inner_list = gap.get_list_elem(&outer_list, 1).unwrap();
let element = gap.get_list_elem(&inner_list, 1).unwrap();
let string = gap.elem_string(&element);
assert_eq!(string, "5");
```

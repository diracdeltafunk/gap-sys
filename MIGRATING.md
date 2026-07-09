# Migrating from upstream/master

This branch renames the convenience API that existed on `upstream/master`.
The old spellings below remain available as deprecated forwarding aliases to
make the transition easy for upstream users.

| `upstream/master` | This branch | Notes |
| --- | --- | --- |
| `GapElement` | `GapRef` | Deprecated alias; explicitly denotes an unrooted, transient handle. |
| `Gap::eval` | `Gap::eval_unrooted` | Exception: the name now means rooted evaluation, so the former unrooted signature cannot coexist as an alias. |
| `Gap::elem_string` | `Gap::display_unrooted` | Deprecated alias. Use `Gap::display` with a `GapValue` in ordinary code. |
| `Gap::get_list_elem` | `Gap::list_get_unrooted` | Deprecated alias. Use `Gap::list_get` with a `GapValue` in ordinary code. |
| `Gap::alloc` | `Gap::root_ref` | Deprecated alias for advanced manual root management. |
| `Gap::free` | `Gap::unroot_ref` | Deprecated alias for advanced manual root management. |

`GapValue` is new. It owns a GAP GC root, so it is safe to retain across calls
that may allocate. The standard constructors and operations (`eval`, `int`,
`list`, `list_get`, `get_global`, `call`, and `call_global`) now return one.

Names added after `upstream/master` have also been normalized. Their former
spellings (`gap_eval`, `*_rooted`, `global`, `call_function`, `integer_usize`,
and `boolean`) remain as deprecated forwarding aliases as well.

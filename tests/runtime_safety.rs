//! Regression tests for runtime-safety bugs in the process-global GAP wrapper.
//!
//! The tests in this binary deliberately share one GAP runtime and run on
//! `cargo test`'s default parallel test threads.

use anyhow::Result;
use std::thread;

/// A GAP evaluation error must not poison later, unrelated calls.
#[test]
fn evaluation_error_does_not_poison_later_calls() -> Result<()> {
    let gap = gap_sys::global()?;
    assert!(gap.eval("this is not GAP syntax;").is_err());
    drop(gap);

    gap_sys::eval("SymmetricGroup(3);")?;
    // Evaluate the argument first: `global()` is not re-entrant, so calling
    // `gap_sys::eval` while a guard is held would deadlock.
    let group = gap_sys::eval("SymmetricGroup(3);")?;
    let gap = gap_sys::global()?;
    let size = gap.call_global("Size", &[&group])?;
    assert_eq!(gap.to_usize(&size)?, 6);
    Ok(())
}

/// Every kind of GAP failure surfaces as an `Err` and leaves the runtime usable.
#[test]
fn gap_errors_are_reported_and_recovered_from() -> Result<()> {
    let mut gap = gap_sys::global()?;

    // Syntax error, runtime error, and an error in a later statement.
    assert!(gap.eval("1 +;").is_err());
    assert!(gap.eval("1/0;").is_err());
    assert!(gap.eval("1; Error(\"boom\");").is_err());
    // An error deep inside nested GAP function calls.
    assert!(gap
        .eval("f := function(n) if n = 0 then return 1/0; fi; return f(n-1); end;; f(50);")
        .is_err());

    // Errors raised by GAP functions called directly through the API.
    let three = gap.int(3);
    assert!(gap.call_global("Size", &[&three]).is_err());
    let error = gap.get_global("Error")?;
    let message = gap.eval("\"boom\";")?;
    assert!(gap.call(&error, &[&message]).is_err());
    assert!(gap.get_global("ThisGlobalDoesNotExist").is_err());

    // Errors raised while printing (from inside `PrintTo`) are recovered too.
    gap.eval(
        "BindGlobal(\"IsGapSysUnprintable\", NewFilter(\"IsGapSysUnprintable\"));; \
         InstallMethod(PrintObj, [IsGapSysUnprintable], function(x) Error(\"no\"); end);;",
    )?;
    let unprintable = gap.eval(
        "Objectify(NewType(NewFamily(\"GapSys\"), \
         IsGapSysUnprintable and IsComponentObjectRep), rec());",
    )?;
    assert!(gap.try_display(&unprintable).is_err());

    // Non-list and out-of-range accesses are errors rather than null handles.
    assert!(gap.list_get(&three, 0).is_err());
    let list = gap.eval("[1, 2, 3];")?;
    assert!(gap.list_get(&list, 3).is_err());
    assert!(gap.to_usize(&list).is_err());

    // Errors raised by GAP operations that are not wrapped in a GAP-level
    // catch reach the `GAP_Enter()` backstop, including from deep inside GAP
    // functions.
    assert!(gap.to_usize(&gap.eval("2^70;")?).is_err());
    gap.eval(
        "BindGlobal(\"IsGapSysBadList\", NewFilter(\"IsGapSysBadList\"));; \
         InstallMethod(IsBound\\[\\], [IsGapSysBadList and IsList, IsPosInt], ReturnTrue);; \
         InstallMethod(\\[\\], [IsGapSysBadList and IsList, IsPosInt], function(list, i) \
           local f; \
           f := function(n) if n = 0 then Error(\"bad element\"); fi; return f(n - 1); end; \
           return f(20); \
         end);;",
    )?;
    let bad_list = gap.eval(
        "Objectify(NewType(ListsFamily, IsGapSysBadList and IsList and IsComponentObjectRep), \
         rec());",
    )?;
    for _ in 0..3 {
        assert!(gap.list_get(&bad_list, 0).is_err());
    }

    // Empty commands, and values from statements that return nothing, are
    // rejected rather than handed to GAP as null pointers.
    assert!(gap.eval("").is_err());
    let nothing = gap.eval("Print(\"\");")?;
    assert!(gap.call_global("Size", &[&nothing]).is_err());
    assert!(gap.try_display(&nothing).is_err());
    assert!(gap.list_get(&nothing, 0).is_err());
    assert!(gap.to_usize(&nothing).is_err());

    // Nothing above left GAP's interpreter, output redirection, or error
    // flag in a bad state.
    let last = gap.eval("GapSysX := 2;; GapSysX + 1;")?;
    assert_eq!(gap.to_usize(&last)?, 3);
    let value = gap.eval("List([1..10], i -> i^2);")?;
    assert_eq!(
        gap.display(&value),
        "[ 1, 4, 9, 16, 25, 36, 49, 64, 81, 100 ]"
    );
    let group = gap.eval("SymmetricGroup(4);")?;
    let size = gap.call_global("Size", &[&group])?;
    assert_eq!(gap.to_usize(&size)?, 24);
    let depth = gap.eval("GetRecursionDepth();")?;
    assert_eq!(gap.to_usize(&depth)?, 0);
    Ok(())
}

/// Heavy, allocation-intensive GAP work from many threads must not crash.
///
/// libgap's conservative garbage collector scans the C stack of whichever
/// thread it believes is running GAP. Before the fix, it kept scanning the
/// stack of the thread that initialized GAP, so collections triggered on
/// other threads either freed live temporaries or read unmapped memory.
#[test]
fn concurrent_gap_use_from_many_threads_is_safe() -> Result<()> {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 20;
    // Groups whose subgroup lattices GAP computes without optional packages
    // (natural symmetric groups such as `SymmetricGroup(5)` need TransGrp).
    const GROUPS: [&str; 5] = [
        "DihedralGroup(IsPermGroup, 16);",
        "DihedralGroup(IsPermGroup, 24);",
        "DirectProduct(DihedralGroup(IsPermGroup, 8), CyclicGroup(IsPermGroup, 3));",
        "WreathProduct(CyclicGroup(IsPermGroup, 3), CyclicGroup(IsPermGroup, 2));",
        "WreathProduct(CyclicGroup(IsPermGroup, 2), CyclicGroup(IsPermGroup, 3));",
    ];

    /// The number of conjugacy classes of subgroups of `group` and the sum
    /// of their representatives' orders, after building the full lattice.
    fn subgroup_class_summary(group: &str) -> Result<(usize, usize)> {
        let group = gap_sys::eval(group)?;
        let gap = gap_sys::global()?;
        let classes = gap.call_global("ConjugacyClassesSubgroups", &[&group])?;
        let lattice = gap.call_global("LatticeSubgroups", &[&group])?;
        let maximal = gap.call_global("MaximalSubgroupsLattice", &[&lattice])?;
        gap.eval("GASMAN(\"collect\");")?;
        let representatives = (0..gap.list_len(&classes))
            .map(|idx| {
                let class = gap.list_get(&classes, idx)?;
                gap.call_global("Representative", &[&class])
            })
            .collect::<Result<Vec<_>>>()?;
        let order_sum = representatives
            .iter()
            .map(|subgroup| gap.to_usize(&gap.call_global("Size", &[subgroup])?))
            .sum::<Result<usize>>()?;
        assert_eq!(gap.list_len(&maximal), gap.list_len(&classes));
        Ok((representatives.len(), order_sum))
    }

    let expected = GROUPS
        .iter()
        .map(|group| subgroup_class_summary(group))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(expected[0], (11, 59), "subgroup classes of D_16");

    let handles = (0..THREADS)
        .map(|thread_idx| {
            let expected = expected.clone();
            thread::spawn(move || -> Result<()> {
                for iteration in 0..ITERATIONS {
                    let idx = (thread_idx + iteration) % GROUPS.len();
                    let summary = subgroup_class_summary(GROUPS[idx])?;
                    assert_eq!(
                        summary, expected[idx],
                        "subgroup classes of {}",
                        GROUPS[idx]
                    );
                    // Give the scheduler a chance to switch threads between
                    // lock acquisitions.
                    thread::yield_now();
                }
                Ok(())
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().expect("GAP worker thread panicked")?;
    }
    Ok(())
}

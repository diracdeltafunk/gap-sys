//! GAP installation discovery shared by `build.rs` and tests.
//!
//! The build script needs three pieces of information before bindgen can run:
//! the runtime GAP root, the directories containing GAP headers, and the
//! directories containing libgap. This module keeps that probing logic
//! testable without executing the full Cargo build script.

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Environment variable for the GAP runtime root containing `lib/init.g`.
pub const GAP_SYS_ROOT: &str = "GAP_SYS_ROOT";
/// Environment variable for the GAP executable used during root discovery.
pub const GAP_SYS_GAP_BIN: &str = "GAP_SYS_GAP_BIN";
/// Environment variable containing a platform-separated list of header dirs.
pub const GAP_SYS_INCLUDE_DIRS: &str = "GAP_SYS_INCLUDE_DIRS";
/// Environment variable containing a platform-separated list of libgap dirs.
pub const GAP_SYS_LIB_DIRS: &str = "GAP_SYS_LIB_DIRS";
/// GAP code used when `gap --print-gaproot` is unavailable.
///
/// Older GAP releases print a banner or prompt instead of supporting
/// `--print-gaproot`. This snippet asks GAP itself for roots containing the
/// core `lib/init.g` file and exits immediately.
const GAP_ROOT_QUERY: &str = "for p in GAPInfo.RootPaths do if IsExistingFile(Concatenation(p,\"lib/init.g\")) then Print(p,\"\\n\"); fi; od; QUIT;";

/// Header include style used by the local GAP installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderLayout {
    /// Headers are under an include prefix, for example `include/gap/gap_all.h`.
    IncludeSubdir,
    /// Headers are directly in a source directory, for example `src/gap_all.h`.
    Direct,
}

/// Complete build-time configuration for libgap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapConfig {
    /// Runtime GAP root containing `lib/init.g`.
    pub root: PathBuf,
    /// Include directories passed to clang and `cc`.
    pub include_dirs: Vec<PathBuf>,
    /// Native library search directories passed to rustc.
    pub lib_dirs: Vec<PathBuf>,
    /// Header layout used when generating the bindgen wrapper header.
    pub header_layout: HeaderLayout,
}

/// Captured GAP discovery environment.
///
/// Tests construct this explicitly; the build script uses
/// [`DiscoveryEnv::from_process_env`] to read the real process environment.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryEnv {
    /// Optional `GAP_SYS_ROOT` value.
    pub root: Option<OsString>,
    /// Optional `GAP_SYS_GAP_BIN` value.
    pub gap_bin: Option<OsString>,
    /// Optional `GAP_SYS_INCLUDE_DIRS` value.
    pub include_dirs: Option<OsString>,
    /// Optional `GAP_SYS_LIB_DIRS` value.
    pub lib_dirs: Option<OsString>,
}

impl DiscoveryEnv {
    /// Reads all supported GAP discovery variables from the current process.
    pub fn from_process_env() -> Self {
        Self {
            root: env::var_os(GAP_SYS_ROOT),
            gap_bin: env::var_os(GAP_SYS_GAP_BIN),
            include_dirs: env::var_os(GAP_SYS_INCLUDE_DIRS),
            lib_dirs: env::var_os(GAP_SYS_LIB_DIRS),
        }
    }
}

/// Discovers the GAP root, include directories, library directories, and layout.
///
/// Explicit environment values take precedence. If no root is supplied, the
/// function queries a GAP executable. Include and library directories are
/// inferred from the resolved root unless their corresponding environment
/// variables are set.
pub fn discover_gap_config(env: &DiscoveryEnv) -> Result<GapConfig, String> {
    let root = env
        .root
        .as_deref()
        .and_then(nonempty_path)
        .map(Ok)
        .unwrap_or_else(|| query_gap_root(env))?;
    let root = resolve_gap_root(&root)?;

    let include_dirs = match env.include_dirs.as_deref() {
        Some(paths) => parse_path_list(paths),
        None => infer_include_dirs(&root),
    };
    let header_layout = find_header_layout(&include_dirs).ok_or_else(|| {
        format!(
            "Could not find GAP headers. Tried include directories: {}. \
             Set {GAP_SYS_INCLUDE_DIRS} or {GAP_SYS_ROOT}.",
            display_paths(&include_dirs)
        )
    })?;

    let lib_dirs = match env.lib_dirs.as_deref() {
        Some(paths) => parse_path_list(paths),
        None => infer_lib_dirs(&root),
    };
    if !lib_dirs.iter().any(|dir| contains_libgap(dir)) {
        return Err(format!(
            "Could not find libgap. Tried library directories: {}. \
             Set {GAP_SYS_LIB_DIRS} or {GAP_SYS_ROOT}.",
            display_paths(&lib_dirs)
        ));
    }

    Ok(GapConfig {
        root,
        include_dirs,
        lib_dirs,
        header_layout,
    })
}

/// Generates the C wrapper header that bindgen reads.
///
/// The wrapper normalizes GAP API differences across releases: callback
/// signatures, `GAP_Enter` availability, output stream state, function calls,
/// and bag marking. Keeping those shims in C lets bindgen expose stable Rust
/// symbols such as `SYSGAP_Initialize` and `SYSGAP_CallFunc2Args`.
pub fn wrapper_header(layout: &HeaderLayout) -> String {
    let includes = match layout {
        HeaderLayout::IncludeSubdir => "#include <gap/libgap-api.h>\n#include <gap/gap_all.h>",
        HeaderLayout::Direct => "#include \"libgap-api.h\"\n#include \"gap_all.h\"",
    };

    format!(
        "\
// Generated by gap-sys build.rs.
// We must define EXPORT_INLINE as static inline for bindgen to work with libgap.
#define EXPORT_INLINE static inline

// Include all of GAP's headers.
{includes}

// Wrapper around macros and version-varying libgap APIs.
#if defined(GAP_CallbackFunc)
typedef GAP_CallbackFunc SYSGAP_CallbackFunc;
#else
typedef void (*SYSGAP_CallbackFunc)(void);
#endif

static inline void SYSGAP_Initialize(
    int argc,
    char ** argv,
    SYSGAP_CallbackFunc markBagsCallback,
    SYSGAP_CallbackFunc errorCallback,
    int handleSignals) {{
#if defined(GAP_Enter)
    GAP_Initialize(argc, argv, markBagsCallback, errorCallback, handleSignals);
#else
    (void)handleSignals;
    GAP_Initialize(argc, argv, 0, markBagsCallback, errorCallback);
#endif
}}

#if defined(GAP_Enter)
static inline int SYSGAP_Enter() {{
    return GAP_Enter();
}}

static inline void SYSGAP_Leave() {{
    GAP_Leave();
}}
#endif

#if defined(GAP_KERNEL_API_VERSION) && GAP_KERNEL_API_VERSION >= 8000
static TypOutputFile SYSGAP_OUTPUT_STREAM = {{ 0 }};
#endif

static inline UInt SYSGAP_OpenOutputStream(Obj stream) {{
#if defined(GAP_KERNEL_API_VERSION) && GAP_KERNEL_API_VERSION >= 8000
    return OpenOutputStream(&SYSGAP_OUTPUT_STREAM, stream);
#else
    return OpenOutputStream(stream);
#endif
}}

static inline UInt SYSGAP_CloseOutput(void) {{
#if defined(GAP_KERNEL_API_VERSION) && GAP_KERNEL_API_VERSION >= 8000
    return CloseOutput(&SYSGAP_OUTPUT_STREAM);
#else
    return CloseOutput();
#endif
}}

static inline Obj SYSGAP_CallFunc2Args(Obj func, Obj a1, Obj a2) {{
#if defined(GAP_Enter)
    Obj args[2] = {{ a1, a2 }};
    return GAP_CallFuncArray(func, 2, args);
#else
    return CALL_2ARGS(func, a1, a2);
#endif
}}

static inline void SYSGAP_MarkBag(Obj obj) {{
#if defined(GAP_KERNEL_API_VERSION) && GAP_KERNEL_API_VERSION >= 8000
    GAP_MarkBag(obj);
#else
    MarkBag(obj);
#endif
}}
"
    )
}

/// Asks a GAP executable to print a usable runtime root.
///
/// The preferred command is `gap --print-gaproot`. If that does not produce a
/// valid root, the function falls back to evaluating `GAP_ROOT_QUERY` through
/// GAP itself for compatibility with older releases.
fn query_gap_root(env: &DiscoveryEnv) -> Result<PathBuf, String> {
    let explicit_gap_bin = env.gap_bin.as_ref().is_some();
    let gap_bin = env
        .gap_bin
        .as_deref()
        .filter(|bin| !bin.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("gap"));

    match run_gap_command(&gap_bin, ["--print-gaproot"]) {
        Ok(output) if output.status.success() => {
            if let Some(root) = parse_gap_root_stdout(&output.stdout) {
                return Ok(root);
            }
        }
        Ok(_) => {}
        Err(err) if explicit_gap_bin => {
            return Err(format!(
                "Could not run `{}`: {err}. Set {GAP_SYS_ROOT}.",
                gap_bin.display()
            ));
        }
        Err(_) => {
            return Err(format!(
                "Could not run `gap --print-gaproot`. Set {GAP_SYS_ROOT} or {GAP_SYS_GAP_BIN}."
            ));
        }
    }

    match run_gap_command(&gap_bin, ["-q", "-c", GAP_ROOT_QUERY]) {
        Ok(output) if output.status.success() => {
            parse_gap_root_stdout(&output.stdout).ok_or_else(|| {
                format!(
                    "`{} -q -c <gap-root-query>` did not print a usable GAP root. Set {GAP_SYS_ROOT}.",
                    gap_bin.display()
                )
            })
        }
        Ok(output) if explicit_gap_bin => Err(format!(
            "`{} -q -c <gap-root-query>` failed with status {}. Set {GAP_SYS_ROOT}.",
            gap_bin.display(),
            output.status
        )),
        Ok(_) => Err(format!(
            "Could not discover GAP root with `gap --print-gaproot` or a GAPInfo.RootPaths query. Set {GAP_SYS_ROOT}."
        )),
        Err(err) if explicit_gap_bin => Err(format!(
            "Could not run `{}`: {err}. Set {GAP_SYS_ROOT}.",
            gap_bin.display()
        )),
        Err(_) => Err(format!(
            "Could not run GAP root discovery commands. Set {GAP_SYS_ROOT} or {GAP_SYS_GAP_BIN}."
        )),
    }
}

/// Runs `gap_bin` with `args` while closing stdin.
///
/// Closing stdin prevents build scripts from accidentally blocking on an
/// interactive GAP prompt when discovery fails.
fn run_gap_command<const N: usize>(
    gap_bin: &Path,
    args: [&str; N],
) -> std::io::Result<std::process::Output> {
    Command::new(gap_bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
}

/// Extracts the best GAP root candidate from command output.
///
/// The parser tolerates startup banners, prompts, and warnings. It prefers a
/// path that already contains `lib/init.g`, but keeps the first existing
/// directory as a fallback for later resolution.
fn parse_gap_root_stdout(stdout: &[u8]) -> Option<PathBuf> {
    let stdout = String::from_utf8_lossy(stdout);
    let mut existing_dir = None;

    for line in stdout.lines() {
        let Some(path) = parse_gap_root_line(line) else {
            continue;
        };

        if path.join("lib").join("init.g").is_file() {
            return Some(path);
        }

        if existing_dir.is_none() && path.is_dir() {
            existing_dir = Some(path);
        }
    }

    existing_dir
}

/// Parses one possible path line from GAP command output.
///
/// GAP prompts such as `gap>` are stripped before checking whether the
/// remaining text looks like a filesystem path.
fn parse_gap_root_line(line: &str) -> Option<PathBuf> {
    let line = line.trim();
    let line = line.strip_prefix("gap>").unwrap_or(line).trim();

    if line.is_empty() || !is_plausible_path(line) {
        return None;
    }

    Some(PathBuf::from(line))
}

/// Returns whether `path` has a shape worth treating as a filesystem path.
///
/// This deliberately stays syntactic so it can accept paths that may only
/// become valid after root candidate resolution.
fn is_plausible_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path.starts_with("./")
        || path.starts_with("../")
        || path
            .as_bytes()
            .get(1)
            .map(|byte| *byte == b':')
            .unwrap_or(false)
}

/// Resolves a printed or configured root to the directory containing `lib/init.g`.
///
/// Package managers sometimes report a package root such as `share/gap` or
/// `lib/gap` while the embeddable runtime lives in a nearby `libexec`
/// directory. Candidate probing handles those common layouts.
fn resolve_gap_root(root: &Path) -> Result<PathBuf, String> {
    let candidates = gap_root_candidates(root);
    for candidate in &candidates {
        if candidate.join("lib").join("init.g").is_file() {
            return Ok(candidate.clone());
        }
    }

    Err(format!(
        "GAP root `{}` does not contain `lib/init.g`. Tried: {}. Set {GAP_SYS_ROOT} to a valid GAP root.",
        root.display(),
        display_paths(&candidates)
    ))
}

/// Returns candidate runtime roots near `root`.
///
/// The first candidate is always the supplied root. Nearby `libexec`,
/// `share/gap`, and `lib/gap` directories are then added while preserving order
/// and uniqueness.
fn gap_root_candidates(root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    push_unique(&mut candidates, root.to_path_buf());

    for base in root.ancestors().take(4) {
        push_unique(&mut candidates, base.join("libexec"));
        push_unique(&mut candidates, base.join("share").join("gap"));
        push_unique(&mut candidates, base.join("lib").join("gap"));
    }

    candidates
}

/// Infers include directories from a resolved GAP runtime root.
///
/// Source-tree layouts expose headers directly under `src` and generated
/// headers under `build`. Installed layouts expose headers under an include
/// prefix with a `gap/` subdirectory.
fn infer_include_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let source_dir = root.join("src");
    if source_dir.join("libgap-api.h").is_file() && source_dir.join("gap_all.h").is_file() {
        push_unique(&mut dirs, source_dir);
        let build_dir = root.join("build");
        if build_dir.is_dir() {
            push_unique(&mut dirs, build_dir);
        }
    }

    push_include_candidate(&mut dirs, root.join("include"));

    if let Some(parent) = root.parent() {
        push_include_candidate(&mut dirs, parent.join("include"));

        if let Some(prefix) = parent.parent() {
            push_include_candidate(&mut dirs, prefix.join("include"));
        }
    }

    dirs
}

/// Adds `dir` when it contains installed-style GAP headers.
fn push_include_candidate(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
    if dir.join("gap").join("libgap-api.h").is_file() && dir.join("gap").join("gap_all.h").is_file()
    {
        push_unique(dirs, dir);
    }
}

/// Infers native library search directories from a resolved GAP root.
///
/// The search covers the root itself, nearby `lib` directories, common
/// multiarch children, and `lib64` under an installation prefix.
fn infer_lib_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    push_lib_candidate(&mut dirs, root.to_path_buf());
    push_lib_candidates_under(&mut dirs, root.join("lib"));

    if let Some(parent) = root.parent() {
        push_lib_candidate(&mut dirs, parent.to_path_buf());
        push_lib_candidates_under(&mut dirs, parent.join("lib"));

        if let Some(prefix) = parent.parent().filter(|prefix| prefix.parent().is_some()) {
            push_lib_candidates_under(&mut dirs, prefix.join("lib"));
            push_lib_candidates_under(&mut dirs, prefix.join("lib64"));
        }
    }

    dirs
}

/// Adds `dir` and its immediate child directories when they contain libgap.
///
/// Immediate children cover layouts such as `lib/x86_64-linux-gnu` without a
/// recursive filesystem walk during build scripts.
fn push_lib_candidates_under(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
    push_lib_candidate(dirs, dir.clone());

    let Ok(entries) = dir.read_dir() else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            push_lib_candidate(dirs, path);
        }
    }
}

/// Adds `dir` if it contains a recognized libgap library file.
fn push_lib_candidate(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
    if contains_libgap(&dir) {
        push_unique(dirs, dir);
    }
}

/// Detects whether include directories use installed or direct header layout.
///
/// Installed `gap/` subdirectories are preferred because they match normal
/// compiler include-prefix conventions.
fn find_header_layout(include_dirs: &[PathBuf]) -> Option<HeaderLayout> {
    for dir in include_dirs {
        if dir.join("gap").join("libgap-api.h").is_file()
            && dir.join("gap").join("gap_all.h").is_file()
        {
            return Some(HeaderLayout::IncludeSubdir);
        }
    }

    for dir in include_dirs {
        if dir.join("libgap-api.h").is_file() && dir.join("gap_all.h").is_file() {
            return Some(HeaderLayout::Direct);
        }
    }

    None
}

/// Returns whether `dir` contains a recognizable libgap artifact.
fn contains_libgap(dir: &Path) -> bool {
    let Ok(entries) = dir.read_dir() else {
        return false;
    };

    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .map(is_libgap_file_name)
            .unwrap_or(false)
    })
}

/// Matches common shared, static, versioned, and Windows libgap filenames.
fn is_libgap_file_name(name: &str) -> bool {
    matches!(
        name,
        "libgap.so" | "libgap.dylib" | "libgap.a" | "libgap.dll" | "libgap.dll.a" | "gap.dll"
    ) || name.starts_with("libgap.so.")
        || (name.starts_with("libgap.") && name.ends_with(".dylib"))
}

/// Parses a platform-separated path-list environment value.
///
/// Empty entries are ignored so accidental leading or trailing separators do
/// not become the current directory.
fn parse_path_list(paths: &OsStr) -> Vec<PathBuf> {
    env::split_paths(paths)
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

/// Converts a non-empty OS string to a path.
fn nonempty_path(path: &OsStr) -> Option<PathBuf> {
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Appends `path` if it is not already present.
fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Formats a path list for human-readable error messages.
fn display_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        "<none>".to_string()
    } else {
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn discovers_source_style_gap_root() {
        let root = temp_root("source-style");
        write_file(root.join("lib/init.g"));
        write_file(root.join("src/libgap-api.h"));
        write_file(root.join("src/gap_all.h"));
        write_file(root.join("build/config.h"));
        write_file(root.join("libgap.dylib"));

        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(root.clone().into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.root, root);
        assert_eq!(config.header_layout, HeaderLayout::Direct);
        assert!(config.include_dirs.contains(&config.root.join("src")));
        assert!(config.include_dirs.contains(&config.root.join("build")));
        assert_eq!(config.lib_dirs, vec![config.root.clone()]);
    }

    #[test]
    fn discovers_installed_style_gap_root() {
        let base = temp_root("installed-style");
        let root = base.join("lib/gap");
        write_file(root.join("lib/init.g"));
        write_file(base.join("include/gap/libgap-api.h"));
        write_file(base.join("include/gap/gap_all.h"));
        write_file(base.join("lib/libgap.so"));

        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(root.clone().into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.root, root);
        assert_eq!(config.header_layout, HeaderLayout::IncludeSubdir);
        assert_eq!(config.include_dirs, vec![base.join("include")]);
        assert_eq!(config.lib_dirs, vec![base.join("lib")]);
    }

    #[test]
    fn explicit_env_vars_override_inferred_paths() {
        let base = temp_root("explicit-env");
        let root = base.join("gaproot");
        let include = base.join("custom-include");
        let lib = base.join("custom-lib");
        write_file(root.join("lib/init.g"));
        write_file(root.join("src/libgap-api.h"));
        write_file(root.join("src/gap_all.h"));
        write_file(root.join("libgap.dylib"));
        write_file(include.join("gap/libgap-api.h"));
        write_file(include.join("gap/gap_all.h"));
        write_file(lib.join("libgap.so"));

        let include_paths = env::join_paths([include.clone()]).unwrap();
        let lib_paths = env::join_paths([lib.clone()]).unwrap();
        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            include_dirs: Some(include_paths),
            lib_dirs: Some(lib_paths),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.header_layout, HeaderLayout::IncludeSubdir);
        assert_eq!(config.include_dirs, vec![include]);
        assert_eq!(config.lib_dirs, vec![lib]);
    }

    #[test]
    fn reports_missing_headers() {
        let root = temp_root("missing-headers");
        write_file(root.join("lib/init.g"));
        write_file(root.join("libgap.dylib"));

        let err = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap_err();

        assert!(err.contains("Could not find GAP headers"));
    }

    #[test]
    fn reports_missing_libgap() {
        let root = temp_root("missing-libgap");
        write_file(root.join("lib/init.g"));
        write_file(root.join("src/libgap-api.h"));
        write_file(root.join("src/gap_all.h"));

        let err = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap_err();

        assert!(err.contains("Could not find libgap"));
    }

    #[test]
    fn discovers_multiarch_lib_dir() {
        let base = temp_root("multiarch-lib");
        let root = base.join("share/gap");
        let include = base.join("include");
        let lib = base.join("lib/x86_64-linux-gnu");
        write_file(root.join("lib/init.g"));
        write_file(include.join("gap/libgap-api.h"));
        write_file(include.join("gap/gap_all.h"));
        write_file(lib.join("libgap.so"));

        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.include_dirs, vec![include]);
        assert_eq!(config.lib_dirs, vec![lib]);
    }

    #[test]
    fn resolves_homebrew_package_root_to_libexec_root() {
        let cellar = temp_root("homebrew-libexec");
        let printed_root = cellar.join("lib/gap");
        let actual_root = cellar.join("libexec");
        write_file(printed_root.join("pkg/README"));
        write_file(actual_root.join("lib/init.g"));
        write_file(actual_root.join("src/libgap-api.h"));
        write_file(actual_root.join("src/gap_all.h"));
        write_file(actual_root.join("build/config.h"));
        write_file(actual_root.join("libgap.dylib"));

        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(printed_root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.root, actual_root);
        assert_eq!(config.header_layout, HeaderLayout::Direct);
    }

    #[test]
    fn finds_libgap_in_sibling_lib_dir() {
        let cellar = temp_root("homebrew-sibling-lib");
        let root = cellar.join("libexec");
        let lib = cellar.join("lib");
        write_file(root.join("lib/init.g"));
        write_file(root.join("src/libgap-api.h"));
        write_file(root.join("src/gap_all.h"));
        write_file(root.join("build/config.h"));
        write_file(lib.join("libgap.dylib"));

        let config = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap();

        assert_eq!(config.lib_dirs, vec![lib]);
    }

    #[test]
    fn parses_plain_gap_root_output() {
        let root = temp_root("plain-gaproot-output");
        write_file(root.join("lib/init.g"));

        assert_eq!(
            parse_gap_root_stdout(root.to_string_lossy().as_bytes()),
            Some(root)
        );
    }

    #[test]
    fn ignores_banner_output_when_parsing_gap_root() {
        let root = temp_root("banner-gaproot-output");
        write_file(root.join("lib/init.g"));
        let output = format!(
            "Unrecognised command line option: --print-gaproot\n\
             GAP 4.11.1 startup banner\n\
             gap> {}\n",
            root.display()
        );

        assert_eq!(parse_gap_root_stdout(output.as_bytes()), Some(root));
    }

    #[test]
    fn reports_invalid_gap_root() {
        let root = temp_root("invalid-root");
        write_file(root.join("src/libgap-api.h"));
        write_file(root.join("src/gap_all.h"));
        write_file(root.join("libgap.dylib"));

        let err = discover_gap_config(&DiscoveryEnv {
            root: Some(root.into_os_string()),
            ..DiscoveryEnv::default()
        })
        .unwrap_err();

        assert!(err.contains("does not contain `lib/init.g`"));
    }

    fn temp_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("gap-sys-{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(path: PathBuf) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "").unwrap();
    }
}

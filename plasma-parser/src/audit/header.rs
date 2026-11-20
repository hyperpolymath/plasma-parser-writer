// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// SPDX header extraction — reads the first N lines of a source file and
// extracts the SPDX-License-Identifier value.

use crate::spdx::{parse_spdx_expr, SpdxExpr};
use std::fs;
use std::path::Path;

/// Maximum number of lines to scan for an SPDX header.
const MAX_HEADER_LINES: usize = 15;

/// File extensions that should have SPDX headers, grouped by comment style.
pub const AUDITABLE_EXTENSIONS: &[&str] = &[
    "rs", "zig", "idr", "js", "ts", "jsx", "tsx", "res", "resi", "ex", "exs", "gleam", "jl", "hs",
    "ml", "mli", "nim", "pony", "py", "rb", "go", "c", "h", "cpp", "hpp", "java", "kt", "scala",
    "sh", "bash", "zsh", "toml", "yaml", "yml", "ncl", "nix", "scm", "v", "ada", "adb", "ads",
];

/// Prose file extensions. Not audited by `plasma audit`; their headers are
/// collected into facts only when a policy asks for them.
pub const PROSE_EXTENSIONS: &[&str] = &["adoc", "md"];

/// Returns the comment prefix for a given file extension.
pub fn comment_prefix(ext: &str) -> &'static str {
    match ext {
        "rs" | "zig" | "js" | "ts" | "jsx" | "tsx" | "res" | "resi" | "go" | "c" | "h" | "cpp"
        | "hpp" | "java" | "kt" | "scala" | "pony" | "v" => "//",
        "idr" | "hs" | "ml" | "mli" => "--",
        "ada" | "adb" | "ads" => "--",
        "ex" | "exs" | "gleam" | "nim" | "py" | "rb" | "sh" | "bash" | "zsh" | "toml" | "yaml"
        | "yml" | "ncl" | "nix" | "jl" => "#",
        "scm" => ";;",
        "adoc" => "//",
        _ => "//",
    }
}

/// Render header comment lines for a file extension, ending with a blank
/// line. Markdown has no line comment, so each line becomes an HTML comment.
pub fn format_header(ext: &str, lines: &[String]) -> String {
    let mut out = String::new();
    for line in lines {
        if ext == "md" {
            out.push_str(&format!("<!-- {line} -->\n"));
        } else {
            out.push_str(&format!("{} {line}\n", comment_prefix(ext)));
        }
    }
    out.push('\n');
    out
}

/// Check whether a file extension is auditable.
pub fn is_auditable(ext: &str) -> bool {
    AUDITABLE_EXTENSIONS.contains(&ext)
}

/// Returns true if the extension is a prose format (AsciiDoc or Markdown).
pub fn is_prose(ext: &str) -> bool {
    PROSE_EXTENSIONS.contains(&ext)
}

/// Extract the SPDX-License-Identifier from a file's header.
///
/// Returns `None` if the file has no SPDX header within the first
/// `MAX_HEADER_LINES` lines.
pub fn extract_spdx_header(path: &Path) -> Option<SpdxExpr> {
    let content = fs::read_to_string(path).ok()?;
    extract_spdx_from_content(&content)
}

/// Extract SPDX expression from file content string.
pub fn extract_spdx_from_content(content: &str) -> Option<SpdxExpr> {
    let raw = extract_spdx_raw_from_content(content)?;
    parse_spdx_expr(&raw).ok()
}

/// Extract the raw (unparsed) SPDX-License-Identifier value from file content.
///
/// Unlike [`extract_spdx_from_content`], this distinguishes "no header"
/// (`None`) from "header present but unparsable" (`Some(raw)`), letting
/// callers defer or report parse failures themselves.
pub fn extract_spdx_raw_from_content(content: &str) -> Option<String> {
    for line in content.lines().take(MAX_HEADER_LINES) {
        let trimmed = line.trim();
        // Markdown HTML comment: <!-- SPDX-License-Identifier: X -->
        let trimmed = match trimmed.strip_prefix("<!--") {
            Some(inner) => inner.trim_end().strip_suffix("-->").unwrap_or(inner).trim(),
            None => trimmed,
        };
        // Strip comment prefixes.
        let stripped = trimmed
            .strip_prefix("//")
            .or_else(|| trimmed.strip_prefix('#'))
            .or_else(|| trimmed.strip_prefix("--"))
            .or_else(|| trimmed.strip_prefix(";;"))
            .unwrap_or(trimmed)
            .trim();

        if let Some(rest) = stripped.strip_prefix("SPDX-License-Identifier:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_header_markdown_round_trips() {
        let h = format_header("md", &["SPDX-License-Identifier: CC-BY-SA-4.0".to_string()]);
        assert_eq!(h, "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n\n");
        assert_eq!(
            extract_spdx_raw_from_content(&h).as_deref(),
            Some("CC-BY-SA-4.0")
        );
    }

    #[test]
    fn test_format_header_asciidoc() {
        let h = format_header(
            "adoc",
            &["SPDX-License-Identifier: CC-BY-SA-4.0".to_string()],
        );
        assert_eq!(h, "// SPDX-License-Identifier: CC-BY-SA-4.0\n\n");
    }

    #[test]
    fn test_extract_markdown_html_comment_header() {
        let content = "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n# Title\n";
        assert_eq!(
            extract_spdx_raw_from_content(content).as_deref(),
            Some("CC-BY-SA-4.0")
        );
    }

    #[test]
    fn test_extract_asciidoc_header() {
        let content = "// SPDX-License-Identifier: CC-BY-SA-4.0\n= Title\n";
        assert_eq!(
            extract_spdx_raw_from_content(content).as_deref(),
            Some("CC-BY-SA-4.0")
        );
    }

    #[test]
    fn test_extract_rust_header() {
        let content = "// SPDX-License-Identifier: PPMPL-1.0-or-later\n// Copyright (c) 2026\n";
        let expr = extract_spdx_from_content(content);
        assert!(expr.is_some());
    }

    #[test]
    fn test_extract_python_header() {
        let content = "#!/usr/bin/env python3\n# SPDX-License-Identifier: MIT\n";
        let expr = extract_spdx_from_content(content);
        assert!(expr.is_some());
    }

    #[test]
    fn test_no_header() {
        let content = "fn main() {\n    println!(\"hello\");\n}\n";
        let expr = extract_spdx_from_content(content);
        assert!(expr.is_none());
    }
}

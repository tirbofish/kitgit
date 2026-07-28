use syntect::html::{ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;
use std::sync::OnceLock;

fn syntaxes() -> &'static SyntaxSet {
    static SS: OnceLock<SyntaxSet> = OnceLock::new();
    SS.get_or_init(SyntaxSet::load_defaults_newlines)
}

/// Highlight `content` for `path`, returning a self-contained `.kg-codeview`.
///
/// Syntect keeps spans open across lines, so the highlighted HTML must stay one
/// contiguous block. Line numbers live in a sibling gutter with the same
/// monospace metrics / line-height / `white-space: pre` so rows stay aligned.
pub fn highlight(path: &str, content: &str) -> String {
    let ss = syntaxes();
    let syntax = ss
        .find_syntax_by_extension(
            std::path::Path::new(path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or(""),
        )
        .or_else(|| {
            std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| ss.find_syntax_by_name(n))
        })
        .or_else(|| ss.find_syntax_by_first_line(content.lines().next().unwrap_or("")))
        .unwrap_or_else(|| ss.find_syntax_plain_text());

    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, ss, ClassStyle::Spaced);
    for line in LinesWithEndings::from(content) {
        let _ = generator.parse_html_for_line_which_includes_newline(line);
    }
    // Trim trailing newlines so <pre> visual rows match str::lines() (a trailing
    // \n inside <pre> otherwise paints an extra blank row vs the gutter).
    let mut html = generator.finalize();
    while html.ends_with('\n') {
        html.pop();
    }

    let line_count = html.lines().count().max(1);
    let mut nums = String::with_capacity(line_count * 4);
    for n in 1..=line_count {
        if n > 1 {
            nums.push('\n');
        }
        nums.push_str(&n.to_string());
    }

    format!(
        "<div class=\"kg-codeview kg-blob\">\
           <div class=\"kg-blob__nums\" aria-hidden=\"true\">{nums}</div>\
           <pre class=\"kg-blob__code\"><code class=\"kg-highlight\">{html}</code></pre>\
         </div>"
    )
}

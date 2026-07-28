use pulldown_cmark::{html, Options, Parser};
use std::borrow::Cow;

/// Render Markdown to HTML. Protects TeX math from Markdown emphasis/escaping,
/// then leaves `$…$` / `$$…$$` for client-side KaTeX (+ KaTeX fonts).
pub fn render_markdown(src: &str) -> String {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let src = preprocess_math_fences(src);
    let (protected, slots) = protect_math(&src);
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_FOOTNOTES);
    let parser = Parser::new_ext(&protected, opts);
    let mut out = String::new();
    html::push_html(&mut out, parser);
    restore_math(&out, &slots)
}

fn preprocess_math_fences(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let fence = if trimmed.starts_with("```math") || trimmed.starts_with("```latex") {
            Some(true)
        } else if trimmed.starts_with("~~~math") || trimmed.starts_with("~~~latex") {
            Some(true)
        } else {
            None
        };
        if fence.is_some() {
            let closer = if trimmed.starts_with("```") { "```" } else { "~~~" };
            out.push_str("$$\n");
            while let Some(inner) = lines.next() {
                if inner.trim().starts_with(closer) {
                    break;
                }
                out.push_str(inner);
                out.push('\n');
            }
            out.push_str("$$\n");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn protect_math(src: &str) -> (String, Vec<String>) {
    let mut out = String::with_capacity(src.len());
    let mut slots = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut in_fence = false;
    let mut fence_char = b'`';
    let mut fence_len = 0usize;

    while i < bytes.len() {
        // Track fenced code blocks so we don't treat $ inside them as math.
        if !in_fence && (bytes[i] == b'`' || bytes[i] == b'~') {
            let ch = bytes[i];
            let mut n = 0;
            while i + n < bytes.len() && bytes[i + n] == ch {
                n += 1;
            }
            if n >= 3 && (i == 0 || bytes[i - 1] == b'\n') {
                in_fence = true;
                fence_char = ch;
                fence_len = n;
                out.push_str(&src[i..i + n]);
                i += n;
                continue;
            }
        } else if in_fence && bytes[i] == fence_char {
            let mut n = 0;
            while i + n < bytes.len() && bytes[i + n] == fence_char {
                n += 1;
            }
            if n >= fence_len && (i == 0 || bytes[i - 1] == b'\n') {
                in_fence = false;
                out.push_str(&src[i..i + n]);
                i += n;
                continue;
            }
        }

        if !in_fence && bytes[i] == b'$' {
            let display = i + 1 < bytes.len() && bytes[i + 1] == b'$';
            let start = if display { i + 2 } else { i + 1 };
            let delim = if display { "$$" } else { "$" };
            if let Some(end) = find_math_end(bytes, start, display) {
                let body = &src[start..end];
                // Skip empty / whitespace-only (likely not math).
                if !body.trim().is_empty() {
                    let token = format!("\u{E000}MATH{}\u{E001}", slots.len());
                    slots.push(format!("{delim}{body}{delim}"));
                    out.push_str(&token);
                    i = end + if display { 2 } else { 1 };
                    continue;
                }
            }
        }

        // Also protect \( ... \) and \[ ... \]
        if !in_fence && bytes[i] == b'\\' && i + 1 < bytes.len() {
            let open = bytes[i + 1];
            if open == b'(' || open == b'[' {
                let close = if open == b'(' { b')' } else { b']' };
                let start = i + 2;
                if let Some(end) = find_escaped_math_end(bytes, start, close) {
                    let body = &src[start..end];
                    if !body.trim().is_empty() {
                        let token = format!("\u{E000}MATH{}\u{E001}", slots.len());
                        let delim_open = if open == b'(' { "\\(" } else { "\\[" };
                        let delim_close = if open == b'(' { "\\)" } else { "\\]" };
                        slots.push(format!("{delim_open}{body}{delim_close}"));
                        out.push_str(&token);
                        i = end + 2;
                        continue;
                    }
                }
            }
        }

        out.push(src[i..].chars().next().unwrap());
        i += src[i..].chars().next().unwrap().len_utf8();
    }

    (out, slots)
}

fn find_math_end(bytes: &[u8], start: usize, display: bool) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if display {
            if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                return Some(i);
            }
        } else if bytes[i] == b'$' {
            // Don't treat $$ as inline closer.
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                return None;
            }
            // No newlines in inline math (common Markdown convention).
            if bytes[start..i].contains(&b'\n') {
                return None;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_escaped_math_end(bytes: &[u8], start: usize, close: u8) -> Option<usize> {
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == close {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn restore_math(html: &str, slots: &[String]) -> String {
    let mut out = Cow::Borrowed(html);
    for (idx, math) in slots.iter().enumerate() {
        let token = format!("\u{E000}MATH{idx}\u{E001}");
        // Markdown may HTML-escape nothing for private-use chars; also handle entities if any.
        if out.contains(&token) {
            out = Cow::Owned(out.replace(&token, math));
        }
    }
    out.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_inline_math_with_underscore() {
        let html = render_markdown("Euler $e^{i\\pi}+1=0$ and $x_1$.");
        assert!(html.contains("$x_1$"), "{html}");
        assert!(!html.contains("<em>"), "{html}");
    }

    #[test]
    fn preserves_display_math() {
        let html = render_markdown("$$\n\\int_0^1 x^2\\,dx\n$$");
        assert!(html.contains("$$"), "{html}");
        assert!(html.contains("\\int_0^1"), "{html}");
    }

    #[test]
    fn latex_fence_to_display() {
        let html = render_markdown("```latex\n\\frac{a}{b}\n```");
        assert!(html.contains("$$"), "{html}");
        assert!(html.contains("\\frac{a}{b}"), "{html}");
    }
}

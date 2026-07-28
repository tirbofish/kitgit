use serde::Deserialize;

use serde_json::{json, Value};

use std::collections::HashMap;

use std::path::Path;

use std::sync::OnceLock;



const DEFAULT_LANG_COLOR: &str = "#858585";

/// Languages below this share of total bytes are omitted from the bar / list.

const MIN_DISPLAY_PERCENT: f64 = 2.0;



#[derive(Deserialize)]

struct ColorEntry {

    color: Option<String>,

}



fn colors_map() -> &'static HashMap<String, String> {

    static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

    MAP.get_or_init(|| {

        let raw: HashMap<String, ColorEntry> =

            serde_json::from_str(include_str!("github-colors.json")).unwrap_or_default();

        raw.into_iter()

            .filter_map(|(name, entry)| entry.color.map(|color| (name, color)))

            .collect()

    })

}



/// GitHub linguist color for a language name ([ozh/github-colors](https://github.com/ozh/github-colors)).

pub fn language_color(name: &str) -> &'static str {

    colors_map()

        .get(name)

        .map(String::as_str)

        .unwrap_or(DEFAULT_LANG_COLOR)

}



pub fn detect_languages(files: &[(String, usize)]) -> Value {

    let mut counts: HashMap<&'static str, usize> = HashMap::new();

    for (path, size) in files {

        if let Some(lang) = lang_for_path(path) {

            *counts.entry(lang).or_default() += *size.max(&1);

        }

    }

    let total: usize = counts.values().sum::<usize>().max(1);

    let mut items: Vec<_> = counts.into_iter().collect();

    items.sort_by(|a, b| b.1.cmp(&a.1));



    // Drop languages under the display threshold, then renormalize percents.

    let kept: Vec<_> = items

        .into_iter()

        .filter(|(_, bytes)| ((*bytes as f64) * 100.0 / total as f64) >= MIN_DISPLAY_PERCENT)

        .collect();

    let kept_total: usize = kept.iter().map(|(_, b)| *b).sum::<usize>().max(1);



    let map: serde_json::Map<String, Value> = kept

        .into_iter()

        .map(|(k, v)| {

            let pct = (v as f64) * 100.0 / kept_total as f64;

            (

                k.to_string(),

                json!({

                    "bytes": v,

                    "percent": (pct * 10.0).round() / 10.0,

                    "color": language_color(k),

                }),

            )

        })

        .collect();

    Value::Object(map)

}



/// Ensure stored language stats include GitHub colors (older rows may omit them).

/// Also filters out languages under 2% and renormalizes displayed percentages.

pub fn enrich_language_colors(stats: Value) -> Value {

    let Value::Object(map) = stats else {

        return stats;

    };



    let mut items: Vec<(String, f64, usize, String)> = Vec::new();

    for (name, meta) in map {

        let Value::Object(obj) = meta else {

            continue;

        };

        let percent = obj

            .get("percent")

            .and_then(|v| v.as_f64())

            .unwrap_or(0.0);

        if percent < MIN_DISPLAY_PERCENT {

            continue;

        }

        let bytes = obj

            .get("bytes")

            .and_then(|v| v.as_u64())

            .map(|b| b as usize)

            .unwrap_or(0);

        let color = obj

            .get("color")

            .and_then(|c| c.as_str())

            .filter(|c| !c.is_empty())

            .map(|c| c.to_string())

            .unwrap_or_else(|| language_color(&name).to_string());

        items.push((name, percent, bytes, color));

    }



    let weight_total: f64 = if items.iter().any(|(_, _, b, _)| *b > 0) {

        items.iter().map(|(_, _, b, _)| *b as f64).sum::<f64>().max(1.0)

    } else {

        items.iter().map(|(_, p, _, _)| *p).sum::<f64>().max(1.0)

    };



    let mut out = serde_json::Map::new();

    for (name, percent, bytes, color) in items {

        let pct = if bytes > 0 {

            (bytes as f64) * 100.0 / weight_total

        } else {

            percent * 100.0 / weight_total

        };

        out.insert(

            name,

            json!({

                "bytes": bytes,

                "percent": (pct * 10.0).round() / 10.0,

                "color": color,

            }),

        );

    }

    Value::Object(out)

}



fn lang_for_path(path: &str) -> Option<&'static str> {

    let name = Path::new(path)

        .file_name()

        .and_then(|s| s.to_str())

        .unwrap_or("");

    if name == "Dockerfile" || name.starts_with("Dockerfile.") {

        return Some("Dockerfile");

    }

    if name == "Makefile" || name == "makefile" {

        return Some("Makefile");

    }

    let ext = Path::new(path)

        .extension()

        .and_then(|s| s.to_str())

        .unwrap_or("")

        .to_ascii_lowercase();

    Some(match ext.as_str() {

        "rs" => "Rust",

        "go" => "Go",

        "py" => "Python",

        "js" | "mjs" | "cjs" => "JavaScript",

        "ts" | "tsx" => "TypeScript",

        "jsx" => "JavaScript",

        "java" => "Java",

        "kt" | "kts" => "Kotlin",

        "c" | "h" => "C",

        "cpp" | "cc" | "cxx" | "hpp" => "C++",

        "cs" => "C#",

        "rb" => "Ruby",

        "php" => "PHP",

        "swift" => "Swift",

        "scala" => "Scala",

        "hs" => "Haskell",

        "lua" => "Lua",

        "sh" | "bash" | "zsh" => "Shell",

        "ps1" => "PowerShell",

        "html" | "htm" => "HTML",

        "css" => "CSS",

        "scss" | "sass" => "SCSS",

        "md" | "markdown" => "Markdown",

        "json" => "JSON",

        "yml" | "yaml" => "YAML",

        "toml" => "TOML",

        "xml" => "XML",

        "sql" => "SQL",

        "r" => "R",

        "dart" => "Dart",

        "vue" => "Vue",

        "svelte" => "Svelte",

        "zig" => "Zig",

        "nim" => "Nim",

        "ex" | "exs" => "Elixir",

        "erl" => "Erlang",

        "clj" | "cljs" => "Clojure",

        "tf" => "HCL",

        "proto" => "Protocol Buffer",

        _ => return None,

    })

}



#[cfg(test)]

mod tests {

    use super::*;



    #[test]

    fn rust_uses_github_color() {

        assert_eq!(language_color("Rust"), "#dea584");

        assert_eq!(language_color("Python"), "#3572A5");

        assert_eq!(language_color("NotARealLang"), DEFAULT_LANG_COLOR);

    }



    #[test]

    fn detect_includes_color() {

        let stats = detect_languages(&[("main.rs".into(), 100)]);

        let rust = stats.get("Rust").unwrap();

        assert_eq!(rust["color"], "#dea584");

    }



    #[test]

    fn detect_excludes_under_two_percent() {

        let stats = detect_languages(&[

            ("main.rs".into(), 980),

            ("tiny.py".into(), 10), // ~1%

            ("app.js".into(), 10),  // ~1%

        ]);

        assert!(stats.get("Rust").is_some());

        assert!(stats.get("Python").is_none());

        assert!(stats.get("JavaScript").is_none());

        let pct = stats["Rust"]["percent"].as_f64().unwrap();

        assert!((pct - 100.0).abs() < 0.01);

    }



    #[test]

    fn enrich_filters_and_renormalizes() {

        let stats = json!({

            "Rust": { "bytes": 90, "percent": 90.0, "color": "#dea584" },

            "Python": { "bytes": 1, "percent": 1.0 },

            "Go": { "bytes": 9, "percent": 9.0 },

        });

        let enriched = enrich_language_colors(stats);

        assert!(enriched.get("Python").is_none());

        assert!(enriched.get("Rust").is_some());

        assert!(enriched.get("Go").is_some());

        let rust = enriched["Rust"]["percent"].as_f64().unwrap();

        let go = enriched["Go"]["percent"].as_f64().unwrap();

        assert!((rust + go - 100.0).abs() < 0.2);

    }

}


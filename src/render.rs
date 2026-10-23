//! The report: what to upgrade, and where the compromised certificate actually
//! is. Terminal (ANSI) and HTML.

use std::collections::BTreeMap;

use crate::remediate::{PlanAction, PlanItem};
use crate::report::FileReport;

pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Style { color }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.paint("1;31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.paint("1;33", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.paint("1;36", s)
    }
}

pub struct Summary {
    pub files: u64,
    pub bytes: u64,
    pub elapsed: f64,
    pub high: usize,
    pub partial: u64,
    pub thorough: bool,
}

const MAX_UNITS: usize = 30;

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

fn action_paint(style: &Style, action: PlanAction) -> String {
    match action {
        PlanAction::Upgrade => style.red("UPGRADE"),
        PlanAction::Clear => style.yellow("CLEAR  "),
        PlanAction::Remove => style.cyan("REMOVE "),
    }
}

pub fn render(reports: &[FileReport], s: &Summary, style: &Style) {
    let references = reports.len().saturating_sub(s.high);
    println!();
    println!(
        "{}",
        style.bold("eMudhra compromised-certificate footprint")
    );
    println!("{}", style.dim(&"\u{2500}".repeat(72)));
    println!(
        "  Scanned {} files ({:.2} GiB) in {:.1}s",
        style.bold(&fmt_num(s.files)),
        s.bytes as f64 / 1_073_741_824.0,
        s.elapsed
    );
    println!(
        "  {} files contain a compromised intermediate   {} files only mention eMudhra (ignored)",
        style.red(&style.bold(&fmt_num(s.high as u64))),
        style.dim(&fmt_num(references as u64)),
    );
    if s.partial > 0 && !s.thorough {
        println!(
            "  {} {} large opaque files were only read at head/tail (--thorough to be sure)",
            style.dim("\u{2139}"),
            fmt_num(s.partial)
        );
    }

    let plan = crate::remediate::plan(reports);
    let urgent: Vec<&PlanItem> = plan.iter().filter(|p| p.intermediate).collect();
    let upgrades: Vec<&PlanItem> = plan
        .iter()
        .filter(|p| p.action == PlanAction::Upgrade && !p.intermediate)
        .collect();
    let side: Vec<&PlanItem> = plan
        .iter()
        .filter(|p| p.action != PlanAction::Upgrade && !p.intermediate)
        .collect();

    if plan.is_empty() {
        println!(
            "\n{}\n",
            style.bold("No traces of the compromised eMudhra certificates were found.")
        );
        return;
    }

    // ① What actually holds the compromised certificate.
    println!(
        "\n{} {}",
        style.red(&style.bold("\u{2460} CONTAINS THE COMPROMISED CERTIFICATE")),
        style.dim("\u{2014} act on these")
    );
    for it in &urgent {
        println!(
            "   {} {} {} {}",
            action_paint(style, it.action),
            style.bold(it.kind),
            style.dim("\u{2022}"),
            it.unit
        );
        println!(
            "        {}",
            style.dim(&format!(
                "{} file(s) contain the exact certificate",
                fmt_num(it.intermediate_files as u64)
            ))
        );
        for c in &it.command {
            println!("        {}", style.green(c));
        }
    }
    let urgent_files: usize = urgent.iter().map(|p| p.intermediate_files).sum();
    println!(
        "   {}",
        style.dim(&format!("({} files)", fmt_num(urgent_files as u64)))
    );

    // ② Things to upgrade — grouped by kind, one command each.
    let upgrade_files: usize = upgrades.iter().map(|p| p.files).sum();
    println!(
        "\n{} {}",
        style.red(&style.bold("\u{2461} UPGRADE PLAN")),
        style.dim(&format!(
            "\u{2014} {} files across {} items",
            fmt_num(upgrade_files as u64),
            upgrades.len()
        ))
    );
    for (kind, items, files) in grouped(&upgrades) {
        let count = if files == 0 {
            format!("{} tool(s)", items.len())
        } else {
            format!("{} files, {} unit(s)", fmt_num(files as u64), items.len())
        };
        println!(
            "   {} {}",
            style.bold(kind),
            style.dim(&format!("\u{2022} {count}"))
        );

        let uniform = items.iter().all(|i| i.command == items[0].command);
        if uniform {
            for c in &items[0].command {
                println!("        {}", style.green(c));
            }
        }
        for it in items.iter().take(MAX_UNITS) {
            let suffix = if it.files > 0 {
                format!(" ({})", it.files)
            } else {
                String::new()
            };
            println!(
                "        {} {}{}",
                style.dim("\u{2022}"),
                it.unit,
                style.dim(&suffix)
            );
            if !uniform {
                for c in &it.command {
                    println!("            {}", style.green(c));
                }
            }
        }
        if items.len() > MAX_UNITS {
            println!(
                "        {}",
                style.dim(&format!("\u{2026} +{} more", items.len() - MAX_UNITS))
            );
        }
    }

    // ③ Non-certificate side effects worth clearing.
    if !side.is_empty() {
        println!(
            "\n{} {}",
            style.cyan(&style.bold("\u{2462} CLEAR / REMOVE")),
            style.dim("\u{2014} no software to upgrade")
        );
        for (kind, items, files) in grouped(&side) {
            let units: Vec<String> = items
                .iter()
                .map(|i| format!("{} ({})", i.unit, i.files))
                .collect();
            println!(
                "   {} {} {}",
                action_paint(style, items[0].action),
                style.bold(kind),
                style.dim(&format!(
                    "\u{2022} {} files \u{2014} {}",
                    fmt_num(files as u64),
                    units.join(", ")
                ))
            );
        }
    }

    println!(
        "\n{}\n",
        style.dim(
            "The 8 compromised certificates are the TLS/code-signing intermediates; a file \"contains\" \
             one only when its exact bytes (or that key's SPKI hash) are present. Use --json for the raw data."
        )
    );
}

/// Group plan items by kind, ordered by file count.
fn grouped<'a>(items: &[&'a PlanItem]) -> Vec<(&'static str, Vec<&'a PlanItem>, usize)> {
    let mut by_kind: BTreeMap<&'static str, Vec<&PlanItem>> = BTreeMap::new();
    for it in items {
        by_kind.entry(it.kind).or_default().push(it);
    }
    let mut out: Vec<(&str, Vec<&PlanItem>, usize)> = by_kind
        .into_iter()
        .map(|(k, v)| (k, v.clone(), v.iter().map(|i| i.files).sum()))
        .collect();
    out.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)));
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn render_html(reports: &[FileReport], s: &Summary) -> String {
    let references = reports.len().saturating_sub(s.high);
    let plan = crate::remediate::plan(reports);
    let urgent: Vec<&PlanItem> = plan.iter().filter(|p| p.intermediate).collect();
    let upgrades: Vec<&PlanItem> = plan
        .iter()
        .filter(|p| p.action == PlanAction::Upgrade && !p.intermediate)
        .collect();
    let side: Vec<&PlanItem> = plan
        .iter()
        .filter(|p| p.action != PlanAction::Upgrade && !p.intermediate)
        .collect();

    let mut h = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>eMudhra compromised-certificate footprint</title><style>\
         :root{color-scheme:dark}\
         body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0e1116;color:#c9d1d9;margin:0;padding:2rem;max-width:1000px}\
         h1{font-size:1.25rem;margin:0 0 .3rem}\
         h2{font-size:1rem;margin:1.6rem 0 .6rem}\
         .sum{color:#8b949e}.sum b{color:#e6edf3}\
         .urgent{color:#f85149}\
         .kind{border:1px solid #21262d;border-radius:10px;padding:.8rem 1rem;margin:.6rem 0;background:#161b22}\
         .kind h3{margin:0 0 .4rem;font-size:.95rem}\
         .n{color:#8b949e;font-weight:400}\
         pre{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:.6rem;margin:.4rem 0;overflow:auto}\
         pre .c{color:#8b949e}pre .g{color:#7ee787}\
         ul{margin:.3rem 0;padding-left:1.1rem;color:#8b949e;columns:2}\
         li{break-inside:avoid}\
         .badge{font-weight:700;font-size:.7rem;padding:.12rem .45rem;border-radius:6px;margin-right:.4rem}\
         .b-up{background:#f85149;color:#0e1116}.b-cl{background:#d29922;color:#0e1116}.b-rm{background:#58a6ff;color:#0e1116}\
         .legend{color:#8b949e;margin-top:1.5rem}\
         </style></head><body>",
    );
    h.push_str(&format!(
        "<h1>eMudhra compromised-certificate footprint</h1>\
         <p class=\"sum\">Scanned <b>{}</b> files ({:.2} GiB) in {:.1}s</p>\
         <p class=\"sum\"><b class=\"urgent\">{}</b> files contain a compromised intermediate &nbsp;\u{2022}&nbsp; \
         {} only mention eMudhra (ignored)</p>",
        fmt_num(s.files),
        s.bytes as f64 / 1_073_741_824.0,
        s.elapsed,
        fmt_num(s.high as u64),
        fmt_num(references as u64),
    ));

    let cmd_block = |cmds: &[String]| {
        let mut b = String::from("<pre>");
        for c in cmds {
            if c.starts_with('#') {
                b.push_str(&format!("<span class=\"c\">{}</span>\n", html_escape(c)));
            } else {
                b.push_str(&format!("<span class=\"g\">{}</span>\n", html_escape(c)));
            }
        }
        b.push_str("</pre>");
        b
    };

    if !urgent.is_empty() {
        h.push_str("<h2 class=\"urgent\">\u{2460} Contains the compromised certificate</h2>");
        for it in &urgent {
            h.push_str(&format!(
                "<div class=\"kind\"><h3><span class=\"badge b-rm\">{}</span>{}</h3>\
                 <p class=\"sum\">{} file(s) contain the exact certificate</p>{}</div>",
                it.action.label(),
                html_escape(it.kind),
                fmt_num(it.intermediate_files as u64),
                cmd_block(&it.command)
            ));
        }
    }

    if !upgrades.is_empty() {
        let files: usize = upgrades.iter().map(|p| p.files).sum();
        h.push_str(&format!(
            "<h2>\u{2461} Upgrade plan <span class=\"n\">\u{2022} {} files across {} items</span></h2>",
            fmt_num(files as u64),
            upgrades.len()
        ));
        for (kind, items, files) in grouped(&upgrades) {
            let count = if files == 0 {
                format!("{} tool(s)", items.len())
            } else {
                format!("{} files, {} unit(s)", fmt_num(files as u64), items.len())
            };
            let uniform = items.iter().all(|i| i.command == items[0].command);
            h.push_str(&format!(
                "<div class=\"kind\"><h3>{} <span class=\"n\">\u{2022} {}</span></h3>",
                html_escape(kind),
                count
            ));
            if uniform {
                h.push_str(&cmd_block(&items[0].command));
            }
            h.push_str("<ul>");
            for it in &items {
                if uniform {
                    let suffix = if it.files > 0 {
                        format!(" <span class=\"n\">({})</span>", it.files)
                    } else {
                        String::new()
                    };
                    h.push_str(&format!("<li>{}{}</li>", html_escape(&it.unit), suffix));
                } else {
                    h.push_str(&format!(
                        "<li>{}<br><span class=\"g\">{}</span></li>",
                        html_escape(&it.unit),
                        html_escape(&it.command.join(" "))
                    ));
                }
            }
            h.push_str("</ul></div>");
        }
    }

    if !side.is_empty() {
        h.push_str("<h2>\u{2462} Clear / remove</h2>");
        for (kind, items, files) in grouped(&side) {
            h.push_str(&format!(
                "<div class=\"kind\"><h3>{} <span class=\"n\">\u{2022} {} files</span></h3>{}<ul>",
                html_escape(kind),
                fmt_num(files as u64),
                cmd_block(&items[0].command)
            ));
            for it in &items {
                h.push_str(&format!(
                    "<li>{} <span class=\"n\">({})</span></li>",
                    html_escape(&it.unit),
                    it.files
                ));
            }
            h.push_str("</ul></div>");
        }
    }

    h.push_str(
        "<p class=\"legend\">The 8 compromised certificates are TLS/code-signing intermediates; a file \
         &ldquo;contains&rdquo; one only when its exact bytes (or that key&rsquo;s SPKI hash) are present.</p>\
         </body></html>",
    );
    h
}

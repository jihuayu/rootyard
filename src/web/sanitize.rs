//! Security rendering, multi-pass obfuscation-resistant URL validation, HTML/Markdown
//! XSS sanitization, and UTF-8 boundary-safe large/binary blob preview truncation (`F34`).
use crate::web::models::BlobPreview;

pub const DEFAULT_WEB_BLOB_PREVIEW_BYTES: usize = 64 * 1024;
pub const MAX_WEB_BLOB_PREVIEW_BYTES: usize = 256 * 1024;
pub const MIN_WEB_BLOB_PREVIEW_BYTES: usize = 256;
pub const MAX_WEB_BLOB_PREVIEW_LINES: usize = 2_000;
pub const BINARY_HEX_PREVIEW_BYTES: usize = 256;
pub const BINARY_SNIFF_BYTES: usize = 8 * 1024;

const PAIRED_DANGEROUS_TAGS: &[&str] = &[
    "iframe", "object", "applet", "svg", "math", "form", "style", "script", "template", "noscript",
    "frame", "frameset", "portal", "select", "textarea", "button", "option",
];
const VOID_DANGEROUS_TAGS: &[&str] = &[
    "base", "meta", "link", "input", "embed", "param", "source", "track", "area", "keygen",
];
const ALLOWED_TAGS: &[&str] = &[
    "p", "br", "hr", "strong", "b", "em", "i", "code", "pre", "blockquote", "ul", "ol", "li",
    "h1", "h2", "h3", "h4", "h5", "h6", "a", "del", "s", "sub", "sup", "table", "thead", "tbody",
    "tr", "th", "td", "span", "div", "img",
];

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '\0' => {}
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn decode_html_entities_once(input: &str) -> String {
    let (bytes, mut out, mut i) = (input.as_bytes(), String::with_capacity(input.len()), 0);
    while i < bytes.len() {
        if bytes[i] == b'&' {
            let rest = &input[i + 1..];
            if let Some(num_rest) = rest.strip_prefix('#') {
                let (is_hex, digits) = if let Some(h) = num_rest.strip_prefix('x').or_else(|| num_rest.strip_prefix('X')) { (true, h) } else { (false, num_rest) };
                let dlen = digits.bytes().take_while(|b| if is_hex { b.is_ascii_hexdigit() } else { b.is_ascii_digit() }).count();
                if dlen > 0 {
                    let nz = digits[..dlen].trim_start_matches('0');
                    if let Ok(code) = u32::from_str_radix(if nz.is_empty() { "0" } else { nz }, if is_hex { 16 } else { 10 }) {
                        out.push(char::from_u32(code).unwrap_or('\0'));
                        i += 2 + usize::from(is_hex) + dlen + usize::from(digits.as_bytes().get(dlen) == Some(&b';'));
                        continue;
                    }
                }
            } else {
                let alen = rest.bytes().take_while(|b| b.is_ascii_alphanumeric()).count();
                if alen > 0 {
                    let rep = match rest[..alen].to_ascii_lowercase().as_str() {
                        "colon" => Some(':'), "tab" => Some('\t'), "newline" => Some('\n'), "amp" => Some('&'),
                        "lt" => Some('<'), "gt" => Some('>'), "quot" => Some('"'), "apos" => Some('\''),
                        "nbsp" => Some(' '), "sol" => Some('/'), "bsol" => Some('\\'), _ => None,
                    };
                    if let Some(ch) = rep {
                        out.push(ch);
                        i += 1 + alen + usize::from(rest.as_bytes().get(alen) == Some(&b';'));
                        continue;
                    }
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8().max(1);
    }
    out
}

fn decode_percent_once(input: &str) -> String {
    let (bytes, mut raw, mut i) = (input.as_bytes(), Vec::with_capacity(input.len()), 0);
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16)) {
                raw.push(((h1 << 4) | h2) as u8);
                i += 3;
                continue;
            }
        }
        raw.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&raw).into_owned()
}

pub fn sanitize_url(raw_url: &str) -> Option<String> {
    if raw_url.contains('\0') || raw_url.contains('\\') {
        return None;
    }
    let mut trimmed = raw_url.trim();
    if trimmed.len() >= 2 && matches!((trimmed.as_bytes()[0], trimmed.as_bytes()[trimmed.len() - 1]), (b'<', b'>') | (b'"', b'"') | (b'\'', b'\'') | (b'`', b'`')) {
        trimmed = trimmed[1..trimmed.len() - 1].trim();
    }
    if trimmed.is_empty() {
        return None;
    }
    let mut norm = trimmed.to_owned();
    for _ in 0..3 {
        norm = decode_percent_once(&decode_html_entities_once(&norm));
        if norm.contains('\0') || norm.contains('\\') {
            return None;
        }
        norm.retain(|c| (c as u32) > 0x20 && (c as u32) != 0x7f);
    }
    let lower = norm.to_ascii_lowercase();
    if lower.is_empty() || lower.starts_with("//") || lower.starts_with("/\\") {
        return None;
    }
    if ["javascript:", "data:", "vbscript:", "file:", "blob:", "about:", "jar:", "ws:", "wss:"].iter().any(|s| lower.starts_with(s)) {
        return None;
    }
    let first_delim = lower.find(['/', '?', '#']).unwrap_or(lower.len());
    if let Some(colon_pos) = lower[..first_delim].find(':') {
        match &lower[..colon_pos] {
            "http" if lower.starts_with("http://") && lower.len() > 7 => {}
            "https" if lower.starts_with("https://") && lower.len() > 8 => {}
            "mailto" if lower.starts_with("mailto:") && lower.len() > 7 => {}
            _ => return None,
        }
    } else if lower.contains(':') {
        return None;
    }
    let cleaned: String = trimmed.chars().filter(|&c| (c as u32) >= 0x20 && (c as u32) != 0x7f).collect();
    (!cleaned.is_empty() && !cleaned.starts_with("//")).then(|| escape_html(&cleaned))
}

fn is_tag_boundary(b: Option<u8>) -> bool {
    b.is_none_or(|ch| ch <= b' ' || matches!(ch, b'>' | b'/' | b'"' | b'\'' | b'`'))
}

fn strip_paired_dangerous_blocks(input: &str) -> String {
    let mut current = input.to_owned();
    for &tag in PAIRED_DANGEROUS_TAGS {
        let (mut out, lower) = (String::with_capacity(current.len()), current.to_ascii_lowercase());
        let (bytes, open_pat, close_pat) = (lower.as_bytes(), format!("<{tag}"), format!("</{tag}"));
        let mut cursor = 0;
        while cursor < bytes.len() {
            let Some(rel_pos) = lower[cursor..].find(&open_pat) else {
                out.push_str(&current[cursor..]);
                break;
            };
            let (start, after_open) = (cursor + rel_pos, cursor + rel_pos + open_pat.len());
            if !is_tag_boundary(bytes.get(after_open).copied()) {
                out.push_str(&current[cursor..after_open]);
                cursor = after_open;
                continue;
            }
            out.push_str(&current[cursor..start]);
            let line_end = lower[after_open..].find('\n').map_or(bytes.len(), |r| after_open + r);
            if let Some(close_rel) = lower[after_open..].find(&close_pat) {
                let close_start = after_open + close_rel;
                if lower[after_open..close_start].find(&open_pat).is_none() {
                    if let Some(gt_rel) = lower[close_start..].find('>') {
                        cursor = close_start + gt_rel + 1;
                        continue;
                    }
                }
            }
            cursor = line_end;
        }
        current = out;
    }
    current
}

fn extract_attr_value(attrs: &str, target_name: &str) -> Option<String> {
    let (bytes, mut i) = (attrs.as_bytes(), 0);
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] <= b' ' || bytes[i] == b'/') { i += 1; }
        if i >= bytes.len() { break; }
        let ns = i;
        while i < bytes.len() && bytes[i] > b' ' && !matches!(bytes[i], b'=' | b'>' | b'/') { i += 1; }
        let name = attrs[ns..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i] <= b' ' { i += 1; }
        let val = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i] <= b' ' { i += 1; }
            if i >= bytes.len() {
                String::new()
            } else if matches!(bytes[i], b'"' | b'\'' | b'`') {
                let (q, vs) = (bytes[i], i + 1);
                i += 1;
                while i < bytes.len() && bytes[i] != q { i += 1; }
                let v = attrs[vs..i].to_owned();
                if i < bytes.len() { i += 1; }
                v
            } else {
                let vs = i;
                while i < bytes.len() && bytes[i] > b' ' && bytes[i] != b'>' { i += 1; }
                attrs[vs..i].to_owned()
            }
        } else {
            String::new()
        };
        if name == target_name { return Some(val); }
    }
    None
}

pub fn strip_dangerous_html(input: &str) -> String {
    let cleaned = strip_paired_dangerous_blocks(input);
    let (mut out, bytes, mut i) = (String::with_capacity(cleaned.len()), cleaned.as_bytes(), 0);
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let Some(gt_rel) = cleaned[i + 1..].find('>') else { break };
            let raw_tag = cleaned[i + 1..i + 1 + gt_rel].trim();
            i += gt_rel + 2;
            if raw_tag.is_empty() || raw_tag.starts_with('!') || raw_tag.starts_with('?') { continue; }
            let is_closing = raw_tag.starts_with('/');
            let body = if is_closing { raw_tag[1..].trim_start() } else { raw_tag };
            let name_len = body.bytes().take_while(|b| b.is_ascii_alphanumeric()).count();
            if name_len == 0 { continue; }
            let (tag_name, attrs) = (body[..name_len].to_ascii_lowercase(), &body[name_len..]);
            if PAIRED_DANGEROUS_TAGS.contains(&tag_name.as_str()) || VOID_DANGEROUS_TAGS.contains(&tag_name.as_str()) || !ALLOWED_TAGS.contains(&tag_name.as_str()) {
                continue;
            }
            if is_closing {
                if !matches!(tag_name.as_str(), "br" | "hr" | "img") { out.push_str(&format!("</{tag_name}>")); }
                continue;
            }
            match tag_name.as_str() {
                "br" => out.push_str("<br/>"),
                "hr" => out.push_str("<hr/>"),
                "a" => match extract_attr_value(attrs, "href").and_then(|v| sanitize_url(&v)) {
                    Some(h) => out.push_str(&format!("<a href=\"{h}\" rel=\"noopener noreferrer\">")),
                    None => out.push_str("<a>"),
                },
                "img" => {
                    let alt = escape_html(&extract_attr_value(attrs, "alt").unwrap_or_default());
                    match extract_attr_value(attrs, "src").and_then(|v| sanitize_url(&v)).filter(|u| !u.to_ascii_lowercase().starts_with("mailto:")) {
                        Some(src) => out.push_str(&format!("<img src=\"{src}\" alt=\"{alt}\" loading=\"lazy\"/>")),
                        None => out.push_str(&format!("<span class=\"sanitized-image\">{alt}</span>")),
                    }
                }
                "code" => {
                    let lang: String = extract_attr_value(attrs, "data-lang").unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '+')).take(32).collect();
                    if lang.is_empty() { out.push_str("<code>") } else { out.push_str(&format!("<code data-lang=\"{lang}\">")) }
                }
                "pre" => if extract_attr_value(attrs, "class").as_deref() == Some("code-block") { out.push_str("<pre class=\"code-block\">") } else { out.push_str("<pre>") },
                _ => out.push_str(&format!("<{tag_name}>")),
            }
        } else {
            let next_lt = cleaned[i..].find('<').map_or(bytes.len(), |r| i + r);
            for ch in cleaned[i..next_lt].chars() {
                match ch {
                    '\0' => {}
                    '<' => out.push_str("&lt;"),
                    '>' => out.push_str("&gt;"),
                    '"' => out.push_str("&quot;"),
                    '\'' => out.push_str("&#x27;"),
                    _ => out.push(ch),
                }
            }
            i = next_lt;
        }
    }
    out
}

fn find_closing_paren(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' if depth > 0 => depth -= 1,
            b')' => return Some(idx),
            _ => {}
        }
    }
    None
}

fn render_inline_markdown(text: &str) -> String {
    let pre = strip_dangerous_html(text);
    let (mut out, mut rest) = (String::with_capacity(pre.len() + 32), pre.as_str());
    while !rest.is_empty() {
        if let Some(after_tick) = rest.strip_prefix('`') {
            if let Some(end_tick) = after_tick.find('`') {
                out.push_str(&format!("<code>{}</code>", escape_html(&after_tick[..end_tick])));
                rest = &after_tick[end_tick + 1..];
                continue;
            }
        }
        if let Some(after_bang) = rest.strip_prefix("![") {
            if let Some(close_br) = after_bang.find("](") {
                let (alt, url_part) = (&after_bang[..close_br], &after_bang[close_br + 2..]);
                if let Some(cp) = find_closing_paren(url_part) {
                    if let Some(u) = sanitize_url(&url_part[..cp]).filter(|u| !u.to_ascii_lowercase().starts_with("mailto:")) {
                        out.push_str(&format!("<img src=\"{u}\" alt=\"{}\" loading=\"lazy\"/>", escape_html(alt)));
                    } else {
                        out.push_str(&format!("<span class=\"sanitized-image\">{}</span>", escape_html(alt)));
                    }
                    rest = &url_part[cp + 1..];
                    continue;
                }
            }
        }
        if let Some(after_br) = rest.strip_prefix('[') {
            if let Some(close_br) = after_br.find("](") {
                let (label, url_part) = (strip_dangerous_html(&after_br[..close_br]), &after_br[close_br + 2..]);
                if let Some(cp) = find_closing_paren(url_part) {
                    if let Some(u) = sanitize_url(&url_part[..cp]) {
                        out.push_str(&format!("<a href=\"{u}\" rel=\"noopener noreferrer\">{label}</a>"));
                    } else {
                        out.push_str(&format!("<span class=\"sanitized-link\">{label}</span>"));
                    }
                    rest = &url_part[cp + 1..];
                    continue;
                }
            }
        }
        if let Some(after_bold) = rest.strip_prefix("**") {
            if let Some(end_bold) = after_bold.find("**") {
                out.push_str(&format!("<strong>{}</strong>", strip_dangerous_html(&after_bold[..end_bold])));
                rest = &after_bold[end_bold + 2..];
                continue;
            }
        }
        let next_special = rest[1..].find(['`', '!', '[', '*']).map_or(rest.len(), |p| p + 1);
        out.push_str(&rest[..next_special]);
        rest = &rest[next_special..];
    }
    out
}

pub fn render_safe_markdown(markdown: &str) -> String {
    let pre_sanitized = strip_paired_dangerous_blocks(&markdown.replace("\r\n", "\n"));
    let (mut html, mut in_code, mut code_buf, mut code_lang, mut list_tag) = (String::with_capacity(pre_sanitized.len() + 64), false, String::new(), String::new(), None::<&str>);
    for line in pre_sanitized.lines() {
        let trimmed = line.trim_end();
        if let Some(fence_rest) = trimmed.strip_prefix("```") {
            if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
            if in_code {
                html.push_str(&format!("<pre class=\"code-block\"><code data-lang=\"{code_lang}\">{code_buf}</code></pre>\n"));
                code_buf.clear();
                code_lang.clear();
                in_code = false;
            } else {
                code_lang = fence_rest.trim().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '+')).take(32).collect();
                in_code = true;
            }
            continue;
        }
        if in_code {
            code_buf.push_str(&escape_html(line));
            code_buf.push('\n');
            continue;
        }
        let ltrim = trimmed.trim_start();
        if ltrim.is_empty() {
            if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
            continue;
        }
        if matches!(ltrim, "---" | "***" | "___") {
            if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
            html.push_str("<hr/>\n");
            continue;
        }
        let hashes = ltrim.bytes().take_while(|&b| b == b'#').count();
        if (1..=6).contains(&hashes) && ltrim.as_bytes().get(hashes) == Some(&b' ') {
            if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
            html.push_str(&format!("<h{hashes}>{}</h{hashes}>\n", render_inline_markdown(ltrim[hashes + 1..].trim())));
            continue;
        }
        if let Some(quote_body) = ltrim.strip_prefix("> ") {
            if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
            html.push_str(&format!("<blockquote><p>{}</p></blockquote>\n", render_inline_markdown(quote_body)));
            continue;
        }
        if let Some(li_body) = ltrim.strip_prefix("- ").or_else(|| ltrim.strip_prefix("* ")) {
            if list_tag != Some("ul") {
                if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
                html.push_str("<ul>\n");
                list_tag = Some("ul");
            }
            html.push_str(&format!("<li>{}</li>\n", render_inline_markdown(li_body)));
            continue;
        }
        if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
        html.push_str(&format!("<p>{}</p>\n", render_inline_markdown(ltrim)));
    }
    if in_code { html.push_str(&format!("<pre class=\"code-block\"><code data-lang=\"{code_lang}\">{code_buf}</code></pre>\n")); }
    if let Some(lt) = list_tag.take() { html.push_str(&format!("</{lt}>\n")); }
    strip_dangerous_html(&html)
}

pub fn format_binary_hex_preview(bytes: &[u8]) -> String {
    let slice = &bytes[..bytes.len().min(BINARY_HEX_PREVIEW_BYTES)];
    let mut out = String::with_capacity((slice.len() / 16 + 1) * 76);
    for (row_idx, chunk) in slice.chunks(16).enumerate() {
        let hex_col: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii_col: String = chunk.iter().map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' }).collect();
        out.push_str(&format!("{:04x}: {:<47}  |{ascii_col}|\n", row_idx * 16, hex_col.join(" ")));
    }
    out
}

pub fn build_blob_preview(oid: &str, path: &str, total_size: u64, raw_prefix: &[u8], max_bytes: usize) -> BlobPreview {
    let clamped_max = max_bytes.clamp(MIN_WEB_BLOB_PREVIEW_BYTES, MAX_WEB_BLOB_PREVIEW_BYTES);
    let has_nul = raw_prefix[..raw_prefix.len().min(BINARY_SNIFF_BYTES)].contains(&0);
    let byte_truncated = (total_size as usize > clamped_max) || (raw_prefix.len() > clamped_max);
    let candidate = &raw_prefix[..raw_prefix.len().min(clamped_max)];
    let (is_binary, valid_text) = if has_nul {
        (true, None)
    } else {
        match std::str::from_utf8(candidate) {
            Ok(s) => (false, Some(s)),
            Err(err) if err.error_len().is_none() && (byte_truncated || (total_size as usize > candidate.len())) => {
                (false, Some(std::str::from_utf8(&candidate[..err.valid_up_to()]).unwrap_or("")))
            }
            Err(_) => (true, None),
        }
    };
    if is_binary {
        let bin_slice = &raw_prefix[..raw_prefix.len().min(BINARY_HEX_PREVIEW_BYTES)];
        let hex_dump = format_binary_hex_preview(bin_slice);
        let line_count = hex_dump.lines().count();
        return BlobPreview {
            oid: oid.to_owned(), path: path.to_owned(), total_size, preview_bytes: bin_slice.len(),
            is_binary: true, truncated: (total_size as usize) > bin_slice.len(), line_count,
            text_preview: None, rendered_markdown_html: None, hex_preview: Some(hex_dump),
        };
    }
    let raw_str = valid_text.unwrap_or("");
    let (mut final_text, mut line_count, mut lines_truncated) = (String::with_capacity(raw_str.len()), 0, false);
    for (idx, line) in raw_str.split_inclusive('\n').enumerate() {
        if idx >= MAX_WEB_BLOB_PREVIEW_LINES { lines_truncated = true; break; }
        final_text.push_str(line);
        line_count += 1;
    }
    let shown_bytes = final_text.len();
    let truncated = byte_truncated || lines_truncated || (total_size as usize > shown_bytes);
    let lower_path = path.to_ascii_lowercase();
    let rendered_markdown_html = (lower_path.ends_with(".md") || lower_path.ends_with(".markdown")).then(|| render_safe_markdown(&final_text));
    BlobPreview {
        oid: oid.to_owned(), path: path.to_owned(), total_size, preview_bytes: shown_bytes,
        is_binary: false, truncated, line_count, text_preview: Some(final_text),
        rendered_markdown_html, hex_preview: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_script_and_unclosed_tags_stripped() {
        let payload = "<p>Safe</p><script>alert(1)</script><SCRIPT SRC=https://evil/x.js></SCRIPT><iframe srcdoc='<script>alert(1)</script>'></iframe><object data='x'></object><embed src='x'><style>body{display:none}</style><svg onload=alert(1)><circle/></svg><math><mtext><script>alert(1)</script></mtext></math><form action='javascript:alert(1)'><input/></form><base href='https://evil/'><meta http-equiv='refresh' content='0'><link rel='stylesheet' href='https://evil/a.css'><script>unclosed_evil()";
        let rendered = render_safe_markdown(payload);
        let lower = rendered.to_ascii_lowercase();
        for forbidden in ["<script", "<iframe", "<object", "<embed", "<style", "<svg", "<math", "<form", "<base", "<meta", "<link", "onload", "srcdoc", "unclosed_evil"] {
            assert!(!lower.contains(forbidden), "leaked {forbidden} in {rendered}");
        }
        assert!(rendered.contains("Safe"));
    }

    #[test]
    fn test_event_handlers_and_obfuscated_urls_rejected() {
        let html = r#"<div onmouseover="alert(1)" onfocus=`alert(1)` onclick=alert(1) style="width:expression(alert(1))"><img src=x onerror=alert(1) alt="pic"><a href="https://example.com" onclick="evil()">link</a></div>"#;
        let clean = render_safe_markdown(html);
        for attr in ["onmouseover", "onfocus", "onclick", "onerror", "style="] {
            assert!(!clean.to_ascii_lowercase().contains(attr));
        }
        assert!(clean.contains(r#"<a href="https://example.com" rel="noopener noreferrer">link</a>"#));
        for bad in ["javascript:alert(1)", "JAVASCRIPT:alert(1)", "jav&#x09;ascript:alert(1)", "&#106;&#97;vascript:alert(1)", "&#0000106avascript:alert(1)", "&#x6a&#x61vascript:alert(1)", "java%0ascript:alert(1)", "\x01javascript:alert(1)", "javascript&colon;alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox(1)", "file:///etc/passwd", "//evil.example/x.js"] {
            assert_eq!(sanitize_url(bad), None);
        }
    }

    #[test]
    fn test_blob_preview_multibyte_utf8_boundary_and_binary_hex_format() {
        let raw = "你好世界🦀🚀".repeat(60).into_bytes();
        for cut in [256usize, 257, 258, 259, 260, 261] {
            let preview = build_blob_preview(&"a".repeat(40), "docs/readme.md", raw.len() as u64, &raw[..cut], 256);
            assert!(!preview.is_binary && preview.truncated && preview.text_preview.is_some());
        }
        let mut bin = vec![0x89, b'P', b'N', b'G', 0x00, 0xff, 0xfe];
        bin.extend_from_slice(&[0x41; 400]);
        let preview = build_blob_preview(&"b".repeat(40), "logo.png", bin.len() as u64, &bin, 1024);
        assert!(preview.is_binary && preview.truncated && preview.text_preview.is_none());
        assert!(preview.hex_preview.as_deref().unwrap_or("").contains("0000: 89 50 4e 47 00 ff fe"));
    }
}

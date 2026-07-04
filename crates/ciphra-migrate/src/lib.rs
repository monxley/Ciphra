//! Translate a MySQL (`mysqldump`) SQL file into Ciphra-dialect
//! statements — a "light migration" path onto Ciphra.
//!
//! This is a pragmatic transpiler for the common shape of a `mysqldump`
//! file, not a full MySQL parser. It keeps `CREATE TABLE` and `INSERT`,
//! maps MySQL column types onto Ciphra's (`INT`/`REAL`/`TEXT`), strips
//! backtick quoting, engine/charset clauses and `AUTO_INCREMENT`, turns
//! a single-column `KEY`/`UNIQUE` into `CREATE INDEX`, and skips
//! everything else (`SET`, `LOCK TABLES`, `/*!… */`, foreign keys, …)
//! with a note. Everything that survives is fed to the normal Ciphra
//! engine, so the imported database is encrypted at rest like any other.
//!
//! Zero dependencies, and no dependency on the rest of the workspace:
//! the output is plain Ciphra SQL text.

/// The result of translating a dump: ready-to-run Ciphra statements and
/// human-readable notes about anything skipped or approximated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Migration {
    /// Ciphra-dialect statements, in source order.
    pub statements: Vec<String>,
    /// Notes about skipped or lossily-translated constructs.
    pub notes: Vec<String>,
}

impl Migration {
    fn note(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.notes.contains(&message) {
            self.notes.push(message);
        }
    }
}

/// Translate a MySQL dump into Ciphra statements.
pub fn translate(dump: &str) -> Migration {
    let mut out = Migration::default();
    for raw in split_statements(dump) {
        let stmt = raw.trim();
        if stmt.is_empty() {
            continue;
        }
        let upper = leading_words(stmt, 2).to_ascii_uppercase();
        if upper.starts_with("CREATE TABLE") {
            translate_create_table(stmt, &mut out);
        } else if upper.starts_with("INSERT INTO")
            || upper.starts_with("INSERT IGNORE")
            || upper.starts_with("REPLACE INTO")
        {
            translate_insert(stmt, &mut out);
        } else {
            let kind = leading_words(stmt, 2);
            out.note(format!("skipped unsupported statement: {kind} …"));
        }
    }
    out
}

/// The first `n` whitespace-separated words of `s`, space-joined.
fn leading_words(s: &str, n: usize) -> String {
    s.split_whitespace().take(n).collect::<Vec<_>>().join(" ")
}

// --------------------------------------------------- statement splitting

/// Split a dump into top-level `;`-terminated statements, dropping SQL
/// comments (`-- `, `#`, `/* … */`, including `/*!… */`). String and
/// backtick-quoted spans are preserved intact.
fn split_statements(input: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut cur = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            cur.push(b as char);
            if b == b'\\' && q != b'`' && i + 1 < bytes.len() {
                // Escaped char inside a '…' or "…" string.
                cur.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quote = Some(b);
                cur.push(b as char);
                i += 1;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2; // consume the closing */
            }
            b';' => {
                statements.push(std::mem::take(&mut cur));
                i += 1;
            }
            _ => {
                cur.push(input[i..].chars().next().unwrap());
                i += input[i..].chars().next().unwrap().len_utf8();
            }
        }
    }
    if !cur.trim().is_empty() {
        statements.push(cur);
    }
    statements
}

/// Split `s` on top-level occurrences of `sep`: not inside quotes and
/// not nested in parentheses/brackets.
fn top_level_split(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' && q != '`' {
                chars.next(); // skip the escaped char
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            _ if c == sep && depth == 0 => {
                parts.push(s[start..i].to_string());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(s[start..].to_string());
    parts
}

// ------------------------------------------------------ CREATE TABLE

fn translate_create_table(stmt: &str, out: &mut Migration) {
    let Some(open) = find_top_level(stmt, '(') else {
        out.note("skipped a CREATE TABLE with no column list");
        return;
    };
    let Some(close) = matching_paren(stmt, open) else {
        out.note("skipped a malformed CREATE TABLE (unbalanced parentheses)");
        return;
    };
    let head = &stmt[..open];
    let body = &stmt[open + 1..close];

    // Name: last token of the head, minus IF NOT EXISTS and backticks.
    let name_token = head
        .split_whitespace()
        .last()
        .map(unquote_ident)
        .unwrap_or_default();
    if name_token.is_empty() {
        out.note("skipped a CREATE TABLE with no table name");
        return;
    }

    let mut columns: Vec<(String, &'static str)> = Vec::new();
    let mut inline_pk: Option<String> = None;
    let mut declared_pk: Vec<String> = Vec::new();
    let mut secondary_indexes: Vec<String> = Vec::new();

    for part in top_level_split(body, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let upper = part.to_ascii_uppercase();
        if upper.starts_with("PRIMARY KEY") {
            declared_pk = paren_columns(part);
            continue;
        }
        if starts_with_any(
            &upper,
            &[
                "KEY ",
                "KEY(",
                "UNIQUE",
                "INDEX",
                "FULLTEXT",
                "SPATIAL",
                "CONSTRAINT",
                "FOREIGN",
                "CHECK",
            ],
        ) {
            let cols = paren_columns(part);
            if (upper.starts_with("KEY")
                || upper.starts_with("UNIQUE")
                || upper.starts_with("INDEX"))
                && cols.len() == 1
            {
                secondary_indexes.push(cols.into_iter().next().unwrap());
            } else if upper.starts_with("FOREIGN") {
                out.note("skipped a FOREIGN KEY (not enforced by Ciphra)");
            } else if cols.len() > 1 {
                out.note("skipped a multi-column index (single-column only)");
            } else {
                out.note("skipped an unsupported table constraint");
            }
            continue;
        }

        // A column definition: `name` type options…
        let Some((col_name, rest)) = split_first_token(part) else {
            continue;
        };
        let col_name = unquote_ident(&col_name);
        let (ty, note) = map_type(rest);
        if let Some(n) = note {
            out.note(n);
        }
        if rest.to_ascii_uppercase().contains("PRIMARY KEY") {
            inline_pk = Some(col_name.clone());
        }
        columns.push((col_name, ty));
    }

    if columns.is_empty() {
        out.note(format!(
            "skipped table {name_token:?}: no translatable columns"
        ));
        return;
    }

    // Resolve the single primary key Ciphra allows.
    let pk = inline_pk.or_else(|| match declared_pk.len() {
        1 => declared_pk.first().cloned(),
        0 => None,
        _ => {
            out.note(format!(
                "table {name_token:?}: composite PRIMARY KEY dropped (Ciphra supports one column)"
            ));
            None
        }
    });

    let mut col_sql = Vec::with_capacity(columns.len());
    for (name, ty) in &columns {
        if Some(name) == pk.as_ref() {
            col_sql.push(format!("{name} {ty} PRIMARY KEY"));
        } else {
            col_sql.push(format!("{name} {ty}"));
        }
    }
    out.statements.push(format!(
        "CREATE TABLE {name_token} ({})",
        col_sql.join(", ")
    ));

    // Emit a Ciphra index for each single-column secondary key, except
    // the primary key column (already indexed).
    let mut seen = std::collections::HashSet::new();
    for col in secondary_indexes {
        if Some(&col) == pk.as_ref() || !seen.insert(col.clone()) {
            continue;
        }
        if columns.iter().any(|(n, _)| n == &col) {
            out.statements
                .push(format!("CREATE INDEX ON {name_token} ({col})"));
        }
    }
}

/// Map a MySQL column type (the text after the column name) to a Ciphra
/// type, with an optional lossiness note.
fn map_type(spec: &str) -> (&'static str, Option<String>) {
    let word = spec
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match word.as_str() {
        "tinyint" | "smallint" | "mediumint" | "int" | "integer" | "bigint" | "bool"
        | "boolean" => ("INT", None),
        "float" | "double" | "real" => ("REAL", None),
        "decimal" | "numeric" | "dec" | "fixed" => (
            "REAL",
            Some(
                "DECIMAL/NUMERIC mapped to REAL (f64) — exact decimal precision is not kept".into(),
            ),
        ),
        "char" | "varchar" | "tinytext" | "text" | "mediumtext" | "longtext" | "enum" | "set"
        | "date" | "datetime" | "timestamp" | "time" | "year" | "json" => ("TEXT", None),
        "binary" | "varbinary" | "bit" | "blob" | "tinyblob" | "mediumblob" | "longblob" => (
            "TEXT",
            Some(format!(
                "binary type {word:?} mapped to TEXT — binary data may not round-trip"
            )),
        ),
        other => (
            "TEXT",
            Some(format!("unknown type {other:?} mapped to TEXT")),
        ),
    }
}

// ------------------------------------------------------------- INSERT

fn translate_insert(stmt: &str, out: &mut Migration) {
    // Strip the leading INSERT [IGNORE] INTO / REPLACE INTO.
    let after_into = match find_keyword(stmt, "into") {
        Some(pos) => stmt[pos + 4..].trim_start(),
        None => {
            out.note("skipped an INSERT without INTO");
            return;
        }
    };
    let Some((name_tok, rest)) = split_first_token(after_into) else {
        out.note("skipped an INSERT with no table name");
        return;
    };
    let name = unquote_ident(&name_tok);

    // Optional column list before VALUES.
    let Some(values_pos) = find_keyword(rest, "values") else {
        out.note(format!("skipped INSERT into {name:?}: no VALUES"));
        return;
    };
    let head = rest[..values_pos].trim();
    let tail = rest[values_pos + 6..].trim();

    let col_list = if head.starts_with('(') {
        let cols: Vec<String> = paren_columns(head);
        if cols.is_empty() {
            String::new()
        } else {
            format!(" ({})", cols.join(", "))
        }
    } else {
        String::new()
    };

    let mut tuples_sql = Vec::new();
    for group in top_level_split(tail, ',') {
        let group = group.trim();
        if !group.starts_with('(') || !group.ends_with(')') {
            continue;
        }
        let inner = &group[1..group.len() - 1];
        let mut values = Vec::new();
        for value in top_level_split(inner, ',') {
            values.push(translate_value(value.trim(), out));
        }
        tuples_sql.push(format!("({})", values.join(", ")));
    }

    if tuples_sql.is_empty() {
        return;
    }
    out.statements.push(format!(
        "INSERT INTO {name}{col_list} VALUES {}",
        tuples_sql.join(", ")
    ));
}

/// Translate one MySQL value literal into a Ciphra literal.
fn translate_value(tok: &str, out: &mut Migration) -> String {
    if tok.eq_ignore_ascii_case("null") {
        return "NULL".to_string();
    }
    let bytes = tok.as_bytes();
    if bytes.first() == Some(&b'\'') || bytes.first() == Some(&b'"') {
        return ciphra_string(&decode_mysql_string(tok));
    }
    // Numbers (normalize sign and form so the Ciphra lexer accepts them).
    if let Ok(n) = tok.parse::<i64>() {
        return n.to_string();
    }
    if !tok.contains(|c: char| c.is_alphabetic() && c != 'e' && c != 'E')
        && let Ok(x) = tok.parse::<f64>()
        && x.is_finite()
    {
        return format!("{x}");
    }
    // Hex / bit / anything else: keep the text, don't lose data.
    out.note(format!(
        "value {tok:?} kept as text (not a recognized number, string or NULL)"
    ));
    ciphra_string(tok)
}

// ------------------------------------------------------------- helpers

/// Decode a MySQL single- or double-quoted string literal to its value.
fn decode_mysql_string(tok: &str) -> String {
    let quote = tok.chars().next().unwrap();
    let inner = &tok[quote.len_utf8()..tok.len() - quote.len_utf8()];
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('0') => out.push('\0'),
                Some('b') => out.push('\u{08}'),
                Some('Z') => out.push('\u{1a}'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"') => out.push('"'),
                // `\%` and `\_` keep the backslash in MySQL.
                Some('%') => out.push_str("\\%"),
                Some('_') => out.push_str("\\_"),
                Some(other) => out.push(other),
                None => {}
            }
        } else if c == quote {
            // A doubled quote inside the literal is one quote character.
            if chars.peek() == Some(&quote) {
                chars.next();
            }
            out.push(quote);
        } else {
            out.push(c);
        }
    }
    out
}

/// Quote `s` as a Ciphra string literal (`'…'`, single quotes doubled).
fn ciphra_string(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Strip surrounding backticks/quotes and any index-prefix length
/// (`col(255)` → `col`) from an identifier.
fn unquote_ident(s: &str) -> String {
    let mut t = s.trim();
    if let Some(paren) = t.find('(') {
        t = t[..paren].trim();
    }
    let bytes = t.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'`' || first == b'"' || first == b'\'') && last == first {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}

/// The column names inside the first `(…)` group of `s`.
fn paren_columns(s: &str) -> Vec<String> {
    let Some(open) = find_top_level(s, '(') else {
        return Vec::new();
    };
    let Some(close) = matching_paren(s, open) else {
        return Vec::new();
    };
    top_level_split(&s[open + 1..close], ',')
        .iter()
        .map(|c| unquote_ident(c))
        .filter(|c| !c.is_empty())
        .collect()
}

/// Split off the first whitespace-delimited token (respecting a leading
/// backtick/quote), returning `(token, rest)`.
fn split_first_token(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let first = s.chars().next().unwrap();
    if first == '`' || first == '"' {
        // Quoted identifier: read to the closing quote.
        let rest = &s[first.len_utf8()..];
        if let Some(end) = rest.find(first) {
            let token = &s[..first.len_utf8() + end + first.len_utf8()];
            return Some((token.to_string(), &s[token.len()..]));
        }
    }
    let end = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
    Some((s[..end].to_string(), &s[end..]))
}

fn starts_with_any(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

/// Index of the first top-level (not quoted) occurrence of `target`.
fn find_top_level(s: &str, target: char) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' && q != '`' {
                chars.next();
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            _ if c == target => return Some(i),
            _ => {}
        }
    }
    None
}

/// The index of the `)` matching the `(` at `open`.
fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut chars = s[open..].char_indices().peekable();
    while let Some((rel, c)) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' && q != '`' {
                chars.next();
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + rel);
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte index of a top-level whole-word keyword (case-insensitive).
fn find_keyword(s: &str, kw: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    let kw = kw.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && q != b'`' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => quote = Some(b),
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            _ if depth == 0 && lower[i..].starts_with(&kw) => {
                let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
                let after = bytes.get(i + kw.len()).copied();
                let after_ok = after.is_none_or(|c| !is_word_byte(c));
                if before_ok && after_ok {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_a_typical_dump() {
        let dump = r#"
-- MySQL dump 10.13
/*!40101 SET NAMES utf8mb4 */;
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `balance` decimal(10,2) DEFAULT '0.00',
  `bio` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email_idx` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES (1,'alice','a@b.c',9.99,'it\'s me'),(2,'bob',NULL,-3.5,'line1\nline2');
UNLOCK TABLES;
"#;
        let m = translate(dump);
        assert_eq!(
            m.statements,
            vec![
                "CREATE TABLE users (id INT PRIMARY KEY, name TEXT, email TEXT, balance REAL, bio TEXT)"
                    .to_string(),
                "CREATE INDEX ON users (email)".to_string(),
                "INSERT INTO users VALUES (1, 'alice', 'a@b.c', 9.99, 'it''s me'), \
                 (2, 'bob', NULL, -3.5, 'line1\nline2')"
                    .to_string(),
            ]
        );
        // The DECIMAL note is present; DROP/SET/LOCK were skipped.
        assert!(m.notes.iter().any(|n| n.contains("DECIMAL")));
        assert!(m.notes.iter().any(|n| n.contains("skipped")));
    }

    #[test]
    fn column_list_and_composite_pk() {
        let dump = "CREATE TABLE t (a int, b int, c int, PRIMARY KEY (a,b));\
                    INSERT INTO `t` (`a`,`b`,`c`) VALUES (1,2,3);";
        let m = translate(dump);
        assert_eq!(
            m.statements[0],
            "CREATE TABLE t (a INT, b INT, c INT)" // composite PK dropped
        );
        assert_eq!(m.statements[1], "INSERT INTO t (a, b, c) VALUES (1, 2, 3)");
        assert!(m.notes.iter().any(|n| n.contains("composite PRIMARY KEY")));
    }

    #[test]
    fn strings_with_commas_and_quotes_are_not_split() {
        let dump = r#"INSERT INTO t VALUES ('a, b', "c\"d", 'x''y');"#;
        let m = translate(dump);
        assert_eq!(
            m.statements[0],
            r#"INSERT INTO t VALUES ('a, b', 'c"d', 'x''y')"#
        );
    }

    #[test]
    fn number_normalization() {
        let dump = "INSERT INTO t VALUES (+5, 1.50, 2., 1000000);";
        let m = translate(dump);
        assert_eq!(m.statements[0], "INSERT INTO t VALUES (5, 1.5, 2, 1000000)");
    }

    #[test]
    fn unknown_statements_are_skipped_with_notes() {
        let m = translate("USE mydb; ALTER TABLE t ADD COLUMN x int;");
        assert!(m.statements.is_empty());
        assert_eq!(m.notes.len(), 2);
    }
}

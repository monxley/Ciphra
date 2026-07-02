//! Tokenizer for the Ciphra SQL dialect.

use crate::ParseError;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    /// Identifier or keyword (keywords are resolved in the parser,
    /// case-insensitively). Stored lowercased.
    Ident(String),
    Int(i64),
    Str(String),
    Comma,
    LParen,
    RParen,
    Star,
    Semi,
    Minus,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Ident(s) => write!(f, "{s}"),
            Token::Int(n) => write!(f, "{n}"),
            Token::Str(s) => write!(f, "'{s}'"),
            Token::Comma => write!(f, ","),
            Token::LParen => write!(f, "("),
            Token::RParen => write!(f, ")"),
            Token::Star => write!(f, "*"),
            Token::Semi => write!(f, ";"),
            Token::Minus => write!(f, "-"),
            Token::Eq => write!(f, "="),
            Token::Ne => write!(f, "!="),
            Token::Lt => write!(f, "<"),
            Token::Gt => write!(f, ">"),
            Token::Le => write!(f, "<="),
            Token::Ge => write!(f, ">="),
        }
    }
}

pub type LexError = ParseError;

pub(crate) fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                // SQL line comment
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            b';' => {
                tokens.push(Token::Semi);
                i += 1;
            }
            b'-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            b'=' => {
                tokens.push(Token::Eq);
                i += 1;
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::Ne);
                    i += 2;
                } else {
                    return Err(ParseError("expected '=' after '!'".into()));
                }
            }
            b'<' => match bytes.get(i + 1) {
                Some(&b'=') => {
                    tokens.push(Token::Le);
                    i += 2;
                }
                Some(&b'>') => {
                    tokens.push(Token::Ne);
                    i += 2;
                }
                _ => {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            },
            b'>' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            b'\'' => {
                let (s, consumed) = lex_string(&input[i..])?;
                tokens.push(Token::Str(s));
                i += consumed;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let text = &input[start..i];
                let n: i64 = text
                    .parse()
                    .map_err(|_| ParseError(format!("integer literal out of range: {text}")))?;
                tokens.push(Token::Int(n));
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                tokens.push(Token::Ident(input[start..i].to_ascii_lowercase()));
            }
            _ => {
                let ch = input[i..].chars().next().unwrap();
                return Err(ParseError(format!("unexpected character: {ch:?}")));
            }
        }
    }
    Ok(tokens)
}

/// Lex a single-quoted string starting at the opening quote.
/// `''` inside the string is an escaped quote. Returns the unescaped
/// contents and the number of input bytes consumed.
fn lex_string(input: &str) -> Result<(String, usize), ParseError> {
    let bytes = input.as_bytes();
    debug_assert_eq!(bytes[0], b'\'');
    let mut out = String::new();
    let mut i = 1usize;
    loop {
        // Find the next quote; everything before it is literal content.
        let Some(rel) = input[i..].find('\'') else {
            return Err(ParseError("unterminated string literal".into()));
        };
        out.push_str(&input[i..i + rel]);
        i += rel + 1;
        if bytes.get(i) == Some(&b'\'') {
            out.push('\'');
            i += 1;
        } else {
            return Ok((out, i));
        }
    }
}

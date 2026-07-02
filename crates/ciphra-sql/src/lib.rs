//! Ciphra SQL front-end: a hand-written lexer and recursive-descent
//! parser for the v0 dialect.
//!
//! Supported statements:
//!
//! ```sql
//! CREATE TABLE users (id INT, name TEXT, ssn TEXT ENCRYPTED);
//! DROP TABLE users;
//! INSERT INTO users (id, name) VALUES (1, 'alice'), (2, 'bob');
//! SELECT * FROM users WHERE id >= 2;
//! SELECT name, ssn FROM users;
//! DELETE FROM users WHERE name = 'bob';
//! ```
//!
//! The grammar is intentionally small; it grows with the engine rather
//! than ahead of it.

mod lexer;
mod parser;

pub use lexer::LexError;
pub use parser::parse_statements;

/// A parsed SQL statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    CreateTable {
        name: String,
        columns: Vec<ColumnDef>,
    },
    DropTable {
        name: String,
    },
    Insert {
        table: String,
        /// Explicit column list, if given.
        columns: Option<Vec<String>>,
        /// One entry per `(...)` tuple.
        rows: Vec<Vec<Literal>>,
    },
    Select {
        columns: Projection,
        table: String,
        predicate: Option<Predicate>,
    },
    Delete {
        table: String,
        predicate: Option<Predicate>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub ty: DataType,
    /// Marked `ENCRYPTED` in the DDL. In v0 all rows are encrypted at
    /// rest; this flag reserves per-column semantics for the queryable
    /// encryption layers (see ROADMAP.md).
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Int,
    Text,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Int(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    All,
    Columns(Vec<String>),
}

/// A single-column comparison, the only predicate form in v0.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    pub column: String,
    pub op: CmpOp,
    pub value: Literal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl std::fmt::Display for CmpOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CmpOp::Eq => "=",
            CmpOp::Ne => "!=",
            CmpOp::Lt => "<",
            CmpOp::Gt => ">",
            CmpOp::Le => "<=",
            CmpOp::Ge => ">=",
        };
        f.write_str(s)
    }
}

/// Errors from lexing or parsing, with a human-readable message.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(sql: &str) -> Statement {
        let mut stmts = parse_statements(sql).unwrap();
        assert_eq!(stmts.len(), 1, "expected exactly one statement");
        stmts.remove(0)
    }

    #[test]
    fn create_table_with_encrypted_column() {
        let stmt = one("CREATE TABLE users (id INT, name TEXT, ssn TEXT ENCRYPTED);");
        assert_eq!(
            stmt,
            Statement::CreateTable {
                name: "users".into(),
                columns: vec![
                    ColumnDef {
                        name: "id".into(),
                        ty: DataType::Int,
                        encrypted: false
                    },
                    ColumnDef {
                        name: "name".into(),
                        ty: DataType::Text,
                        encrypted: false
                    },
                    ColumnDef {
                        name: "ssn".into(),
                        ty: DataType::Text,
                        encrypted: true
                    },
                ],
            }
        );
    }

    #[test]
    fn insert_multi_row_with_columns() {
        let stmt = one("insert into users (id, name) values (1, 'alice'), (2, 'bo''b');");
        assert_eq!(
            stmt,
            Statement::Insert {
                table: "users".into(),
                columns: Some(vec!["id".into(), "name".into()]),
                rows: vec![
                    vec![Literal::Int(1), Literal::Text("alice".into())],
                    vec![Literal::Int(2), Literal::Text("bo'b".into())],
                ],
            }
        );
    }

    #[test]
    fn select_star_with_predicate() {
        let stmt = one("SELECT * FROM users WHERE id >= -2");
        assert_eq!(
            stmt,
            Statement::Select {
                columns: Projection::All,
                table: "users".into(),
                predicate: Some(Predicate {
                    column: "id".into(),
                    op: CmpOp::Ge,
                    value: Literal::Int(-2),
                }),
            }
        );
    }

    #[test]
    fn select_columns_no_predicate() {
        let stmt = one("SELECT name, ssn FROM users");
        assert_eq!(
            stmt,
            Statement::Select {
                columns: Projection::Columns(vec!["name".into(), "ssn".into()]),
                table: "users".into(),
                predicate: None,
            }
        );
    }

    #[test]
    fn delete_and_drop() {
        assert_eq!(
            one("DELETE FROM users WHERE name <> 'bob'"),
            Statement::Delete {
                table: "users".into(),
                predicate: Some(Predicate {
                    column: "name".into(),
                    op: CmpOp::Ne,
                    value: Literal::Text("bob".into()),
                }),
            }
        );
        assert_eq!(
            one("DROP TABLE users"),
            Statement::DropTable {
                name: "users".into()
            }
        );
    }

    #[test]
    fn multiple_statements() {
        let stmts = parse_statements("CREATE TABLE t (a INT); INSERT INTO t VALUES (1);").unwrap();
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn keywords_are_case_insensitive_identifiers_are_not_keywords() {
        let stmt = one("select A, b from T");
        assert_eq!(
            stmt,
            Statement::Select {
                columns: Projection::Columns(vec!["a".into(), "b".into()]),
                table: "t".into(),
                predicate: None,
            }
        );
    }

    #[test]
    fn errors_are_reported() {
        assert!(parse_statements("SELECT FROM users").is_err());
        assert!(parse_statements("CREATE TABLE ()").is_err());
        assert!(parse_statements("INSERT INTO t VALUES").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE x ! 1").is_err());
        assert!(parse_statements("'unterminated").is_err());
    }
}

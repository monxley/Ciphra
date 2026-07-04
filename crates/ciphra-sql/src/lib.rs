//! Ciphra SQL front-end: a hand-written lexer and recursive-descent
//! parser for the v0 dialect.
//!
//! Supported statements:
//!
//! ```sql
//! CREATE TABLE users (id INT, name TEXT, ssn TEXT ENCRYPTED);
//! DROP TABLE users;
//! INSERT INTO users (id, name) VALUES (1, 'alice'), (2, 'bob');
//! SELECT * FROM users WHERE id >= 2 AND (name = 'bob' OR ssn IS NULL)
//!     ORDER BY id DESC LIMIT 10 OFFSET 5;
//! UPDATE users SET name = 'robert', ssn = NULL WHERE id = 2;
//! DELETE FROM users WHERE NOT name = 'bob';
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
    /// `CREATE [RANGE] INDEX ON table (column)` — an equality index,
    /// or a sealed range index when `range` is set.
    CreateIndex {
        table: String,
        column: String,
        range: bool,
    },
    /// `DROP [RANGE] INDEX ON table (column)`.
    DropIndex {
        table: String,
        column: String,
        range: bool,
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
        predicate: Option<Expr>,
        /// Grouping columns for an aggregate query; empty otherwise.
        group_by: Vec<String>,
        /// Post-aggregation filter over groups (`HAVING`).
        having: Option<HavingExpr>,
        order_by: Option<OrderBy>,
        limit: Option<Limit>,
    },
    Update {
        table: String,
        assignments: Vec<Assignment>,
        predicate: Option<Expr>,
    },
    Delete {
        table: String,
        predicate: Option<Expr>,
    },
    /// `EXPLAIN <select|update|delete>` — describe the access path
    /// without executing the statement.
    Explain(Box<Statement>),
    /// `BEGIN` / `START TRANSACTION` — open a transaction.
    Begin,
    /// `COMMIT` — commit the open transaction atomically.
    Commit,
    /// `ROLLBACK` — discard the open transaction.
    Rollback,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub ty: DataType,
    /// Marked `ENCRYPTED` in the DDL. In v0 all rows are encrypted at
    /// rest; this flag reserves per-column semantics for the queryable
    /// encryption layers (see ROADMAP.md).
    pub encrypted: bool,
    /// Marked `PRIMARY KEY` in the DDL: unique, non-NULL, and backed by
    /// an equality index for point lookups. At most one per table.
    pub primary_key: bool,
    /// Has a secondary equality index. Not column DDL syntax — the
    /// parser always leaves this false; the engine flips it via
    /// `CREATE INDEX` / `DROP INDEX` and persists it in the catalog.
    pub indexed: bool,
    /// Has a sealed range index (`CREATE RANGE INDEX`). Engine-managed,
    /// like `indexed`.
    pub range_indexed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Int,
    /// 64-bit IEEE-754 floating point.
    Real,
    Text,
    /// Fixed-dimension f32 embedding, e.g. `VECTOR(384)`.
    Vector(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Int(i64),
    /// A floating-point literal, e.g. `3.14`.
    Real(f64),
    Text(String),
    /// `[0.1, -2.5, 3]` — components may be written as ints or floats.
    Vector(Vec<f32>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    All,
    Columns(Vec<String>),
    /// A mix of grouping columns and aggregate functions — the shape of
    /// an aggregate query (`SELECT dept, COUNT(*) ... GROUP BY dept`).
    Items(Vec<SelectItem>),
}

/// One item in an aggregate query's projection.
#[derive(Debug, Clone, PartialEq)]
pub enum SelectItem {
    /// A bare column — must appear in `GROUP BY`.
    Column(String),
    /// An aggregate function over the group.
    Aggregate { func: AggFunc, arg: AggArg },
}

/// Supported aggregate functions. `AVG` is intentionally absent until a
/// non-integer numeric type exists (its result is generally fractional).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggFunc {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

/// The argument of an aggregate: `*` (only for `COUNT`) or a column.
#[derive(Debug, Clone, PartialEq)]
pub enum AggArg {
    Star,
    Column(String),
}

/// A `HAVING` predicate: like [`Expr`] but its comparison operands are
/// aggregates or grouping columns rather than plain row columns.
#[derive(Debug, Clone, PartialEq)]
pub enum HavingExpr {
    Compare {
        term: HavingTerm,
        op: CmpOp,
        value: Literal,
    },
    Not(Box<HavingExpr>),
    And(Box<HavingExpr>, Box<HavingExpr>),
    Or(Box<HavingExpr>, Box<HavingExpr>),
}

/// The left-hand operand of a `HAVING` comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum HavingTerm {
    /// A grouping column (must appear in `GROUP BY`).
    Column(String),
    /// An aggregate over the group.
    Aggregate { func: AggFunc, arg: AggArg },
}

impl AggFunc {
    /// The canonical name used in output column headers.
    pub fn name(self) -> &'static str {
        match self {
            AggFunc::Count => "COUNT",
            AggFunc::Sum => "SUM",
            AggFunc::Avg => "AVG",
            AggFunc::Min => "MIN",
            AggFunc::Max => "MAX",
        }
    }
}

/// One `column = literal` pair in an `UPDATE ... SET` list.
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub column: String,
    pub value: Literal,
}

/// A `WHERE` expression. Comparisons follow SQL three-valued logic:
/// any comparison with NULL is *unknown*, and only rows for which the
/// whole expression is *true* match.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Compare {
        column: String,
        op: CmpOp,
        value: Literal,
    },
    IsNull {
        column: String,
        negated: bool,
    },
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl std::fmt::Display for Literal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Literal::Null => write!(f, "NULL"),
            Literal::Int(n) => write!(f, "{n}"),
            Literal::Real(x) => write!(f, "{x}"),
            Literal::Text(s) => write!(f, "'{}'", s.replace('\'', "''")),
            Literal::Vector(v) => {
                write!(f, "[")?;
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{x}")?;
                }
                write!(f, "]")
            }
        }
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Compare { column, op, value } => write!(f, "{column} {op} {value}"),
            Expr::IsNull { column, negated } => {
                write!(f, "{column} IS {}NULL", if *negated { "NOT " } else { "" })
            }
            Expr::Not(inner) => write!(f, "NOT ({inner})"),
            Expr::And(a, b) => write!(f, "({a} AND {b})"),
            Expr::Or(a, b) => write!(f, "({a} OR {b})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrderBy {
    pub column: String,
    pub descending: bool,
    /// `ORDER BY col NEAREST TO [..]`: sort by cosine distance to this
    /// query vector, nearest first. Mutually exclusive with ASC/DESC.
    pub nearest_to: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub count: u64,
    pub offset: u64,
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

    fn cmp(column: &str, op: CmpOp, value: Literal) -> Expr {
        Expr::Compare {
            column: column.into(),
            op,
            value,
        }
    }

    #[test]
    fn create_table_with_column_markers() {
        let stmt = one("CREATE TABLE users (id INT PRIMARY KEY, name TEXT, ssn TEXT ENCRYPTED);");
        assert_eq!(
            stmt,
            Statement::CreateTable {
                name: "users".into(),
                columns: vec![
                    ColumnDef {
                        name: "id".into(),
                        ty: DataType::Int,
                        encrypted: false,
                        primary_key: true,
                        indexed: false,
                        range_indexed: false,
                    },
                    ColumnDef {
                        name: "name".into(),
                        ty: DataType::Text,
                        encrypted: false,
                        primary_key: false,
                        indexed: false,
                        range_indexed: false,
                    },
                    ColumnDef {
                        name: "ssn".into(),
                        ty: DataType::Text,
                        encrypted: true,
                        primary_key: false,
                        indexed: false,
                        range_indexed: false,
                    },
                ],
            }
        );
        // Markers compose in any order.
        let stmt = one("CREATE TABLE t (k TEXT ENCRYPTED PRIMARY KEY)");
        let Statement::CreateTable { columns, .. } = stmt else {
            unreachable!()
        };
        assert!(columns[0].encrypted && columns[0].primary_key);
        // PRIMARY without KEY is an error.
        assert!(parse_statements("CREATE TABLE t (k INT PRIMARY)").is_err());
    }

    #[test]
    fn create_and_drop_index() {
        assert_eq!(
            one("CREATE INDEX ON users (name)"),
            Statement::CreateIndex {
                table: "users".into(),
                column: "name".into(),
                range: false,
            }
        );
        assert_eq!(
            one("drop index on users (name);"),
            Statement::DropIndex {
                table: "users".into(),
                column: "name".into(),
                range: false,
            }
        );
        assert_eq!(
            one("CREATE RANGE INDEX ON users (age)"),
            Statement::CreateIndex {
                table: "users".into(),
                column: "age".into(),
                range: true,
            }
        );
        assert_eq!(
            one("DROP RANGE INDEX ON users (age)"),
            Statement::DropIndex {
                table: "users".into(),
                column: "age".into(),
                range: true,
            }
        );
        assert!(parse_statements("CREATE RANGE TABLE t (a INT)").is_err());
        assert!(parse_statements("CREATE INDEX users (name)").is_err());
        assert!(parse_statements("CREATE INDEX ON users ()").is_err());
        assert!(parse_statements("CREATE INDEX ON users (a, b)").is_err());
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
                predicate: Some(cmp("id", CmpOp::Ge, Literal::Int(-2))),
                group_by: vec![],

                having: None,
                order_by: None,
                limit: None,
            }
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // a = 1 OR b = 2 AND c = 3  ==  a = 1 OR (b = 2 AND c = 3)
        let stmt = one("SELECT * FROM t WHERE a = 1 OR b = 2 AND c = 3");
        let Statement::Select {
            predicate: Some(expr),
            ..
        } = stmt
        else {
            panic!("expected a select with a predicate");
        };
        assert_eq!(
            expr,
            Expr::Or(
                Box::new(cmp("a", CmpOp::Eq, Literal::Int(1))),
                Box::new(Expr::And(
                    Box::new(cmp("b", CmpOp::Eq, Literal::Int(2))),
                    Box::new(cmp("c", CmpOp::Eq, Literal::Int(3))),
                )),
            )
        );
    }

    #[test]
    fn parentheses_override_precedence() {
        let stmt = one("SELECT * FROM t WHERE (a = 1 OR b = 2) AND c = 3");
        let Statement::Select {
            predicate: Some(expr),
            ..
        } = stmt
        else {
            panic!("expected a select with a predicate");
        };
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Or(
                    Box::new(cmp("a", CmpOp::Eq, Literal::Int(1))),
                    Box::new(cmp("b", CmpOp::Eq, Literal::Int(2))),
                )),
                Box::new(cmp("c", CmpOp::Eq, Literal::Int(3))),
            )
        );
    }

    #[test]
    fn not_and_is_null() {
        let stmt = one("SELECT * FROM t WHERE NOT a IS NULL AND b IS NOT NULL");
        let Statement::Select {
            predicate: Some(expr),
            ..
        } = stmt
        else {
            panic!("expected a select with a predicate");
        };
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Not(Box::new(Expr::IsNull {
                    column: "a".into(),
                    negated: false
                }))),
                Box::new(Expr::IsNull {
                    column: "b".into(),
                    negated: true
                }),
            )
        );
    }

    #[test]
    fn order_by_limit_offset() {
        let stmt = one("SELECT name FROM t ORDER BY id DESC LIMIT 10 OFFSET 5");
        assert_eq!(
            stmt,
            Statement::Select {
                columns: Projection::Columns(vec!["name".into()]),
                table: "t".into(),
                predicate: None,
                group_by: vec![],

                having: None,
                order_by: Some(OrderBy {
                    column: "id".into(),
                    descending: true,
                    nearest_to: None,
                }),
                limit: Some(Limit {
                    count: 10,
                    offset: 5
                }),
            }
        );
        let stmt = one("SELECT * FROM t ORDER BY id ASC");
        let Statement::Select {
            order_by, limit, ..
        } = stmt
        else {
            unreachable!()
        };
        assert_eq!(
            order_by,
            Some(OrderBy {
                column: "id".into(),
                descending: false,
                nearest_to: None,
            })
        );
        assert_eq!(limit, None);
    }

    #[test]
    fn update_statement() {
        let stmt = one("UPDATE users SET name = 'robert', ssn = NULL WHERE id = 2");
        assert_eq!(
            stmt,
            Statement::Update {
                table: "users".into(),
                assignments: vec![
                    Assignment {
                        column: "name".into(),
                        value: Literal::Text("robert".into())
                    },
                    Assignment {
                        column: "ssn".into(),
                        value: Literal::Null
                    },
                ],
                predicate: Some(cmp("id", CmpOp::Eq, Literal::Int(2))),
            }
        );
    }

    #[test]
    fn delete_and_drop() {
        assert_eq!(
            one("DELETE FROM users WHERE name <> 'bob'"),
            Statement::Delete {
                table: "users".into(),
                predicate: Some(cmp("name", CmpOp::Ne, Literal::Text("bob".into()))),
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
    fn keywords_are_case_insensitive() {
        let stmt = one("select A, b from T order by A desc limit 1");
        let Statement::Select {
            columns, order_by, ..
        } = stmt
        else {
            unreachable!()
        };
        assert_eq!(columns, Projection::Columns(vec!["a".into(), "b".into()]));
        assert_eq!(
            order_by,
            Some(OrderBy {
                column: "a".into(),
                descending: true,
                nearest_to: None,
            })
        );
    }

    #[test]
    fn parses_aggregates_and_group_by() {
        let stmt = one("SELECT dept, COUNT(*), SUM(salary) FROM emp GROUP BY dept");
        let Statement::Select {
            columns, group_by, ..
        } = stmt
        else {
            unreachable!()
        };
        assert_eq!(group_by, vec!["dept".to_string()]);
        assert_eq!(
            columns,
            Projection::Items(vec![
                SelectItem::Column("dept".into()),
                SelectItem::Aggregate {
                    func: AggFunc::Count,
                    arg: AggArg::Star
                },
                SelectItem::Aggregate {
                    func: AggFunc::Sum,
                    arg: AggArg::Column("salary".into())
                },
            ])
        );

        // A bare aggregate with no GROUP BY is still an Items projection.
        let stmt = one("SELECT MIN(x), MAX(x) FROM t");
        let Statement::Select {
            columns, group_by, ..
        } = stmt
        else {
            unreachable!()
        };
        assert!(group_by.is_empty());
        assert!(matches!(columns, Projection::Items(items) if items.len() == 2));

        // `count` as a plain column name (no parens) stays a column.
        let stmt = one("SELECT count FROM t");
        let Statement::Select { columns, .. } = stmt else {
            unreachable!()
        };
        assert_eq!(columns, Projection::Columns(vec!["count".into()]));
    }

    #[test]
    fn parses_transaction_control() {
        assert_eq!(one("BEGIN"), Statement::Begin);
        assert_eq!(one("BEGIN TRANSACTION"), Statement::Begin);
        assert_eq!(one("START TRANSACTION"), Statement::Begin);
        assert_eq!(one("COMMIT"), Statement::Commit);
        assert_eq!(one("COMMIT WORK"), Statement::Commit);
        assert_eq!(one("ROLLBACK"), Statement::Rollback);
        assert!(parse_statements("START").is_err()); // START needs TRANSACTION
    }

    #[test]
    fn aggregate_parse_errors() {
        assert!(parse_statements("SELECT SUM(*) FROM t").is_err());
        assert!(parse_statements("SELECT * FROM t GROUP BY a").is_err());
        assert!(parse_statements("SELECT COUNT( FROM t").is_err());
    }

    #[test]
    fn parses_having() {
        let stmt = one(
            "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 1 AND dept = 'eng'",
        );
        let Statement::Select { having, .. } = stmt else {
            unreachable!()
        };
        assert_eq!(
            having,
            Some(HavingExpr::And(
                Box::new(HavingExpr::Compare {
                    term: HavingTerm::Aggregate {
                        func: AggFunc::Count,
                        arg: AggArg::Star
                    },
                    op: CmpOp::Gt,
                    value: Literal::Int(1),
                }),
                Box::new(HavingExpr::Compare {
                    term: HavingTerm::Column("dept".into()),
                    op: CmpOp::Eq,
                    value: Literal::Text("eng".into()),
                }),
            ))
        );

        // HAVING keeps the aggregate projection even without GROUP BY.
        let stmt = one("SELECT COUNT(*) FROM t HAVING COUNT(*) > 0");
        let Statement::Select {
            columns, having, ..
        } = stmt
        else {
            unreachable!()
        };
        assert!(having.is_some());
        assert!(matches!(columns, Projection::Items(_)));
    }

    #[test]
    fn errors_are_reported() {
        assert!(parse_statements("SELECT FROM users").is_err());
        assert!(parse_statements("CREATE TABLE ()").is_err());
        assert!(parse_statements("INSERT INTO t VALUES").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE x ! 1").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE (a = 1").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE a = 1 AND").is_err());
        assert!(parse_statements("SELECT * FROM t WHERE a IS 1").is_err());
        assert!(parse_statements("SELECT * FROM t LIMIT -1").is_err());
        assert!(parse_statements("SELECT * FROM t ORDER id").is_err());
        assert!(parse_statements("UPDATE t SET").is_err());
        assert!(parse_statements("UPDATE t SET a 1").is_err());
        assert!(parse_statements("'unterminated").is_err());
    }
}

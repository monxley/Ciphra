//! Recursive-descent parser for the Ciphra SQL dialect.

use crate::lexer::{Token, tokenize};
use crate::{
    AggArg, AggFunc, Assignment, CmpOp, ColumnDef, DataType, Expr, Limit, Literal, OrderBy,
    ParseError, Projection, SelectItem, Statement,
};

/// Parse zero or more `;`-separated statements.
pub fn parse_statements(input: &str) -> Result<Vec<Statement>, ParseError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser { tokens, pos: 0 };
    let mut statements = Vec::new();
    loop {
        while parser.eat(&Token::Semi) {}
        if parser.at_end() {
            return Ok(statements);
        }
        statements.push(parser.statement()?);
        if !parser.at_end() && !parser.check(&Token::Semi) {
            return Err(parser.unexpected("';' or end of input"));
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn statement(&mut self) -> Result<Statement, ParseError> {
        let kw = self.keyword("a statement keyword")?;
        match kw.as_str() {
            "create" if self.eat_keyword("index") => self.index_target(true, false),
            "create" if self.eat_keyword("range") => {
                self.expect_keyword("index")?;
                self.index_target(true, true)
            }
            "create" => self.create_table(),
            "drop" if self.eat_keyword("index") => self.index_target(false, false),
            "drop" if self.eat_keyword("range") => {
                self.expect_keyword("index")?;
                self.index_target(false, true)
            }
            "drop" => self.drop_table(),
            "insert" => self.insert(),
            "select" => self.select(),
            "update" => self.update(),
            "delete" => self.delete(),
            "explain" => {
                let inner = self.statement()?;
                match inner {
                    Statement::Select { .. }
                    | Statement::Update { .. }
                    | Statement::Delete { .. } => Ok(Statement::Explain(Box::new(inner))),
                    _ => Err(ParseError(
                        "EXPLAIN supports SELECT, UPDATE and DELETE".into(),
                    )),
                }
            }
            other => Err(ParseError(format!("unknown statement: {other:?}"))),
        }
    }

    /// `... [RANGE] INDEX ON table (column)` for both CREATE and DROP.
    fn index_target(&mut self, create: bool, range: bool) -> Result<Statement, ParseError> {
        self.expect_keyword("on")?;
        let table = self.identifier("table name")?;
        self.expect(&Token::LParen)?;
        let column = self.identifier("column name")?;
        self.expect(&Token::RParen)?;
        Ok(if create {
            Statement::CreateIndex {
                table,
                column,
                range,
            }
        } else {
            Statement::DropIndex {
                table,
                column,
                range,
            }
        })
    }

    fn create_table(&mut self) -> Result<Statement, ParseError> {
        self.expect_keyword("table")?;
        let name = self.identifier("table name")?;
        self.expect(&Token::LParen)?;
        let mut columns = Vec::new();
        loop {
            let col_name = self.identifier("column name")?;
            let ty = match self
                .keyword("a column type (INT, TEXT or VECTOR)")?
                .as_str()
            {
                "int" | "integer" => DataType::Int,
                "real" | "float" | "double" => DataType::Real,
                "text" | "varchar" => DataType::Text,
                "vector" => {
                    self.expect(&Token::LParen)?;
                    let dim = self.unsigned("a vector dimension")?;
                    self.expect(&Token::RParen)?;
                    if dim == 0 || dim > 4096 {
                        return Err(ParseError(format!(
                            "vector dimension must be 1..=4096, got {dim}"
                        )));
                    }
                    DataType::Vector(dim as u16)
                }
                other => return Err(ParseError(format!("unknown column type: {other:?}"))),
            };
            let mut encrypted = false;
            let mut primary_key = false;
            loop {
                if self.eat_keyword("encrypted") {
                    encrypted = true;
                } else if self.eat_keyword("primary") {
                    self.expect_keyword("key")?;
                    primary_key = true;
                } else {
                    break;
                }
            }
            columns.push(ColumnDef {
                name: col_name,
                ty,
                encrypted,
                primary_key,
                indexed: false,
                range_indexed: false,
            });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen)?;
        Ok(Statement::CreateTable { name, columns })
    }

    fn drop_table(&mut self) -> Result<Statement, ParseError> {
        self.expect_keyword("table")?;
        let name = self.identifier("table name")?;
        Ok(Statement::DropTable { name })
    }

    fn insert(&mut self) -> Result<Statement, ParseError> {
        self.expect_keyword("into")?;
        let table = self.identifier("table name")?;
        let columns = if self.eat(&Token::LParen) {
            let mut cols = vec![self.identifier("column name")?];
            while self.eat(&Token::Comma) {
                cols.push(self.identifier("column name")?);
            }
            self.expect(&Token::RParen)?;
            Some(cols)
        } else {
            None
        };
        self.expect_keyword("values")?;
        let mut rows = vec![self.value_tuple()?];
        while self.eat(&Token::Comma) {
            rows.push(self.value_tuple()?);
        }
        Ok(Statement::Insert {
            table,
            columns,
            rows,
        })
    }

    fn value_tuple(&mut self) -> Result<Vec<Literal>, ParseError> {
        self.expect(&Token::LParen)?;
        let mut values = vec![self.literal()?];
        while self.eat(&Token::Comma) {
            values.push(self.literal()?);
        }
        self.expect(&Token::RParen)?;
        Ok(values)
    }

    fn select(&mut self) -> Result<Statement, ParseError> {
        let (mut columns, has_aggregate) = if self.eat(&Token::Star) {
            (Projection::All, false)
        } else {
            let mut items = vec![self.select_item()?];
            while self.eat(&Token::Comma) {
                items.push(self.select_item()?);
            }
            let has_aggregate = items
                .iter()
                .any(|it| matches!(it, SelectItem::Aggregate { .. }));
            (Projection::Items(items), has_aggregate)
        };
        self.expect_keyword("from")?;
        let table = self.identifier("table name")?;
        let predicate = self.optional_where()?;

        let mut group_by = Vec::new();
        if self.eat_keyword("group") {
            self.expect_keyword("by")?;
            group_by.push(self.identifier("column name")?);
            while self.eat(&Token::Comma) {
                group_by.push(self.identifier("column name")?);
            }
        }

        // Collapse a plain column projection with no grouping back to the
        // simple form the non-aggregate executor path expects.
        if !has_aggregate
            && group_by.is_empty()
            && let Projection::Items(items) = &columns
        {
            let plain: Vec<String> = items
                .iter()
                .map(|it| match it {
                    SelectItem::Column(name) => name.clone(),
                    SelectItem::Aggregate { .. } => unreachable!(),
                })
                .collect();
            columns = Projection::Columns(plain);
        }
        if matches!(columns, Projection::All) && !group_by.is_empty() {
            return Err(ParseError(
                "SELECT * cannot be combined with GROUP BY; list the grouping columns".into(),
            ));
        }

        let order_by = if self.eat_keyword("order") {
            self.expect_keyword("by")?;
            let column = self.identifier("column name")?;
            if self.eat_keyword("nearest") {
                self.expect_keyword("to")?;
                let query = match self.literal()? {
                    Literal::Vector(v) => v,
                    other => {
                        return Err(ParseError(format!(
                            "NEAREST TO takes a vector literal, found {other}"
                        )));
                    }
                };
                Some(OrderBy {
                    column,
                    descending: false,
                    nearest_to: Some(query),
                })
            } else {
                let descending = if self.eat_keyword("desc") {
                    true
                } else {
                    self.eat_keyword("asc");
                    false
                };
                Some(OrderBy {
                    column,
                    descending,
                    nearest_to: None,
                })
            }
        } else {
            None
        };

        let limit = if self.eat_keyword("limit") {
            let count = self.unsigned("a row count after LIMIT")?;
            let offset = if self.eat_keyword("offset") {
                self.unsigned("a row count after OFFSET")?
            } else {
                0
            };
            Some(Limit { count, offset })
        } else {
            None
        };

        Ok(Statement::Select {
            columns,
            table,
            predicate,
            group_by,
            order_by,
            limit,
        })
    }

    /// One projected item: `func(*|col)` for an aggregate, else a column.
    fn select_item(&mut self) -> Result<SelectItem, ParseError> {
        if let Some(func) = self.peek_aggregate() {
            self.pos += 1; // function name
            self.expect(&Token::LParen)?;
            let arg = if self.eat(&Token::Star) {
                if func != AggFunc::Count {
                    return Err(ParseError(format!(
                        "{}(*) is not allowed; {} needs a column",
                        func.name(),
                        func.name()
                    )));
                }
                AggArg::Star
            } else {
                AggArg::Column(self.identifier("a column inside the aggregate")?)
            };
            self.expect(&Token::RParen)?;
            Ok(SelectItem::Aggregate { func, arg })
        } else {
            Ok(SelectItem::Column(self.identifier("column name")?))
        }
    }

    /// If the next tokens are `agg (`, return the aggregate function.
    fn peek_aggregate(&self) -> Option<AggFunc> {
        let Some(Token::Ident(name)) = self.peek() else {
            return None;
        };
        let func = match name.as_str() {
            "count" => AggFunc::Count,
            "sum" => AggFunc::Sum,
            "avg" => AggFunc::Avg,
            "min" => AggFunc::Min,
            "max" => AggFunc::Max,
            _ => return None,
        };
        match self.tokens.get(self.pos + 1) {
            Some(Token::LParen) => Some(func),
            _ => None,
        }
    }

    fn update(&mut self) -> Result<Statement, ParseError> {
        let table = self.identifier("table name")?;
        self.expect_keyword("set")?;
        let mut assignments = vec![self.assignment()?];
        while self.eat(&Token::Comma) {
            assignments.push(self.assignment()?);
        }
        let predicate = self.optional_where()?;
        Ok(Statement::Update {
            table,
            assignments,
            predicate,
        })
    }

    fn assignment(&mut self) -> Result<Assignment, ParseError> {
        let column = self.identifier("column name")?;
        self.expect(&Token::Eq)?;
        let value = self.literal()?;
        Ok(Assignment { column, value })
    }

    fn delete(&mut self) -> Result<Statement, ParseError> {
        self.expect_keyword("from")?;
        let table = self.identifier("table name")?;
        let predicate = self.optional_where()?;
        Ok(Statement::Delete { table, predicate })
    }

    fn optional_where(&mut self) -> Result<Option<Expr>, ParseError> {
        if !self.eat_keyword("where") {
            return Ok(None);
        }
        Ok(Some(self.expr()?))
    }

    // -- expressions: OR < AND < NOT < primary --------------------------

    fn expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and_expr()?;
        while self.eat_keyword("or") {
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.not_expr()?;
        while self.eat_keyword("and") {
            let right = self.not_expr()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not_expr(&mut self) -> Result<Expr, ParseError> {
        if self.eat_keyword("not") {
            Ok(Expr::Not(Box::new(self.not_expr()?)))
        } else {
            self.primary_expr()
        }
    }

    fn primary_expr(&mut self) -> Result<Expr, ParseError> {
        if self.eat(&Token::LParen) {
            let inner = self.expr()?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        let column = self.identifier("a column name")?;
        if self.eat_keyword("is") {
            let negated = self.eat_keyword("not");
            self.expect_keyword("null")?;
            return Ok(Expr::IsNull { column, negated });
        }
        let op = match self.next("a comparison operator")? {
            Token::Eq => CmpOp::Eq,
            Token::Ne => CmpOp::Ne,
            Token::Lt => CmpOp::Lt,
            Token::Gt => CmpOp::Gt,
            Token::Le => CmpOp::Le,
            Token::Ge => CmpOp::Ge,
            other => {
                return Err(ParseError(format!(
                    "expected a comparison operator, found {other}"
                )));
            }
        };
        let value = self.literal()?;
        Ok(Expr::Compare { column, op, value })
    }

    fn literal(&mut self) -> Result<Literal, ParseError> {
        match self.next("a literal")? {
            Token::Int(n) => Ok(Literal::Int(n)),
            Token::Str(s) => Ok(Literal::Text(s)),
            Token::LBracket => {
                let mut components = vec![self.vector_component()?];
                while self.eat(&Token::Comma) {
                    components.push(self.vector_component()?);
                }
                self.expect(&Token::RBracket)?;
                Ok(Literal::Vector(components))
            }
            Token::Float(x) => Ok(Literal::Real(x)),
            Token::Minus => match self.next("a number")? {
                Token::Int(n) => Ok(Literal::Int(-n)),
                Token::Float(x) => Ok(Literal::Real(-x)),
                other => Err(ParseError(format!(
                    "expected a number after '-', found {other}"
                ))),
            },
            Token::Ident(kw) if kw == "null" => Ok(Literal::Null),
            other => Err(ParseError(format!("expected a literal, found {other}"))),
        }
    }

    /// One number inside a `[...]` vector literal.
    fn vector_component(&mut self) -> Result<f32, ParseError> {
        let negative = self.eat(&Token::Minus);
        let magnitude = match self.next("a number")? {
            Token::Int(n) => n as f32,
            Token::Float(x) => x as f32,
            other => {
                return Err(ParseError(format!(
                    "expected a number in a vector literal, found {other}"
                )));
            }
        };
        Ok(if negative { -magnitude } else { magnitude })
    }

    fn unsigned(&mut self, expected: &str) -> Result<u64, ParseError> {
        match self.next(expected)? {
            Token::Int(n) if n >= 0 => Ok(n as u64),
            other => Err(ParseError(format!(
                "expected a non-negative integer ({expected}), found {other}"
            ))),
        }
    }

    // -- token helpers -------------------------------------------------

    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self, expected: &str) -> Result<Token, ParseError> {
        let token = self
            .tokens
            .get(self.pos)
            .cloned()
            .ok_or_else(|| ParseError(format!("expected {expected}, found end of input")))?;
        self.pos += 1;
        Ok(token)
    }

    fn check(&self, token: &Token) -> bool {
        self.peek() == Some(token)
    }

    fn eat(&mut self, token: &Token) -> bool {
        if self.check(token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &Token) -> Result<(), ParseError> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(self.unexpected(&format!("'{token}'")))
        }
    }

    /// Consume any identifier-shaped token and return it (lowercased).
    fn keyword(&mut self, expected: &str) -> Result<String, ParseError> {
        match self.next(expected)? {
            Token::Ident(s) => Ok(s),
            other => Err(ParseError(format!("expected {expected}, found {other}"))),
        }
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<(), ParseError> {
        let found = self.keyword(&format!("keyword {}", kw.to_uppercase()))?;
        if found == kw {
            Ok(())
        } else {
            Err(ParseError(format!(
                "expected keyword {}, found {found:?}",
                kw.to_uppercase()
            )))
        }
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        if let Some(Token::Ident(s)) = self.peek()
            && s == kw
        {
            self.pos += 1;
            return true;
        }
        false
    }

    fn identifier(&mut self, expected: &str) -> Result<String, ParseError> {
        self.keyword(expected)
    }

    fn unexpected(&self, expected: &str) -> ParseError {
        match self.peek() {
            Some(token) => ParseError(format!("expected {expected}, found {token}")),
            None => ParseError(format!("expected {expected}, found end of input")),
        }
    }
}

//! Binary codecs for schemas and rows. Hand-rolled and versioned so the
//! on-disk format is fully under our control from day one.

use crate::{EngineError, Result, Value};
use ciphra_sql::{ColumnDef, DataType};

// v2: the table name moved inside the (sealed) schema record, so no
// plaintext table names remain anywhere on disk.
const SCHEMA_VERSION: u8 = 2;

const TAG_NULL: u8 = 0;
const TAG_INT: u8 = 1;
const TAG_TEXT: u8 = 2;

/// Table schema as stored in the catalog.
#[derive(Debug, Clone, PartialEq)]
pub struct TableSchema {
    pub name: String,
    pub columns: Vec<ColumnDef>,
}

impl TableSchema {
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }
}

/// Schema layout: `version (1) | name_len (2 LE) | name | ncols (2 LE)`
/// then per column: `flags (1) | type (1) | name_len (2 LE) | name`.
pub fn encode_schema(schema: &TableSchema) -> Vec<u8> {
    let mut out = vec![SCHEMA_VERSION];
    out.extend_from_slice(&(schema.name.len() as u16).to_le_bytes());
    out.extend_from_slice(schema.name.as_bytes());
    out.extend_from_slice(&(schema.columns.len() as u16).to_le_bytes());
    for col in &schema.columns {
        out.push(u8::from(col.encrypted));
        out.push(match col.ty {
            DataType::Int => TAG_INT,
            DataType::Text => TAG_TEXT,
        });
        out.extend_from_slice(&(col.name.len() as u16).to_le_bytes());
        out.extend_from_slice(col.name.as_bytes());
    }
    out
}

pub fn decode_schema(buf: &[u8]) -> Result<TableSchema> {
    let corrupt = || EngineError::Corrupt("bad schema record in catalog".into());
    if buf.len() < 5 || buf[0] != SCHEMA_VERSION {
        return Err(corrupt());
    }
    let name_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    let mut pos = 3usize;
    if buf.len() < pos + name_len + 2 {
        return Err(corrupt());
    }
    let name = std::str::from_utf8(&buf[pos..pos + name_len])
        .map_err(|_| corrupt())?
        .to_string();
    pos += name_len;
    let ncols = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let mut columns = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        if buf.len() < pos + 4 {
            return Err(corrupt());
        }
        let encrypted = buf[pos] != 0;
        let ty = match buf[pos + 1] {
            TAG_INT => DataType::Int,
            TAG_TEXT => DataType::Text,
            _ => return Err(corrupt()),
        };
        let col_name_len = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if buf.len() < pos + col_name_len {
            return Err(corrupt());
        }
        let col_name = std::str::from_utf8(&buf[pos..pos + col_name_len])
            .map_err(|_| corrupt())?
            .to_string();
        pos += col_name_len;
        columns.push(ColumnDef {
            name: col_name,
            ty,
            encrypted,
        });
    }
    if pos != buf.len() {
        return Err(corrupt());
    }
    Ok(TableSchema { name, columns })
}

/// Row layout: `ncols (2 LE)` then per value a tag byte followed by:
/// nothing (NULL), `i64 LE` (INT), or `len (4 LE) | utf8` (TEXT).
pub fn encode_row(values: &[Value]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 9);
    out.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for value in values {
        match value {
            Value::Null => out.push(TAG_NULL),
            Value::Int(n) => {
                out.push(TAG_INT);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Value::Text(s) => {
                out.push(TAG_TEXT);
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out
}

pub fn decode_row(buf: &[u8]) -> Result<Vec<Value>> {
    let corrupt = || EngineError::Corrupt("bad row record".into());
    if buf.len() < 2 {
        return Err(corrupt());
    }
    let ncols = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let mut pos = 2usize;
    let mut values = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        let tag = *buf.get(pos).ok_or_else(corrupt)?;
        pos += 1;
        match tag {
            TAG_NULL => values.push(Value::Null),
            TAG_INT => {
                let bytes: [u8; 8] = buf
                    .get(pos..pos + 8)
                    .ok_or_else(corrupt)?
                    .try_into()
                    .unwrap();
                values.push(Value::Int(i64::from_le_bytes(bytes)));
                pos += 8;
            }
            TAG_TEXT => {
                let len_bytes: [u8; 4] = buf
                    .get(pos..pos + 4)
                    .ok_or_else(corrupt)?
                    .try_into()
                    .unwrap();
                let len = u32::from_le_bytes(len_bytes) as usize;
                pos += 4;
                let text = std::str::from_utf8(buf.get(pos..pos + len).ok_or_else(corrupt)?)
                    .map_err(|_| corrupt())?;
                values.push(Value::Text(text.to_string()));
                pos += len;
            }
            _ => return Err(corrupt()),
        }
    }
    if pos != buf.len() {
        return Err(corrupt());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_roundtrip() {
        let schema = TableSchema {
            name: "users".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    ty: DataType::Int,
                    encrypted: false,
                },
                ColumnDef {
                    name: "ssn".into(),
                    ty: DataType::Text,
                    encrypted: true,
                },
            ],
        };
        let decoded = decode_schema(&encode_schema(&schema)).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn row_roundtrip() {
        let row = vec![
            Value::Int(-42),
            Value::Null,
            Value::Text("héllo 'world'".into()),
            Value::Int(i64::MAX),
        ];
        assert_eq!(decode_row(&encode_row(&row)).unwrap(), row);
    }

    #[test]
    fn truncated_row_is_rejected() {
        let row = encode_row(&[Value::Text("abc".into())]);
        assert!(decode_row(&row[..row.len() - 1]).is_err());
    }
}

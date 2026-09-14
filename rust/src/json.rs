use num_bigint::BigInt;
use serde_json::Value;
use std::collections::HashSet;

pub(crate) fn decode(data: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(data).map_err(|_| "invalid UTF-8")?;
    let mut guard = Guard { data, pos: 0 };
    guard.value(0)?;
    guard.ws();
    if guard.pos != data.len() {
        return Err("trailing JSON data".into());
    }
    serde_json::from_str(text).map_err(|_| "invalid JSON".into())
}

// A bounded structural pass retains duplicate object keys before serde's map
// representation could discard them. The serde parser validates primitive syntax.
struct Guard<'a> {
    data: &'a [u8],
    pos: usize,
}
impl Guard<'_> {
    fn ws(&mut self) {
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn take(&mut self, expected: u8) -> Result<(), String> {
        self.ws();
        if self.data.get(self.pos) != Some(&expected) {
            return Err("invalid JSON".into());
        }
        self.pos += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, String> {
        self.ws();
        let start = self.pos;
        self.take(b'"')?;
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b'\\' => {
                    self.pos += 2;
                }
                b'"' => {
                    self.pos += 1;
                    return serde_json::from_slice(&self.data[start..self.pos])
                        .map_err(|_| "invalid JSON string".into());
                }
                _ => self.pos += 1,
            }
        }
        Err("unterminated JSON string".into())
    }
    fn value(&mut self, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err("JSON nesting exceeds limit".into());
        }
        self.ws();
        match self.data.get(self.pos).copied() {
            Some(b'{') => {
                self.pos += 1;
                self.ws();
                let mut seen = HashSet::new();
                if self.data.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    let key = self.string()?;
                    if !seen.insert(key) {
                        return Err("duplicate JSON key".into());
                    }
                    self.take(b':')?;
                    self.value(depth + 1)?;
                    self.ws();
                    if self.data.get(self.pos) == Some(&b'}') {
                        self.pos += 1;
                        break;
                    }
                    self.take(b',')?;
                }
            }
            Some(b'[') => {
                self.pos += 1;
                self.ws();
                if self.data.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.ws();
                    if self.data.get(self.pos) == Some(&b']') {
                        self.pos += 1;
                        break;
                    }
                    self.take(b',')?;
                }
            }
            Some(b'"') => {
                self.string()?;
            }
            Some(_) => {
                let start = self.pos;
                while self.pos < self.data.len()
                    && !self.data[self.pos].is_ascii_whitespace()
                    && !b",]}".contains(&self.data[self.pos])
                {
                    self.pos += 1;
                }
                if self.pos == start || self.pos - start > 1024 {
                    return Err("invalid or oversized JSON primitive".into());
                }
            }
            None => return Err("invalid JSON".into()),
        }
        Ok(())
    }
}

pub(crate) fn parts(pointer: &str) -> Result<Vec<String>, String> {
    if pointer.is_empty() {
        return Ok(vec![]);
    }
    if !pointer.starts_with('/') {
        return Err("invalid JSON Pointer".into());
    }
    pointer[1..]
        .split('/')
        .map(|part| {
            let bytes = part.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'~' {
                    if !matches!(bytes.get(i + 1), Some(b'0' | b'1')) {
                        return Err("invalid JSON Pointer escape".into());
                    }
                    i += 1;
                }
                i += 1;
            }
            Ok(part.replace("~1", "/").replace("~0", "~"))
        })
        .collect()
}

pub(crate) fn lookup<'a>(mut value: &'a Value, parts: &[String]) -> Option<&'a Value> {
    for part in parts {
        value = match value {
            Value::Object(map) => map.get(part)?,
            Value::Array(array) => {
                if part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || !part.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                array.get(part.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(value)
}

pub(crate) fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => decimal(&a.to_string()) == decimal(&b.to_string()),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| equal(value, other)))
        }
        _ => a == b,
    }
}

fn decimal(raw: &str) -> String {
    let s = raw.to_lowercase();
    let (sign, s) = if let Some(v) = s.strip_prefix('-') {
        ("-", v)
    } else {
        ("", s.as_str())
    };
    let (mantissa, power) = s.split_once('e').unwrap_or((s, "0"));
    let mut exponent = power.parse::<BigInt>().unwrap_or_default();
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let combined = format!("{whole}{fraction}");
    let digits = combined.trim_start_matches('0');
    if digits.is_empty() {
        return "0".into();
    }
    let trimmed = digits.trim_end_matches('0');
    exponent += BigInt::from(digits.len() as i64 - trimmed.len() as i64 - fraction.len() as i64);
    format!("{sign}{trimmed}e{exponent}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_keys_and_depth() {
        for input in [
            r#"{"x":1,"x":2}"#,
            r#"{"nested":{"x":1,"x":2}}"#,
            "1 2",
            "[1,]",
        ] {
            assert!(decode(input.as_bytes()).is_err());
        }
        assert!(decode(format!("{}0{}", "[".repeat(66), "]".repeat(66)).as_bytes()).is_err());
    }
    #[test]
    fn precision_and_pointers() {
        assert!(equal(
            &decode(b"1e1000").unwrap(),
            &decode(b"10e999").unwrap()
        ));
        assert!(equal(&decode(b"-0").unwrap(), &decode(b"0.0").unwrap()));
        assert!(!equal(
            &decode(b"9007199254740993").unwrap(),
            &decode(b"9007199254740992").unwrap()
        ));
        let value = decode(br#"{"a/b":{"~key":[null,2]}}"#).unwrap();
        assert_eq!(
            lookup(&value, &parts("/a~1b/~0key/0").unwrap()),
            Some(&Value::Null)
        );
        assert_eq!(lookup(&value, &parts("/a~1b/~0key/01").unwrap()), None);
        assert!(parts("/bad~2").is_err());
    }
}

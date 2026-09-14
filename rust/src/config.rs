use crate::json;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
};

pub const MAX_SUITE_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub base_url: String,
    pub identities: Vec<Identity>,
    pub cases: Vec<Case>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    #[serde(default)]
    pub bearer_env: String,
    #[serde(default)]
    pub header_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    #[serde(default)]
    pub method: String,
    pub path: String,
    pub expect: BTreeMap<String, Expectation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub access: String,
    pub status: Vec<u16>,
    #[serde(default)]
    pub json: Vec<Assertion>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    #[serde(default)]
    pub pointer: String,
    pub op: String,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<Value>,
}
fn present_value<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

impl Suite {
    pub fn read(reader: impl Read) -> Result<Self, String> {
        let mut data = vec![];
        reader
            .take(MAX_SUITE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| "cannot read suite")?;
        if data.len() as u64 > MAX_SUITE_BYTES {
            return Err("suite exceeds 1 MiB limit".into());
        }
        json::decode(&data)
            .map_err(|_| "invalid suite JSON (including duplicate keys or excessive nesting)")?;
        let suite: Self = serde_json::from_slice(&data)
            .map_err(|_| "invalid suite structure or unknown field")?;
        suite.validate()?;
        Ok(suite)
    }
    pub fn validate(&self) -> Result<(), String> {
        base_url(&self.base_url)?;
        if self.identities.is_empty() || self.identities.len() > 64 {
            return Err("declare between 1 and 64 identities".into());
        }
        if self.cases.is_empty() || self.cases.len() > 1000 {
            return Err("declare between 1 and 1000 cases".into());
        }
        let mut names = HashSet::new();
        for (i, identity) in self.identities.iter().enumerate() {
            if !label(&identity.name) || !names.insert(identity.name.as_str()) {
                return Err(format!("identity {}: invalid or duplicate name", i + 1));
            }
            if !identity.bearer_env.is_empty() && !env_name(&identity.bearer_env) {
                return Err(format!("identity {}: invalid bearer_env name", i + 1));
            }
            let mut seen = HashSet::new();
            for (header, variable) in &identity.header_env {
                let lower = header.to_ascii_lowercase();
                if !allowed_header(header)
                    || !env_name(variable)
                    || !seen.insert(lower.clone())
                    || (lower == "authorization" && !identity.bearer_env.is_empty())
                {
                    return Err(format!(
                        "identity {}: invalid, reserved or duplicate credential header",
                        i + 1
                    ));
                }
            }
        }
        let mut case_names = HashSet::new();
        for (i, case) in self.cases.iter().enumerate() {
            let fail = |text: &str| format!("case {}: {text}", i + 1);
            if !label(&case.name) || !case_names.insert(&case.name) {
                return Err(fail("invalid or duplicate name"));
            }
            if !["", "GET", "HEAD"].contains(&case.method.as_str()) {
                return Err(fail("only GET and HEAD are supported"));
            }
            request_url(&self.base_url, &case.path)
                .map_err(|_| fail("invalid rooted request path"))?;
            if case.expect.len() != names.len()
                || case
                    .expect
                    .keys()
                    .any(|name| !names.contains(name.as_str()))
            {
                return Err(fail(
                    "expect must cover every declared identity exactly once",
                ));
            }
            for expect in case.expect.values() {
                if !["allow", "deny"].contains(&expect.access.as_str()) {
                    return Err(fail("access must be allow or deny"));
                }
                if expect.status.is_empty()
                    || expect
                        .status
                        .iter()
                        .any(|s| !(200..=599).contains(s) || (300..400).contains(s))
                {
                    return Err(fail(
                        "expected statuses must be final 2xx, 4xx or 5xx responses",
                    ));
                }
                if case.method == "HEAD" && !expect.json.is_empty() {
                    return Err(fail("HEAD cannot have response-body assertions"));
                }
                if expect.json.len() > 64 {
                    return Err(fail("at most 64 JSON assertions per expectation"));
                }
                let mut positive = false;
                for assertion in &expect.json {
                    json::parts(&assertion.pointer).map_err(|_| fail("invalid JSON Pointer"))?;
                    match assertion.op.as_str() {
                        "equals" | "not_equals" => {
                            let value = assertion
                                .value
                                .as_ref()
                                .ok_or_else(|| fail("equals and not_equals require a value"))?;
                            json::decode(
                                &serde_json::to_vec(value)
                                    .map_err(|_| fail("invalid assertion value"))?,
                            )
                            .map_err(|_| fail("invalid assertion value"))?;
                        }
                        "exists" | "absent" => {
                            if assertion.value.is_some() {
                                return Err(fail("exists and absent do not accept a value"));
                            }
                        }
                        _ => return Err(fail("unknown JSON assertion operator")),
                    }
                    positive |= ["equals", "exists"].contains(&assertion.op.as_str());
                }
                if case.method != "HEAD"
                    && (expect.access == "allow" || expect.status.iter().any(|s| *s < 300))
                    && !positive
                {
                    return Err(fail("GET allow or 2xx expectations need a positive equals/exists body assertion"));
                }
            }
        }
        Ok(())
    }
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn env_name(s: &str) -> bool {
    !s.is_empty()
        && (s.as_bytes()[0].is_ascii_alphabetic() || s.starts_with('_'))
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn allowed_header(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
        && ![
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "trailer",
            "te",
            "accept-encoding",
            "proxy-authorization",
            "proxy-connection",
            "user-agent",
        ]
        .contains(&s.to_ascii_lowercase().as_str())
}

pub(crate) fn base_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "invalid base_url")?;
    if raw
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .contains('@')
    {
        return Err("base_url cannot contain user information".into());
    }
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || raw.contains(['\\', '\r', '\n', '\t', ' '])
        || !raw.starts_with(&format!("{}://", url.scheme()))
    {
        return Err(
            "base_url must be an HTTP(S) origin without credentials, path, query or fragment"
                .into(),
        );
    }
    Ok(url)
}

pub(crate) fn request_url(base: &str, path: &str) -> Result<Url, String> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['#', '\\', '\r', '\n', '\t', ' '])
    {
        return Err("invalid request path".into());
    }
    // Reject encoded leading slashes/backslashes too, matching the Go parser.
    let plain_path = path
        .split('?')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
        .replace("%2f", "/")
        .replace("%5c", "\\")
        .replace("%2e", ".");
    if plain_path.starts_with("//") || plain_path.contains('\\') {
        return Err("invalid request path".into());
    }
    if plain_path
        .split('/')
        .any(|part| part == "." || part == "..")
    {
        return Err("dot path segments are not supported".into());
    }
    let origin = base_url(base)?;
    let url = origin.join(path).map_err(|_| "invalid request path")?;
    if url.origin() != origin.origin() {
        return Err("request must stay on configured origin".into());
    }
    Ok(url)
}

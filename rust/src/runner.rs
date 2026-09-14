use crate::{config, json, Suite};
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::Serialize;
use std::{
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Options {
    pub timeout: Duration,
    pub delay: Duration,
    pub max_requests: usize,
    pub max_response_bytes: u64,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            delay: Duration::ZERO,
            max_requests: 256,
            max_response_bytes: 1 << 20,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: String,
    pub assertion: usize,
}

#[derive(Debug, Serialize)]
pub struct ResultRow {
    pub case: String,
    pub identity: String,
    pub expected: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub failures: Vec<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub results: Vec<ResultRow>,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub skipped: usize,
}
impl Report {
    pub fn exit_code(&self) -> i32 {
        if self.errors > 0 || self.skipped > 0 {
            2
        } else if self.failed > 0 {
            1
        } else {
            0
        }
    }
}

pub struct Runner {
    suite: Suite,
    headers: Vec<HeaderMap>,
    client: Client,
    options: Options,
}
impl Runner {
    pub fn new(suite: Suite, options: Options) -> Result<Self, String> {
        Self::with_env(suite, options, |key| std::env::var(key).ok())
    }
    pub fn with_env(
        suite: Suite,
        options: Options,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        // Re-read the owned snapshot to apply byte/depth limits to library callers.
        let encoded = serde_json::to_vec(&suite).map_err(|_| "invalid suite")?;
        let suite = Suite::read(encoded.as_slice())?;
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(300)
            || options.delay > Duration::from_secs(60)
            || !(1..=10000).contains(&options.max_requests)
            || !(1..=64 << 20).contains(&options.max_response_bytes)
        {
            return Err("invalid runner limits".into());
        }
        if suite.cases.len() * suite.identities.len() > options.max_requests {
            return Err("planned requests exceed max-requests; nothing sent".into());
        }
        let mut headers = vec![];
        for (i, identity) in suite.identities.iter().enumerate() {
            let resolve = |key: &str| -> Result<String, String> {
                let error = || {
                    format!(
                        "identity {}: credential environment variable is missing, empty or invalid",
                        i + 1
                    )
                };
                let value = lookup(key).ok_or_else(error)?;
                if value.trim().is_empty() || value.chars().any(|c| c < ' ' || c == '\u{7f}') {
                    return Err(error());
                }
                Ok(value)
            };
            let mut h = HeaderMap::new();
            for (name, key) in &identity.header_env {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| "invalid credential header")?;
                let value = HeaderValue::from_str(&resolve(key)?)
                    .map_err(|_| "invalid credential header value")?;
                h.insert(name, value);
            }
            if !identity.bearer_env.is_empty() {
                h.insert(
                    "authorization",
                    HeaderValue::from_str(&format!("Bearer {}", resolve(&identity.bearer_env)?))
                        .map_err(|_| "invalid bearer value")?,
                );
            }
            headers.push(h);
        }
        let client = Client::builder()
            .timeout(options.timeout)
            .connect_timeout(options.timeout)
            .redirect(Policy::none())
            .no_proxy()
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| "cannot initialize HTTP client")?;
        Ok(Self {
            suite,
            headers,
            client,
            options,
        })
    }
    pub fn planned_requests(&self) -> usize {
        self.suite.cases.len() * self.suite.identities.len()
    }
    pub fn run(&self) -> Report {
        self.run_with_cancel(&AtomicBool::new(false))
    }
    /// Cancellation skips queued work; an in-flight request is bounded by timeout.
    pub fn run_with_cancel(&self, cancelled: &AtomicBool) -> Report {
        let mut report = Report::default();
        let mut first = true;
        for case in &self.suite.cases {
            for (i, identity) in self.suite.identities.iter().enumerate() {
                if !first && !cancelled.load(Ordering::Relaxed) {
                    std::thread::sleep(self.options.delay);
                }
                first = false;
                let expect = &case.expect[&identity.name];
                let mut result = ResultRow {
                    case: case.name.clone(),
                    identity: identity.name.clone(),
                    expected: expect.access.clone(),
                    outcome: "PASS".into(),
                    http_status: None,
                    failures: vec![],
                    error: None,
                };
                if cancelled.load(Ordering::Relaxed) {
                    result.outcome = "SKIP".into();
                    result.error = Some("cancelled".into());
                } else if let Err(code) = self.request(case, &self.headers[i], expect, &mut result)
                {
                    result.outcome = "ERROR".into();
                    result.error = Some(code);
                }
                match result.outcome.as_str() {
                    "PASS" => report.passed += 1,
                    "FAIL" => report.failed += 1,
                    "ERROR" => report.errors += 1,
                    _ => report.skipped += 1,
                }
                report.results.push(result);
            }
        }
        report
    }
    fn request(
        &self,
        case: &crate::Case,
        headers: &HeaderMap,
        expect: &crate::Expectation,
        result: &mut ResultRow,
    ) -> Result<(), String> {
        let target =
            config::request_url(&self.suite.base_url, &case.path).map_err(|_| "request_invalid")?;
        let method = if case.method == "HEAD" {
            reqwest::Method::HEAD
        } else {
            reqwest::Method::GET
        };
        let mut headers = headers.clone();
        if !headers.contains_key("accept") {
            headers.insert("accept", HeaderValue::from_static("application/json"));
        }
        headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        headers.insert("user-agent", HeaderValue::from_static("RoleDiff/0.1"));
        let response = self
            .client
            .request(method, target)
            .headers(headers)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "timeout"
                } else {
                    "request_failed"
                }
            })?;
        let status = response.status().as_u16();
        result.http_status = Some(status);
        if (300..400).contains(&status) {
            return Err("redirect_blocked".into());
        }
        let mut body = vec![];
        response
            .take(self.options.max_response_bytes + 1)
            .read_to_end(&mut body)
            .map_err(|_| "body_read_failed")?;
        if body.len() as u64 > self.options.max_response_bytes {
            return Err("response_too_large".into());
        }
        if !expect.status.contains(&status) {
            result.failures.push(Failure {
                code: "status_mismatch".into(),
                assertion: 0,
            });
        }
        if !expect.json.is_empty() {
            match json::decode(&body) {
                Err(_) => result.failures.push(Failure {
                    code: "invalid_json".into(),
                    assertion: 0,
                }),
                Ok(value) => {
                    for (i, assertion) in expect.json.iter().enumerate() {
                        let parts =
                            json::parts(&assertion.pointer).map_err(|_| "request_invalid")?;
                        let actual = json::lookup(&value, &parts);
                        let passed = match assertion.op.as_str() {
                            "exists" => actual.is_some(),
                            "absent" => actual.is_none(),
                            "equals" => actual
                                .zip(assertion.value.as_ref())
                                .is_some_and(|(a, b)| json::equal(a, b)),
                            "not_equals" => actual
                                .zip(assertion.value.as_ref())
                                .is_some_and(|(a, b)| !json::equal(a, b)),
                            _ => false,
                        };
                        if !passed {
                            result.failures.push(Failure {
                                code: format!("json_{}_failed", assertion.op),
                                assertion: i + 1,
                            });
                        }
                    }
                }
            }
        }
        if !result.failures.is_empty() {
            result.outcome = "FAIL".into();
        }
        Ok(())
    }
}

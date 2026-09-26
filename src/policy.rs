//! TOML policy: first matching rule wins, like a firewall.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Action {
    Allow,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    default: Action,
    #[serde(default)]
    rule: Vec<RuleFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    tool: String,
    action: Action,
    #[serde(default)]
    deny_args: Vec<String>,
    max_calls: Option<u64>,
}

struct Rule {
    tool: String,
    action: Action,
    deny_args: Vec<Regex>,
    max_calls: Option<u64>,
    calls: u64,
}

pub struct Policy {
    default: Action,
    rules: Vec<Rule>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Policy> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy {}", path.display()))?;
        Policy::from_toml(&text).with_context(|| format!("invalid policy {}", path.display()))
    }

    pub fn from_toml(text: &str) -> Result<Policy> {
        let file: PolicyFile = toml::from_str(text)?;
        let mut rules = Vec::new();
        for (i, r) in file.rule.into_iter().enumerate() {
            let deny_args = r
                .deny_args
                .iter()
                .map(|p| {
                    Regex::new(p).with_context(|| {
                        format!(
                            "rule {} ({:?}): invalid deny_args regex {p:?}",
                            i + 1,
                            r.tool
                        )
                    })
                })
                .collect::<Result<_>>()?;
            rules.push(Rule {
                tool: r.tool,
                action: r.action,
                deny_args,
                max_calls: r.max_calls,
                calls: 0,
            });
        }
        Ok(Policy {
            default: file.default,
            rules,
        })
    }

    /// Decide on one `tools/call`. Allowed calls count against the rule's `max_calls`.
    pub fn evaluate(&mut self, tool: &str, args: &Value) -> Decision {
        let Some((i, rule)) = self
            .rules
            .iter_mut()
            .enumerate()
            .find(|(_, r)| glob(&r.tool, tool))
        else {
            let allowed = self.default == Action::Allow;
            let default = if allowed { "allow" } else { "deny" };
            return Decision {
                allowed,
                reason: format!("no rule matches {tool:?}, default is {default}"),
            };
        };
        let name = format!("rule {} ({:?})", i + 1, rule.tool);
        let deny = |reason: String| Decision {
            allowed: false,
            reason,
        };
        if rule.action == Action::Deny {
            return deny(format!("{name} denies this tool"));
        }
        let mut strings = Vec::new();
        collect_strings(args, &mut strings);
        if let Some(re) = rule
            .deny_args
            .iter()
            .find(|re| strings.iter().any(|s| re.is_match(s)))
        {
            return deny(format!("{name}: an argument matches deny_args '{re}'"));
        }
        if rule.max_calls.is_some_and(|max| rule.calls >= max) {
            return deny(format!("{name}: max_calls reached"));
        }
        rule.calls += 1;
        Decision {
            allowed: true,
            reason: format!("{name} allows this tool"),
        }
    }

    /// True if the tool is denied by name alone, whatever its arguments.
    pub fn hides(&self, tool: &str) -> bool {
        let action = self.rules.iter().find(|r| glob(&r.tool, tool));
        action.map_or(self.default, |r| r.action) == Action::Deny
    }
}

/// Every string in a JSON value, object keys included.
fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|i| collect_strings(i, out)),
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k);
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

/// Match `name` against a pattern where `*` matches any run of characters.
fn glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if parts.len() == 1 {
        return pattern == name;
    }
    if name.len() < first.len() + last.len() || !name.starts_with(first) || !name.ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(text: &str) -> Policy {
        Policy::from_toml(text).unwrap()
    }

    #[test]
    fn glob_matches_star_only() {
        assert!(glob("read_file", "read_file"));
        assert!(!glob("read_file", "read_files"));
        assert!(glob("read_*", "read_file"));
        assert!(glob("read_*", "read_"));
        assert!(!glob("read_*", "Read_file"));
        assert!(glob("*_file", "write_file"));
        assert!(glob("*exec*", "shell_exec_cmd"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("a*b*c", "acb"));
        assert!(!glob("ab*ba", "aba"));
        assert!(glob("*", ""));
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut p = policy(
            r#"
            default = "allow"
            [[rule]]
            tool = "read_secret"
            action = "deny"
            [[rule]]
            tool = "read_*"
            action = "allow"
            "#,
        );
        let d = p.evaluate("read_secret", &json!({}));
        assert!(!d.allowed);
        assert_eq!(d.reason, r#"rule 1 ("read_secret") denies this tool"#);
        assert!(p.evaluate("read_file", &json!({})).allowed);
    }

    #[test]
    fn default_applies_when_no_rule_matches() {
        let mut deny = policy(r#"default = "deny""#);
        let d = deny.evaluate("Anything", &json!({}));
        assert_eq!(
            d,
            Decision {
                allowed: false,
                reason: r#"no rule matches "Anything", default is deny"#.into()
            }
        );
        assert!(
            policy(r#"default = "allow""#)
                .evaluate("x", &json!(null))
                .allowed
        );
    }

    #[test]
    fn deny_args_search_nested_values_and_keys() {
        let mut p = policy(
            r#"
            default = "deny"
            [[rule]]
            tool = "*"
            action = "allow"
            deny_args = ['\.env$']
            "#,
        );
        assert!(
            p.evaluate("t", &json!({"path": "src/main.rs", "n": 3}))
                .allowed
        );
        assert!(
            !p.evaluate("t", &json!({"a": [{"b": ["x", "prod.env"]}]}))
                .allowed
        );
        assert!(
            !p.evaluate("t", &json!({"files": {"prod.env": true}}))
                .allowed
        );
    }

    #[test]
    fn max_calls_counts_only_allowed_calls() {
        let mut p = policy(
            r#"
            default = "deny"
            [[rule]]
            tool = "fetch"
            action = "allow"
            deny_args = ['evil']
            max_calls = 2
            "#,
        );
        assert!(!p.evaluate("fetch", &json!({"url": "evil"})).allowed);
        assert!(p.evaluate("fetch", &json!({"url": "a"})).allowed);
        assert!(p.evaluate("fetch", &json!({"url": "b"})).allowed);
        let d = p.evaluate("fetch", &json!({"url": "c"}));
        assert_eq!(d.reason, r#"rule 1 ("fetch"): max_calls reached"#);
    }

    #[test]
    fn hides_only_tools_denied_by_name() {
        let p = policy(
            r#"
            default = "deny"
            [[rule]]
            tool = "shell"
            action = "deny"
            [[rule]]
            tool = "read_*"
            action = "allow"
            deny_args = ['\.ssh']
            "#,
        );
        assert!(p.hides("shell"));
        assert!(p.hides("unknown"));
        assert!(!p.hides("read_file"));
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let err = |text: &str| format!("{:#}", Policy::from_toml(text).err().unwrap());
        assert!(err("").contains("default"));
        assert!(err(r#"default = "maybe""#).contains("maybe"));
        assert!(err("default = \"deny\"\nextra = 1").contains("extra"));
        let bad_key = "default = \"deny\"\n[[rule]]\ntool = \"x\"\naction = \"allow\"\nmax = 1";
        assert!(err(bad_key).contains("max"));
        let bad_re =
            "default = \"deny\"\n[[rule]]\ntool = \"x\"\naction = \"allow\"\ndeny_args = ['(']";
        assert!(err(bad_re).contains(r#"rule 1 ("x"): invalid deny_args regex "(""#));
    }
}

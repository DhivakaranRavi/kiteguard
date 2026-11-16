//! Human-approval rules.
//!
//! Some actions are not provably malicious but cannot be undone or reach outside the
//! machine: publishing a package, deploying, sending mail, a state-changing API call.
//! A blocklist cannot enumerate these, and blocking them outright breaks legitimate work.
//! They return `Verdict::Confirm`, which the host turns into a prompt to a human.
//!
//! Everything here runs only after the block detectors found nothing.

use crate::detectors::structural;
use crate::engine::verdict::Verdict;

fn has(args: &[String], s: &str) -> bool {
    args.iter().any(|a| a == s)
}

fn dry_run(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.starts_with("--dry-run") || a == "--check" || a == "--simulate" || a == "--what-if"
    })
}

fn is_local_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "::1"
        || h == "0.0.0.0"
        || h.starts_with("127.")
}

fn host_of(arg: &str) -> Option<String> {
    let rest = arg.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next()?.to_string()
    } else {
        authority.split(':').next()?.to_string()
    };
    Some(host)
}

/// Method of a curl/wget/httpie-style invocation, if it is state-changing.
fn mutating_method(prog: &str, args: &[String]) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        let method = if a == "-X" || a == "--request" || a == "--method" {
            args.get(i + 1).cloned()
        } else if let Some(m) = a.strip_prefix("--request=") {
            Some(m.to_string())
        } else if let Some(m) = a.strip_prefix("--method=") {
            Some(m.to_string())
        } else if a.len() > 2 && a.starts_with("-X") {
            Some(a[2..].to_string())
        } else {
            None
        };
        if let Some(m) = method {
            let m = m.to_uppercase();
            if matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
                return Some(m);
            }
        }
    }
    let body = args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-d" | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "-F"
                | "--form"
                | "-T"
                | "--upload-file"
                | "--json"
                | "--post-data"
                | "--post-file"
                | "--body-data"
                | "--body-file"
        ) || a.starts_with("--data=")
            || a.starts_with("--post-data=")
            || a.starts_with("--post-file=")
    });
    if body && matches!(prog, "curl" | "wget") {
        return Some("POST".into());
    }
    None
}

fn check(prog: &str, args: &[String]) -> Option<(&'static str, String)> {
    let sub = |s: &str| has(args, s);
    match prog {
        // ── publishing ───────────────────────────────────────────────────────
        "npm" | "yarn" | "pnpm" | "bun" if sub("publish") && !dry_run(args) => Some((
            "approval_publish",
            format!("`{prog} publish` releases a package publicly"),
        )),
        "cargo" if sub("publish") && !dry_run(args) => Some((
            "approval_publish",
            "`cargo publish` is permanent: crates cannot be deleted".into(),
        )),
        "twine" if sub("upload") => Some((
            "approval_publish",
            "`twine upload` publishes to a package index".into(),
        )),
        "gem" if sub("push") => Some(("approval_publish", "`gem push` publishes a gem".into())),
        "poetry" if sub("publish") && !dry_run(args) => Some((
            "approval_publish",
            "`poetry publish` releases a package".into(),
        )),
        "docker" | "podman" if sub("push") => {
            Some(("approval_publish", "Pushing an image to a registry".into()))
        }
        // ── deploys / state changes in live systems ──────────────────────────
        "kubectl" | "oc"
            if (sub("apply")
                || sub("create")
                || sub("replace")
                || sub("patch")
                || sub("scale")
                || sub("set")
                || sub("cordon")
                || sub("drain"))
                && !dry_run(args) =>
        {
            Some((
                "approval_deploy",
                "Changes a live Kubernetes cluster".into(),
            ))
        }
        "kubectl" | "oc"
            if sub("rollout")
                && (sub("restart") || sub("undo") || sub("pause"))
                && !dry_run(args) =>
        {
            Some((
                "approval_deploy",
                "Restarts or rolls back a live workload".into(),
            ))
        }
        "helm" if (sub("install") || sub("upgrade") || sub("rollback")) && !dry_run(args) => {
            Some(("approval_deploy", "Changes a live Helm release".into()))
        }
        "terraform" | "tofu" if sub("apply") && !dry_run(args) => Some((
            "approval_deploy",
            "`terraform apply` changes real infrastructure".into(),
        )),
        "pulumi" if (sub("up") || sub("refresh")) && !dry_run(args) => Some((
            "approval_deploy",
            "`pulumi up` changes real infrastructure".into(),
        )),
        "vercel" | "netlify" | "firebase" | "fly" | "flyctl" | "serverless" | "sls" | "cdk"
        | "wrangler" | "railway" | "surge" | "amplify"
            if sub("deploy") || sub("--prod") || sub("--production") || sub("publish") =>
        {
            Some(("approval_deploy", format!("`{prog}` deploys to production")))
        }
        "vercel" | "railway" | "surge" if !dry_run(args) && args.is_empty() => {
            Some(("approval_deploy", format!("`{prog}` deploys the project")))
        }
        "stripe"
            if args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "create"
                        | "delete"
                        | "cancel"
                        | "update"
                        | "post"
                        | "refunds"
                        | "transfers"
                        | "payouts"
                )
            }) && !sub("list")
                && !sub("get") =>
        {
            Some(("approval_payment", "Changes payment state in Stripe".into()))
        }
        "twilio" if args.iter().any(|a| a.ends_with(":create") || a == "create") => {
            Some(("approval_send", "Sends a message through Twilio".into()))
        }
        "ansible-playbook" if !dry_run(args) => Some((
            "approval_deploy",
            "Runs an Ansible playbook against hosts".into(),
        )),
        "heroku" if sub("releases:rollback") || sub("config:set") || sub("ps:scale") => {
            Some(("approval_deploy", "Changes a live Heroku app".into()))
        }
        "gh" => {
            if sub("pr") && sub("merge") {
                return Some((
                    "approval_deploy",
                    "Merging a pull request changes the default branch".into(),
                ));
            }
            if (sub("release") && sub("create")) || (sub("workflow") && sub("run")) {
                return Some((
                    "approval_publish",
                    "Creates a release or triggers a workflow".into(),
                ));
            }
            if sub("api") {
                if let Some(m) = mutating_method(prog, args) {
                    return Some((
                        "approval_api_write",
                        format!("`gh api` {m} changes GitHub state"),
                    ));
                }
            }
            None
        }
        // ── outbound messages ────────────────────────────────────────────────
        "mail" | "mailx" | "sendmail" | "mutt" | "msmtp" | "swaks" | "ssmtp" => Some((
            "approval_send",
            format!("`{prog}` sends email on the user's behalf"),
        )),
        "aws" => {
            let send = args.iter().any(|a| {
                a == "publish"
                    || a == "send-message"
                    || a == "send-email"
                    || a == "send-raw-email"
                    || a == "send-templated-email"
                    || a == "put-events"
            });
            if send && !dry_run(args) {
                return Some((
                    "approval_send",
                    "Sends a message or event through AWS".into(),
                ));
            }
            if (sub("deploy")
                || sub("update-service")
                || sub("update-function-code")
                || sub("put-object"))
                && !dry_run(args)
            {
                return Some(("approval_deploy", "Changes a live AWS resource".into()));
            }
            None
        }
        // ── remote shells ────────────────────────────────────────────────────
        "ssh"
            if args
                .iter()
                .any(|a| a.contains("sudo ") || a.contains("sudo\t")) =>
        {
            Some((
                "approval_remote",
                "Runs a privileged command on a remote host".into(),
            ))
        }
        "redis-cli"
            if args.iter().any(|a| {
                matches!(
                    a.to_uppercase().as_str(),
                    "SET"
                        | "DEL"
                        | "UNLINK"
                        | "EXPIRE"
                        | "HSET"
                        | "LPUSH"
                        | "RPUSH"
                        | "SADD"
                        | "ZADD"
                        | "INCR"
                        | "DECR"
                        | "RENAME"
                        | "CONFIG"
                        | "PUBLISH"
                )
            }) =>
        {
            Some(("approval_db_write", "`redis-cli` modifies data".into()))
        }
        // ── databases: writes ────────────────────────────────────────────────
        "psql" | "mysql" | "mariadb" | "sqlite3" | "mongosh" | "mongo" | "redis-cli"
            if args.iter().any(|a| {
                let l = a.to_lowercase();
                [
                    "update ",
                    "insert ",
                    "alter ",
                    "grant ",
                    "revoke ",
                    "delete ",
                    "set ",
                    "del ",
                    "unlink ",
                    "expire ",
                    "insertone",
                    "updateone",
                    "updatemany",
                    "insertmany",
                    "deleteone",
                ]
                .iter()
                .any(|k| {
                    l.starts_with(k) || l.contains(&format!(" {k}")) || l.contains(&format!(";{k}"))
                })
            }) =>
        {
            Some(("approval_db_write", format!("`{prog}` modifies data")))
        }
        // ── state-changing HTTP calls to a non-local host ────────────────────
        "curl" | "wget" | "http" | "https" | "xh" => {
            let method = mutating_method(prog, args)?;
            let host = args.iter().find_map(|a| host_of(a))?;
            if is_local_host(&host) {
                return None;
            }
            Some((
                "approval_api_write",
                format!("{method} request to external host `{host}` changes remote state"),
            ))
        }
        _ => None,
    }
}

/// Programs that are local development or read-only tools. They are exempt from the
/// generic risky-verb rule and are never "unknown" in strict mode.
const KNOWN: &[&str] = &[
    "git",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "node",
    "npx",
    "cargo",
    "rustc",
    "rustup",
    "go",
    "pip",
    "pip3",
    "python",
    "python3",
    "pytest",
    "ruby",
    "bundle",
    "make",
    "cmake",
    "gcc",
    "clang",
    "javac",
    "mvn",
    "gradle",
    "brew",
    "apt",
    "apt-get",
    "apt-cache",
    "dpkg",
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "rg",
    "find",
    "sed",
    "awk",
    "sort",
    "uniq",
    "wc",
    "diff",
    "jq",
    "tree",
    "pwd",
    "cd",
    "echo",
    "printf",
    "date",
    "whoami",
    "which",
    "uname",
    "df",
    "du",
    "ps",
    "env",
    "printenv",
    "mkdir",
    "touch",
    "cp",
    "mv",
    "rm",
    "chmod",
    "tar",
    "unzip",
    "zip",
    "sleep",
    "true",
    "false",
    "test",
    "[",
    "export",
    "source",
    "eslint",
    "prettier",
    "tsc",
    "xargs",
    "tee",
    "docker",
    "history",
    "stat",
    "file",
    "less",
    "more",
    "basename",
    "dirname",
    "realpath",
    "ln",
    "open",
];

const RISKY_VERBS: &[&str] = &[
    "delete",
    "destroy",
    "terminate",
    "purge",
    "wipe",
    "drop",
    "decommission",
    "deprovision",
    "force-delete",
    "remove-all",
    "delete-all",
];

const RISKY_FLAGS: &[&str] = &[
    "--delete",
    "--force",
    "--yes",
    "--auto-approve",
    "--purge",
    "--prune",
];

fn generic_risky(prog: &str, args: &[String]) -> Option<(&'static str, String)> {
    if KNOWN.contains(&prog) || dry_run(args) {
        return None;
    }
    let verb = args.iter().any(|a| RISKY_VERBS.contains(&a.as_str()))
        || args.windows(2).any(|w| w[0] == "state" && w[1] == "rm")
        || args.iter().any(|a| {
            a.starts_with("delete-") || a.starts_with("destroy-") || a.starts_with("terminate-")
        });
    let flag = args.iter().any(|a| RISKY_FLAGS.contains(&a.as_str()));
    if verb || flag {
        return Some((
            "approval_generic_risky",
            format!("`{prog}` is run with a destructive or force flag/verb"),
        ));
    }
    None
}

/// Returns a `Confirm` verdict when `command` contains an action that needs a human decision.
/// With `strict`, any program outside the known read-only/dev list also needs approval.
pub fn scan(command: &str, strict: bool) -> Option<Verdict> {
    let parsed = structural::parse(command);
    for (prog, args) in &parsed {
        if let Some((rule, reason)) = check(prog, args).or_else(|| generic_risky(prog, args)) {
            return Some(Verdict::confirm(rule, reason));
        }
    }
    if strict {
        for (prog, _) in &parsed {
            let base = prog.rsplit('/').next().unwrap_or(prog);
            if !KNOWN.contains(&base) {
                return Some(Verdict::confirm(
                    "approval_unknown_program",
                    format!("`{base}` is not in the known-safe program list (strict mode)"),
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asks(c: &str) -> bool {
        scan(c, false).is_some_and(|v| v.is_confirm())
    }

    #[test]
    fn publish_and_deploy_need_approval() {
        for c in [
            "npm publish",
            "npm publish --access public",
            "cargo publish",
            "twine upload dist/*",
            "kubectl apply -f prod.yaml",
            "helm upgrade app ./chart",
            "terraform apply -auto-approve",
            "vercel --prod",
            "firebase deploy --only hosting",
            "gh pr merge 4 --admin --squash",
            "echo ok && npm publish",
            "sudo npm publish",
        ] {
            assert!(asks(c), "should ask: {c}");
        }
    }

    #[test]
    fn outbound_messages_need_approval() {
        for c in [
            "mail -s hi a@b.example < body",
            "sendmail cfo@corp.example < msg",
            "aws sns publish --topic-arn arn:x --message hi",
            "aws ses send-email --to a@b.example",
        ] {
            assert!(asks(c), "should ask: {c}");
        }
    }

    #[test]
    fn mutating_http_to_external_host_needs_approval() {
        assert!(asks(
            "curl -X POST https://api.stripe.com/v1/refunds -d charge=ch_1"
        ));
        assert!(asks("curl -X DELETE https://api.x.example/v1/users/3"));
        assert!(asks(
            "curl -XPOST https://hooks.slack.example/T/B/x -d '{}'"
        ));
        assert!(asks("wget --post-data=a=1 https://example.com/f"));
        assert!(asks("gh api -X DELETE /repos/o/r/issues/1"));
    }

    #[test]
    fn database_writes_need_approval() {
        assert!(asks("psql -c \"UPDATE users SET plan='x' WHERE id=1\""));
        assert!(asks("redis-cli SET k v"));
    }

    #[test]
    fn privileged_remote_command_needs_approval() {
        assert!(asks("ssh prod 'sudo systemctl restart app'"));
        assert!(!asks("ssh dev@build 'uptime'"));
    }

    #[test]
    fn generic_risky_verbs_ask_for_unlisted_tools() {
        for c in [
            "terraform state rm module.db",
            "aws s3 sync ./empty s3://prod --delete",
            "gcloud container clusters delete prod --quiet",
            "somecli --force --yes",
        ] {
            assert!(asks(c), "should ask: {c}");
        }
        assert!(!asks("git branch --delete old"));
        assert!(!asks("somecli delete x --dry-run"));
    }

    #[test]
    fn strict_mode_asks_for_unknown_programs() {
        assert!(scan("mystery-tool run", true).is_some());
        assert!(scan("git status && ls -la", true).is_none());
        assert!(scan("mystery-tool run", false).is_none());
    }

    #[test]
    fn read_only_and_local_work_is_not_gated() {
        for c in [
            "git status",
            "cargo build",
            "npm publish --dry-run",
            "cargo publish --dry-run",
            "kubectl get pods",
            "kubectl apply -f dev.yaml --dry-run=client",
            "terraform plan",
            "curl -s https://api.github.com/repos/o/r",
            "curl -I https://docs.rs",
            "curl -X POST http://localhost:3000/api -d '{\"a\":1}'",
            "curl -d x http://127.0.0.1:8080/",
            "psql -c 'SELECT count(*) FROM users'",
            "redis-cli GET k",
            "gh pr view 3",
            "gh api /repos/o/r",
            "ssh -T git@github.com",
        ] {
            assert!(!asks(c), "should not ask: {c}");
        }
    }
}

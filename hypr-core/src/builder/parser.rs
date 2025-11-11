//! Dockerfile parser for HYPR build system.
//!
//! Parses Dockerfiles into a structured representation that can be used
//! to build images. Supports:
//! - All standard Dockerfile instructions
//! - Multi-stage builds
//! - ARG and variable substitution
//! - BuildKit-style heredocs (future)

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Represents a complete Dockerfile with all its stages.
#[derive(Debug, Clone, PartialEq)]
pub struct Dockerfile {
    /// Build stages (may be multiple for multi-stage builds)
    pub stages: Vec<BuildStage>,
    /// Global ARG declarations (before first FROM)
    pub global_args: HashMap<String, Option<String>>,
}

/// A single build stage in a Dockerfile.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildStage {
    /// Stage name (from `FROM ... AS name`)
    pub name: Option<String>,
    /// Base image reference
    pub from: ImageRef,
    /// Instructions in this stage
    pub instructions: Vec<Instruction>,
}

/// Reference to a base image.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageRef {
    /// Regular image (e.g., "alpine:3.19", "ubuntu")
    Image {
        name: String,
        tag: Option<String>,
        digest: Option<String>,
    },
    /// Reference to another build stage
    Stage(String),
    /// Scratch (empty base)
    Scratch,
}

/// A single Dockerfile instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    /// FROM base_image [AS name]
    From {
        image: ImageRef,
        stage_name: Option<String>,
        platform: Option<String>,
    },

    /// RUN command
    Run {
        command: RunCommand,
    },

    /// COPY [--from=stage] src... dest
    Copy {
        from_stage: Option<String>,
        sources: Vec<String>,
        destination: String,
        chown: Option<String>,
    },

    /// ADD src... dest
    Add {
        sources: Vec<String>,
        destination: String,
        chown: Option<String>,
    },

    /// ENV key=value or ENV key value
    Env {
        vars: HashMap<String, String>,
    },

    /// ARG name[=default]
    Arg {
        name: String,
        default: Option<String>,
    },

    /// LABEL key=value
    Label {
        labels: HashMap<String, String>,
    },

    /// EXPOSE port[/protocol]
    Expose {
        ports: Vec<PortSpec>,
    },

    /// WORKDIR /path
    Workdir {
        path: String,
    },

    /// USER user[:group]
    User {
        user: String,
    },

    /// VOLUME ["/data"]
    Volume {
        paths: Vec<String>,
    },

    /// ENTRYPOINT ["exec", "form"] or ENTRYPOINT command
    Entrypoint {
        command: RunCommand,
    },

    /// CMD ["exec", "form"] or CMD command
    Cmd {
        command: RunCommand,
    },

    /// HEALTHCHECK --options CMD command
    Healthcheck {
        config: HealthcheckConfig,
    },

    /// STOPSIGNAL signal
    Stopsignal {
        signal: String,
    },

    /// SHELL ["executable", "parameters"]
    Shell {
        shell: Vec<String>,
    },
}

/// RUN/CMD/ENTRYPOINT command format.
#[derive(Debug, Clone, PartialEq)]
pub enum RunCommand {
    /// Shell form: RUN apt-get update
    Shell(String),
    /// Exec form: RUN ["apt-get", "update"]
    Exec(Vec<String>),
}

/// Port specification for EXPOSE instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct PortSpec {
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Healthcheck configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthcheckConfig {
    pub command: RunCommand,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub start_period: Option<String>,
    pub retries: Option<u32>,
}

/// Dockerfile parse error.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
    pub hint: Option<String>,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Line {}: {}", self.line, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  Hint: {}", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

/// Parses a Dockerfile from a string.
///
/// # Arguments
/// * `content` - The Dockerfile content as a string
///
/// # Returns
/// * `Ok(Dockerfile)` - Successfully parsed Dockerfile
/// * `Err(ParseError)` - Parse error with line number and message
///
/// # Examples
/// ```
/// use hypr_core::builder::parser::parse_dockerfile;
///
/// let dockerfile = r#"
/// FROM alpine:3.19
/// RUN apk add --no-cache nginx
/// CMD ["nginx", "-g", "daemon off;"]
/// "#;
///
/// let parsed = parse_dockerfile(dockerfile).unwrap();
/// assert_eq!(parsed.stages.len(), 1);
/// ```
pub fn parse_dockerfile(content: &str) -> Result<Dockerfile, ParseError> {
    let mut parser = DockerfileParser::new(content);
    parser.parse()
}

/// Parses a Dockerfile from a file.
pub fn parse_dockerfile_file(path: &Path) -> Result<Dockerfile, ParseError> {
    let content = std::fs::read_to_string(path).map_err(|e| ParseError {
        line: 0,
        message: format!("Failed to read Dockerfile: {}", e),
        hint: Some(format!("Check that {} exists and is readable", path.display())),
    })?;

    parse_dockerfile(&content)
}

/// Internal parser state.
struct DockerfileParser {
    lines: Vec<(usize, String)>, // (line_number, content)
    pos: usize,
    global_args: HashMap<String, Option<String>>,
    current_args: HashMap<String, String>, // Active ARG values for substitution
}

impl DockerfileParser {
    fn new(content: &str) -> Self {
        // Preprocess: combine continuation lines, remove comments
        let lines = Self::preprocess(content);

        Self {
            lines,
            pos: 0,
            global_args: HashMap::new(),
            current_args: HashMap::new(),
        }
    }

    /// Preprocess Dockerfile: handle line continuations and remove comments.
    fn preprocess(content: &str) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut current_line = String::new();
        let mut current_line_num = 0;
        let mut continuation = false;

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1; // 1-based line numbers

            // Remove comments (but not in strings - simplified for now)
            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            let trimmed = line.trim_end();

            // Skip empty lines
            if trimmed.is_empty() && !continuation {
                continue;
            }

            if continuation {
                current_line.push(' ');
                current_line.push_str(trimmed.trim_end_matches('\\').trim());
            } else {
                current_line_num = line_num;
                current_line = trimmed.trim_end_matches('\\').trim().to_string();
            }

            continuation = trimmed.ends_with('\\');

            if !continuation && !current_line.is_empty() {
                result.push((current_line_num, current_line.clone()));
                current_line.clear();
            }
        }

        // Handle final line if it was a continuation
        if !current_line.is_empty() {
            result.push((current_line_num, current_line));
        }

        result
    }

    fn parse(&mut self) -> Result<Dockerfile, ParseError> {
        // Parse global ARGs (before first FROM)
        while !self.is_eof() {
            let (line_num, line) = (self.lines[self.pos].0, self.lines[self.pos].1.clone());
            let instruction = Self::extract_instruction(&line);

            if instruction.eq_ignore_ascii_case("ARG") {
                self.parse_global_arg(line_num, &line)?;
                self.pos += 1;
            } else if instruction.eq_ignore_ascii_case("FROM") {
                break;
            } else if !instruction.is_empty() {
                return Err(ParseError {
                    line: line_num,
                    message: format!("Expected ARG or FROM, found {}", instruction),
                    hint: Some("Dockerfile must start with ARG or FROM instruction".into()),
                });
            } else {
                self.pos += 1;
            }
        }

        // Parse stages
        let mut stages = Vec::new();
        while !self.is_eof() {
            stages.push(self.parse_stage()?);
        }

        if stages.is_empty() {
            return Err(ParseError {
                line: 1,
                message: "Dockerfile must contain at least one FROM instruction".into(),
                hint: None,
            });
        }

        Ok(Dockerfile {
            stages,
            global_args: self.global_args.clone(),
        })
    }

    fn parse_stage(&mut self) -> Result<BuildStage, ParseError> {
        // Every stage must start with FROM
        let (line_num, line) = {
            let (num, l) = self.current_line()?;
            (*num, l.clone())
        };
        let instruction = Self::extract_instruction(&line);

        if !instruction.eq_ignore_ascii_case("FROM") {
            return Err(ParseError {
                line: line_num,
                message: format!("Expected FROM, found {}", instruction),
                hint: Some("Each build stage must start with FROM".into()),
            });
        }

        let from_inst = self.parse_from(line_num, &line)?;
        self.pos += 1;

        let (from_image, stage_name) = match &from_inst {
            Instruction::From { image, stage_name, .. } => (image.clone(), stage_name.clone()),
            _ => unreachable!(),
        };

        // Parse remaining instructions in this stage
        let mut instructions = vec![from_inst];

        while !self.is_eof() {
            let (line_num, line) = (self.lines[self.pos].0, self.lines[self.pos].1.clone());
            let instruction_name = Self::extract_instruction(&line);

            // Next FROM starts a new stage
            if instruction_name.eq_ignore_ascii_case("FROM") {
                break;
            }

            let inst = self.parse_instruction(line_num, &line)?;
            instructions.push(inst);
            self.pos += 1;
        }

        Ok(BuildStage {
            name: stage_name,
            from: from_image,
            instructions,
        })
    }

    fn parse_instruction(&mut self, line_num: usize, line: &str) -> Result<Instruction, ParseError> {
        let instruction = Self::extract_instruction(line);
        let args = Self::extract_args(line);

        match instruction.to_uppercase().as_str() {
            "FROM" => self.parse_from(line_num, line),
            "RUN" => self.parse_run(line_num, &args),
            "COPY" => self.parse_copy(line_num, &args),
            "ADD" => self.parse_add(line_num, &args),
            "ENV" => self.parse_env(line_num, &args),
            "ARG" => self.parse_arg(line_num, &args),
            "LABEL" => self.parse_label(line_num, &args),
            "EXPOSE" => self.parse_expose(line_num, &args),
            "WORKDIR" => self.parse_workdir(line_num, &args),
            "USER" => self.parse_user(line_num, &args),
            "VOLUME" => self.parse_volume(line_num, &args),
            "ENTRYPOINT" => self.parse_entrypoint(line_num, &args),
            "CMD" => self.parse_cmd(line_num, &args),
            "HEALTHCHECK" => self.parse_healthcheck(line_num, &args),
            "STOPSIGNAL" => self.parse_stopsignal(line_num, &args),
            "SHELL" => self.parse_shell(line_num, &args),
            _ => Err(ParseError {
                line: line_num,
                message: format!("Unknown instruction: {}", instruction),
                hint: None,
            }),
        }
    }

    fn parse_from(&mut self, line_num: usize, line: &str) -> Result<Instruction, ParseError> {
        // FROM [--platform=<platform>] <image> [AS <name>]
        let args = Self::extract_args(line);

        let mut platform = None;
        let mut image_start = 0;

        // Check for --platform flag
        if args.get(0).map(|s| s.starts_with("--platform=")).unwrap_or(false) {
            platform = Some(args[0].strip_prefix("--platform=").unwrap().to_string());
            image_start = 1;
        }

        if image_start >= args.len() {
            return Err(ParseError {
                line: line_num,
                message: "FROM instruction requires an image reference".into(),
                hint: Some("Usage: FROM <image> [AS <name>]".into()),
            });
        }

        // Parse image reference
        let image_ref = &args[image_start];
        let image = self.parse_image_ref(image_ref);

        // Check for AS name
        let stage_name = if image_start + 1 < args.len() && args[image_start + 1].eq_ignore_ascii_case("AS") {
            if image_start + 2 >= args.len() {
                return Err(ParseError {
                    line: line_num,
                    message: "FROM ... AS requires a stage name".into(),
                    hint: None,
                });
            }
            Some(args[image_start + 2].clone())
        } else {
            None
        };

        Ok(Instruction::From {
            image,
            stage_name,
            platform,
        })
    }

    fn parse_image_ref(&self, s: &str) -> ImageRef {
        if s.eq_ignore_ascii_case("scratch") {
            return ImageRef::Scratch;
        }

        // Check if it's a stage reference (all lowercase, no special chars)
        if s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') && !s.contains(':') {
            // Could be a stage name, but also could be a simple image name
            // We'll treat it as an image for now
        }

        // Parse image:tag@digest format
        let (name_tag, digest) = if let Some(idx) = s.find('@') {
            (&s[..idx], Some(s[idx+1..].to_string()))
        } else {
            (s, None)
        };

        let (name, tag) = if let Some(idx) = name_tag.rfind(':') {
            (&name_tag[..idx], Some(name_tag[idx+1..].to_string()))
        } else {
            (name_tag, None)
        };

        ImageRef::Image {
            name: name.to_string(),
            tag,
            digest,
        }
    }

    fn parse_run(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        if args.is_empty() {
            return Err(ParseError {
                line: line_num,
                message: "RUN instruction requires a command".into(),
                hint: Some("Usage: RUN <command> or RUN [\"executable\", \"arg1\"]".into()),
            });
        }

        let command = self.parse_run_command(args);

        Ok(Instruction::Run { command })
    }

    fn parse_run_command(&self, args: &[String]) -> RunCommand {
        // Check if it's JSON array format
        let first = &args[0];
        if first.starts_with('[') {
            // Exec form: parse JSON array
            let json_str = args.join(" ");
            if let Ok(exec_args) = serde_json::from_str::<Vec<String>>(&json_str) {
                return RunCommand::Exec(exec_args);
            }
        }

        // Shell form
        RunCommand::Shell(args.join(" "))
    }

    fn parse_copy(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // COPY [--from=<stage>] [--chown=<user>:<group>] <src>... <dest>
        let mut from_stage = None;
        let mut chown = None;
        let mut arg_start = 0;

        for (i, arg) in args.iter().enumerate() {
            if arg.starts_with("--from=") {
                from_stage = Some(arg.strip_prefix("--from=").unwrap().to_string());
                arg_start = i + 1;
            } else if arg.starts_with("--chown=") {
                chown = Some(arg.strip_prefix("--chown=").unwrap().to_string());
                arg_start = i + 1;
            } else {
                break;
            }
        }

        let remaining_args = &args[arg_start..];
        if remaining_args.len() < 2 {
            return Err(ParseError {
                line: line_num,
                message: "COPY requires at least source and destination".into(),
                hint: Some("Usage: COPY <src>... <dest>".into()),
            });
        }

        let sources = remaining_args[..remaining_args.len() - 1].to_vec();
        let destination = remaining_args.last().unwrap().clone();

        Ok(Instruction::Copy {
            from_stage,
            sources,
            destination,
            chown,
        })
    }

    fn parse_add(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // ADD [--chown=<user>:<group>] <src>... <dest>
        let mut chown = None;
        let mut arg_start = 0;

        if args.get(0).map(|s| s.starts_with("--chown=")).unwrap_or(false) {
            chown = Some(args[0].strip_prefix("--chown=").unwrap().to_string());
            arg_start = 1;
        }

        let remaining_args = &args[arg_start..];
        if remaining_args.len() < 2 {
            return Err(ParseError {
                line: line_num,
                message: "ADD requires at least source and destination".into(),
                hint: None,
            });
        }

        let sources = remaining_args[..remaining_args.len() - 1].to_vec();
        let destination = remaining_args.last().unwrap().clone();

        Ok(Instruction::Add {
            sources,
            destination,
            chown,
        })
    }

    fn parse_env(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // ENV key=value or ENV key value
        if args.is_empty() {
            return Err(ParseError {
                line: line_num,
                message: "ENV requires at least one key=value pair".into(),
                hint: None,
            });
        }

        let mut vars = HashMap::new();

        // Check if first arg contains '='
        if args[0].contains('=') {
            // key=value format
            for arg in args {
                if let Some(idx) = arg.find('=') {
                    let key = arg[..idx].to_string();
                    let value = arg[idx+1..].to_string();
                    vars.insert(key, value);
                }
            }
        } else {
            // key value format (only supports one pair)
            if args.len() < 2 {
                return Err(ParseError {
                    line: line_num,
                    message: "ENV requires a value".into(),
                    hint: None,
                });
            }
            vars.insert(args[0].clone(), args[1..].join(" "));
        }

        Ok(Instruction::Env { vars })
    }

    fn parse_arg(&mut self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        if args.is_empty() {
            return Err(ParseError {
                line: line_num,
                message: "ARG requires a name".into(),
                hint: Some("Usage: ARG <name>[=<default>]".into()),
            });
        }

        let (name, default) = if let Some(idx) = args[0].find('=') {
            let name = args[0][..idx].to_string();
            let default = Some(args[0][idx+1..].to_string());
            (name, default)
        } else {
            (args[0].clone(), None)
        };

        // Update active args for substitution
        if let Some(default_val) = &default {
            self.current_args.insert(name.clone(), default_val.clone());
        }

        Ok(Instruction::Arg { name, default })
    }

    fn parse_global_arg(&mut self, line_num: usize, line: &str) -> Result<(), ParseError> {
        let args = Self::extract_args(line);
        let inst = self.parse_arg(line_num, &args)?;

        if let Instruction::Arg { name, default } = inst {
            self.global_args.insert(name, default);
        }

        Ok(())
    }

    fn parse_label(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        let mut labels = HashMap::new();

        for arg in args {
            if let Some(idx) = arg.find('=') {
                let key = arg[..idx].to_string();
                let value = arg[idx+1..].trim_matches('"').to_string();
                labels.insert(key, value);
            }
        }

        Ok(Instruction::Label { labels })
    }

    fn parse_expose(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        let mut ports = Vec::new();

        for arg in args {
            let (port_str, protocol) = if arg.contains('/') {
                let parts: Vec<&str> = arg.split('/').collect();
                (parts[0], parts.get(1).copied().unwrap_or("tcp"))
            } else {
                (arg.as_str(), "tcp")
            };

            let port = port_str.parse::<u16>().map_err(|_| ParseError {
                line: line_num,
                message: format!("Invalid port number: {}", port_str),
                hint: None,
            })?;

            let protocol = match protocol.to_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err(ParseError {
                    line: line_num,
                    message: format!("Unknown protocol: {}", protocol),
                    hint: Some("Protocol must be 'tcp' or 'udp'".into()),
                }),
            };

            ports.push(PortSpec { port, protocol });
        }

        Ok(Instruction::Expose { ports })
    }

    fn parse_workdir(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        Ok(Instruction::Workdir {
            path: args.join(" "),
        })
    }

    fn parse_user(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        Ok(Instruction::User {
            user: args.join(" "),
        })
    }

    fn parse_volume(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // VOLUME ["/data"] or VOLUME /data /var/log
        let paths = if args.len() == 1 && args[0].starts_with('[') {
            // JSON array format
            serde_json::from_str::<Vec<String>>(&args[0]).map_err(|_| ParseError {
                line: line_num,
                message: "Invalid JSON array for VOLUME".into(),
                hint: None,
            })?
        } else {
            args.to_vec()
        };

        Ok(Instruction::Volume { paths })
    }

    fn parse_entrypoint(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        let command = self.parse_run_command(args);
        Ok(Instruction::Entrypoint { command })
    }

    fn parse_cmd(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        let command = self.parse_run_command(args);
        Ok(Instruction::Cmd { command })
    }

    fn parse_healthcheck(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // HEALTHCHECK [OPTIONS] CMD command
        // Options: --interval=30s --timeout=3s --start-period=0s --retries=3

        let mut interval = None;
        let mut timeout = None;
        let mut start_period = None;
        let mut retries = None;
        let mut cmd_start = 0;

        for (i, arg) in args.iter().enumerate() {
            if arg.starts_with("--interval=") {
                interval = Some(arg.strip_prefix("--interval=").unwrap().to_string());
                cmd_start = i + 1;
            } else if arg.starts_with("--timeout=") {
                timeout = Some(arg.strip_prefix("--timeout=").unwrap().to_string());
                cmd_start = i + 1;
            } else if arg.starts_with("--start-period=") {
                start_period = Some(arg.strip_prefix("--start-period=").unwrap().to_string());
                cmd_start = i + 1;
            } else if arg.starts_with("--retries=") {
                let retries_str = arg.strip_prefix("--retries=").unwrap();
                retries = Some(retries_str.parse().map_err(|_| ParseError {
                    line: line_num,
                    message: format!("Invalid retries value: {}", retries_str),
                    hint: None,
                })?);
                cmd_start = i + 1;
            } else if arg.eq_ignore_ascii_case("CMD") {
                cmd_start = i + 1;
                break;
            }
        }

        let cmd_args = &args[cmd_start..];
        let command = self.parse_run_command(cmd_args);

        Ok(Instruction::Healthcheck {
            config: HealthcheckConfig {
                command,
                interval,
                timeout,
                start_period,
                retries,
            },
        })
    }

    fn parse_stopsignal(&self, _line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        Ok(Instruction::Stopsignal {
            signal: args.join(" "),
        })
    }

    fn parse_shell(&self, line_num: usize, args: &[String]) -> Result<Instruction, ParseError> {
        // SHELL ["executable", "parameters"]
        let json_str = args.join(" ");
        let shell = serde_json::from_str::<Vec<String>>(&json_str).map_err(|_| ParseError {
            line: line_num,
            message: "SHELL requires JSON array format".into(),
            hint: Some("Usage: SHELL [\"executable\", \"arg1\", \"arg2\"]".into()),
        })?;

        Ok(Instruction::Shell { shell })
    }

    fn extract_instruction(line: &str) -> String {
        line.split_whitespace()
            .next()
            .unwrap_or("")
            .to_uppercase()
    }

    fn extract_args(line: &str) -> Vec<String> {
        let mut parts = line.splitn(2, char::is_whitespace);
        parts.next(); // Skip instruction

        if let Some(args_str) = parts.next() {
            Self::tokenize(args_str.trim())
        } else {
            Vec::new()
        }
    }

    /// Simple tokenizer that respects quotes and JSON arrays.
    fn tokenize(s: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut in_json = 0;
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '"' if in_json == 0 => {
                    in_quotes = !in_quotes;
                    current.push(c);
                }
                '[' if !in_quotes => {
                    in_json += 1;
                    current.push(c);
                }
                ']' if !in_quotes && in_json > 0 => {
                    in_json -= 1;
                    current.push(c);
                    if in_json == 0 {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                ' ' | '\t' if !in_quotes && in_json == 0 => {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.lines.len()
    }

    fn current_line(&self) -> Result<&(usize, String), ParseError> {
        if self.is_eof() {
            return Err(ParseError {
                line: self.lines.last().map(|(n, _)| *n).unwrap_or(0),
                message: "Unexpected end of file".into(),
                hint: None,
            });
        }
        Ok(&self.lines[self.pos])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dockerfile() {
        let dockerfile = r#"
FROM alpine:3.19
RUN apk add --no-cache nginx
CMD ["nginx", "-g", "daemon off;"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        assert_eq!(parsed.stages.len(), 1);

        let stage = &parsed.stages[0];
        assert_eq!(stage.name, None);
        assert!(matches!(&stage.from, ImageRef::Image { name, tag, .. } if name == "alpine" && tag.as_deref() == Some("3.19")));

        // Should have FROM + RUN + CMD = 3 instructions
        assert_eq!(stage.instructions.len(), 3);
    }

    #[test]
    fn test_multi_stage_build() {
        let dockerfile = r#"
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

FROM alpine:3.19
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        assert_eq!(parsed.stages.len(), 2);

        assert_eq!(parsed.stages[0].name, Some("builder".into()));
        assert_eq!(parsed.stages[1].name, None);
    }

    #[test]
    fn test_arg_parsing() {
        let dockerfile = r#"
ARG VERSION=1.0
FROM alpine:${VERSION}
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        assert_eq!(parsed.global_args.len(), 1);
        assert_eq!(parsed.global_args.get("VERSION"), Some(&Some("1.0".into())));
    }

    #[test]
    fn test_line_continuation() {
        let dockerfile = r#"
FROM alpine:3.19
RUN apk add --no-cache \
    nginx \
    curl \
    bash
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let stage = &parsed.stages[0];

        // Should have FROM + RUN = 2 instructions
        assert_eq!(stage.instructions.len(), 2);
    }

    #[test]
    fn test_comments() {
        let dockerfile = r#"
# This is a comment
FROM alpine:3.19  # inline comment
# Another comment
RUN echo "hello"
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        assert_eq!(parsed.stages.len(), 1);
    }

    #[test]
    fn test_expose_parsing() {
        let dockerfile = r#"
FROM alpine
EXPOSE 80 443/tcp 53/udp
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let stage = &parsed.stages[0];

        if let Instruction::Expose { ports } = &stage.instructions[1] {
            assert_eq!(ports.len(), 3);
            assert_eq!(ports[0].port, 80);
            assert_eq!(ports[1].port, 443);
            assert_eq!(ports[2].port, 53);
            assert!(matches!(ports[2].protocol, Protocol::Udp));
        } else {
            panic!("Expected EXPOSE instruction");
        }
    }

    #[test]
    fn test_env_parsing() {
        let dockerfile = r#"
FROM alpine
ENV KEY1=value1 KEY2=value2
ENV KEY3 value with spaces
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let stage = &parsed.stages[0];

        if let Instruction::Env { vars } = &stage.instructions[1] {
            assert_eq!(vars.len(), 2);
            assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
        }

        if let Instruction::Env { vars } = &stage.instructions[2] {
            assert_eq!(vars.len(), 1);
            assert_eq!(vars.get("KEY3"), Some(&"value with spaces".to_string()));
        }
    }

    #[test]
    fn test_error_no_from() {
        let dockerfile = "RUN echo hello";
        let result = parse_dockerfile(dockerfile);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_unknown_instruction() {
        let dockerfile = r#"
FROM alpine
INVALID instruction
        "#;
        let result = parse_dockerfile(dockerfile);
        assert!(result.is_err());
    }
}

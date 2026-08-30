//! SCIM filter parsing and evaluation, per RFC 7644 section 3.4.2.2.
//!
//! A filter arrives as untrusted text from an identity provider. It is tokenised, parsed into an
//! AST, and then **evaluated in Rust against already-loaded resources**. A filter is never turned
//! into a SQL fragment; the only values that reach the database are bound parameters lifted out
//! of the recognised fast-path shapes by [`Filter::required_eq_on`].
//!
//! The grammar implemented here is deliberately wider than what Microsoft Entra ID emits, so that
//! supporting a new identity provider is a change to the fast-path optimiser rather than to the
//! parser. Everything the parser accepts, the evaluator can answer.

use std::collections::HashMap;

use super::error::{ScimError, ScimResult};

/// Longest filter string we will look at. Entra's filters are a few dozen bytes.
pub const MAX_FILTER_LEN: usize = 2048;
/// Deepest nesting of `and` / `or` / `not` / `[...]` we will parse.
pub const MAX_FILTER_DEPTH: usize = 16;
/// Most AST nodes a single filter may produce.
pub const MAX_FILTER_NODES: usize = 128;

// ---------------------------------------------------------------------------------------------
// Attribute specifications
// ---------------------------------------------------------------------------------------------

/// One filterable attribute of a resource type.
///
/// `case_exact` mirrors the `caseExact` characteristic in RFC 7643: identifiers are compared
/// exactly, human-facing text is compared case-insensitively.
pub struct AttrSpec {
    /// Canonical lower-case path, e.g. `username` or `emails.value`.
    pub path: &'static str,
    pub case_exact: bool,
}

const fn spec(path: &'static str, case_exact: bool) -> AttrSpec {
    AttrSpec {
        path,
        case_exact,
    }
}

pub const USER_ATTRS: &[AttrSpec] = &[
    spec("id", true),
    spec("externalid", true),
    spec("username", false),
    spec("displayname", false),
    spec("active", true),
    spec("emails", false),
    spec("emails.value", false),
    spec("emails.type", false),
    spec("emails.primary", true),
    spec("meta.resourcetype", false),
];

pub const GROUP_ATTRS: &[AttrSpec] = &[
    spec("id", true),
    spec("externalid", true),
    spec("displayname", false),
    spec("members", true),
    spec("members.value", true),
    spec("meta.resourcetype", false),
];

fn find_spec(attrs: &'static [AttrSpec], path: &str) -> Option<&'static AttrSpec> {
    attrs.iter().find(|s| s.path == path)
}

// ---------------------------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

impl CompareOp {
    fn from_keyword(kw: &str) -> Option<Self> {
        match kw {
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "co" => Some(Self::Co),
            "sw" => Some(Self::Sw),
            "ew" => Some(Self::Ew),
            "gt" => Some(Self::Gt),
            "ge" => Some(Self::Ge),
            "lt" => Some(Self::Lt),
            "le" => Some(Self::Le),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompValue {
    Str(String),
    Bool(bool),
    Null,
    /// Kept as text: none of Vaultwarden's SCIM attributes are numeric, so a number can only ever
    /// fail to match. Preserving the literal keeps error messages honest.
    Number(String),
}

/// A parsed attribute path with any schema URN already stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrPath {
    /// Canonical lower-case path, e.g. `username`, `emails.value`.
    pub path: String,
    /// The attribute on its own, without a sub-attribute.
    pub base: String,
}

impl AttrPath {
    fn parse(raw: &str) -> Option<Self> {
        // Strip an optional schema URN prefix: `urn:...:User:userName` -> `userName`.
        // URNs contain colons and attribute names never do, so the last colon is the boundary.
        let without_urn = match raw.rfind(':') {
            Some(idx) => &raw[idx + 1..],
            None => raw,
        };

        if without_urn.is_empty() {
            return None;
        }

        let path = without_urn.to_lowercase();
        if path.matches('.').count() > 1 {
            // SCIM has exactly one level of sub-attribute.
            return None;
        }

        let base = path.split('.').next().unwrap_or(&path).to_owned();
        Some(Self {
            path,
            base,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    Present(AttrPath),
    Compare {
        path: AttrPath,
        op: CompareOp,
        value: CompValue,
    },
    /// `attr[subfilter]`, e.g. `emails[type eq "work"]`.
    ValuePath {
        path: AttrPath,
        filter: Box<Filter>,
    },
}

// ---------------------------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// A bare word: an attribute path, an operator, or a literal keyword.
    Word(String),
    Str(String),
    Number(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '$')
}

fn tokenize(input: &str) -> ScimResult<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some(&(idx, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '[' => {
                chars.next();
                tokens.push(Token::LBracket);
            }
            ']' => {
                chars.next();
                tokens.push(Token::RBracket);
            }
            '"' => {
                chars.next(); // opening quote
                let mut value = String::new();
                loop {
                    let Some((_, c)) = chars.next() else {
                        return Err(ScimError::invalid_filter("Unterminated string literal in filter."));
                    };
                    match c {
                        '"' => break,
                        '\\' => {
                            let Some((_, esc)) = chars.next() else {
                                return Err(ScimError::invalid_filter("Unterminated escape in filter."));
                            };
                            match esc {
                                '"' => value.push('"'),
                                '\\' => value.push('\\'),
                                '/' => value.push('/'),
                                'b' => value.push('\u{0008}'),
                                'f' => value.push('\u{000C}'),
                                'n' => value.push('\n'),
                                'r' => value.push('\r'),
                                't' => value.push('\t'),
                                'u' => {
                                    let mut hex = String::with_capacity(4);
                                    for _ in 0..4 {
                                        let Some((_, h)) = chars.next() else {
                                            return Err(ScimError::invalid_filter("Truncated \\u escape in filter."));
                                        };
                                        hex.push(h);
                                    }
                                    let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) else {
                                        return Err(ScimError::invalid_filter("Invalid \\u escape in filter."));
                                    };
                                    value.push(ch);
                                }
                                other => {
                                    return Err(ScimError::invalid_filter(format!(
                                        "Unsupported escape sequence \\{other} in filter."
                                    )));
                                }
                            }
                        }
                        other => value.push(other),
                    }
                }
                tokens.push(Token::Str(value));
            }
            c if c.is_ascii_digit() || c == '-' => {
                // A leading '-' could also start a negative number; attribute paths never start
                // with a digit, so treat this as a number and let the parser reject misuse.
                let start = idx;
                let mut end = idx;
                while let Some(&(i, c)) = chars.peek() {
                    if c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E') {
                        end = i + c.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Number(input[start..end].to_owned()));
            }
            c if is_word_char(c) => {
                let start = idx;
                let mut end = idx;
                while let Some(&(i, c)) = chars.peek() {
                    if is_word_char(c) {
                        end = i + c.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Word(input[start..end].to_owned()));
            }
            other => {
                return Err(ScimError::invalid_filter(format!("Unexpected character '{other}' in filter.")));
            }
        }
    }

    Ok(tokens)
}

// ---------------------------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------------------------

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    nodes: usize,
    attrs: &'static [AttrSpec],
}

impl<'a> Parser<'a> {
    // Both borrow from `self.tokens`, not from `self`, so a token can outlive the `&mut self`
    // that produced it and the parse functions stay readable.
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.pos);
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    /// Is the next token this keyword (case-insensitively)?
    fn peek_keyword(&self, keyword: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w.eq_ignore_ascii_case(keyword))
    }

    fn count_node(&mut self) -> ScimResult<()> {
        self.nodes += 1;
        if self.nodes > MAX_FILTER_NODES {
            return Err(ScimError::invalid_filter(format!(
                "Filter is too complex; at most {MAX_FILTER_NODES} terms are supported."
            )));
        }
        Ok(())
    }

    fn check_depth(depth: usize) -> ScimResult<()> {
        if depth > MAX_FILTER_DEPTH {
            return Err(ScimError::invalid_filter(format!(
                "Filter is nested too deeply; at most {MAX_FILTER_DEPTH} levels are supported."
            )));
        }
        Ok(())
    }

    /// `or` has the lowest precedence.
    fn parse_or(&mut self, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;
        let mut left = self.parse_and(depth + 1)?;
        while self.peek_keyword("or") {
            self.next();
            let right = self.parse_and(depth + 1)?;
            self.count_node()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;
        let mut left = self.parse_unary(depth + 1)?;
        while self.peek_keyword("and") {
            self.next();
            let right = self.parse_unary(depth + 1)?;
            self.count_node()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;
        if self.peek_keyword("not") {
            self.next();
            // RFC 7644 requires parentheses after `not`.
            if !matches!(self.peek(), Some(Token::LParen)) {
                return Err(ScimError::invalid_filter("'not' must be followed by a parenthesised filter."));
            }
            self.next();
            let inner = self.parse_or(depth + 1)?;
            if !matches!(self.next(), Some(Token::RParen)) {
                return Err(ScimError::invalid_filter("Unbalanced parentheses in filter."));
            }
            self.count_node()?;
            return Ok(Filter::Not(Box::new(inner)));
        }

        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;

        if matches!(self.peek(), Some(Token::LParen)) {
            self.next();
            let inner = self.parse_or(depth + 1)?;
            if !matches!(self.next(), Some(Token::RParen)) {
                return Err(ScimError::invalid_filter("Unbalanced parentheses in filter."));
            }
            return Ok(inner);
        }

        let Some(Token::Word(raw)) = self.next() else {
            return Err(ScimError::invalid_filter("Expected an attribute name in filter."));
        };

        let Some(path) = AttrPath::parse(raw) else {
            return Err(ScimError::invalid_filter(format!("Invalid attribute path '{raw}' in filter.")));
        };

        // `attr[subfilter]`, optionally followed by `.subAttr op value`
        if matches!(self.peek(), Some(Token::LBracket)) {
            self.next();
            let mut inner = self.parse_value_or(&path, depth + 1)?;
            if !matches!(self.next(), Some(Token::RBracket)) {
                return Err(ScimError::invalid_filter("Unbalanced brackets in filter."));
            }

            // `emails[type eq "work"].value eq "someone@example.test"`. Microsoft lists this form
            // as required whenever an attribute is used for user matching, so it has to work even
            // though the simpler `emails.value eq "..."` is what most clients send.
            //
            // The tokenizer treats `.` as part of a word, so the trailing sub-attribute arrives as
            // a single `.value` token.
            if let Some(Token::Word(trailing)) = self.peek()
                && let Some(sub) = trailing.strip_prefix('.')
            {
                self.next();

                let qualified = format!("{}.{}", path.base, sub.to_lowercase());
                let Some(sub_path) = AttrPath::parse(&qualified) else {
                    return Err(ScimError::invalid_filter(format!("Invalid attribute path '{qualified}' in filter.")));
                };

                let op = self.expect_operator(&qualified)?;
                let value = self.expect_value(op)?;
                self.count_node()?;
                self.require_known(&sub_path)?;

                // An element has to satisfy both the bracket filter and the trailing comparison.
                inner = Filter::And(
                    Box::new(inner),
                    Box::new(Filter::Compare {
                        path: sub_path,
                        op,
                        value,
                    }),
                );
            }

            self.count_node()?;
            self.require_known(&path)?;
            return Ok(Filter::ValuePath {
                path,
                filter: Box::new(inner),
            });
        }

        // `attr pr`
        if self.peek_keyword("pr") {
            self.next();
            self.count_node()?;
            self.require_known(&path)?;
            return Ok(Filter::Present(path));
        }

        // `attr op value`
        let op = self.expect_operator(raw)?;
        let value = self.expect_value(op)?;

        self.count_node()?;
        self.require_known(&path)?;
        Ok(Filter::Compare {
            path,
            op,
            value,
        })
    }

    fn expect_operator(&mut self, after: &str) -> ScimResult<CompareOp> {
        let Some(Token::Word(op_word)) = self.next() else {
            return Err(ScimError::invalid_filter(format!("Expected an operator after '{after}' in filter.")));
        };
        CompareOp::from_keyword(&op_word.to_lowercase())
            .ok_or_else(|| ScimError::invalid_filter(format!("Unsupported filter operator '{op_word}'.")))
    }

    fn expect_value(&mut self, op: CompareOp) -> ScimResult<CompValue> {
        match self.next() {
            Some(Token::Str(s)) => Ok(CompValue::Str(s.clone())),
            Some(Token::Number(n)) => Ok(CompValue::Number(n.clone())),
            Some(Token::Word(w)) if w.eq_ignore_ascii_case("true") => Ok(CompValue::Bool(true)),
            Some(Token::Word(w)) if w.eq_ignore_ascii_case("false") => Ok(CompValue::Bool(false)),
            Some(Token::Word(w)) if w.eq_ignore_ascii_case("null") => Ok(CompValue::Null),
            // RFC 7644 requires string literals to be quoted, but Microsoft's own SCIM
            // documentation shows Entra ID sending `filter=externalId eq jyoung` with no quotes.
            // Accepting a bare word as a string costs nothing -- the grammar still requires the
            // `attribute operator value` shape -- and avoids failing a real client over quoting.
            Some(Token::Word(w)) => Ok(CompValue::Str(w.clone())),
            _ => Err(ScimError::invalid_filter(format!("Expected a value after '{op:?}' in filter."))),
        }
    }

    fn parse_value_or(&mut self, outer: &AttrPath, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;
        let mut left = self.parse_value_and(outer, depth + 1)?;
        while self.peek_keyword("or") {
            self.next();
            let right = self.parse_value_and(outer, depth + 1)?;
            self.count_node()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_value_and(&mut self, outer: &AttrPath, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;
        let mut left = self.parse_value_primary(outer, depth + 1)?;
        while self.peek_keyword("and") {
            self.next();
            let right = self.parse_value_primary(outer, depth + 1)?;
            self.count_node()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_value_primary(&mut self, outer: &AttrPath, depth: usize) -> ScimResult<Filter> {
        Self::check_depth(depth)?;

        if matches!(self.peek(), Some(Token::LParen)) {
            self.next();
            let inner = self.parse_value_or(outer, depth + 1)?;
            if !matches!(self.next(), Some(Token::RParen)) {
                return Err(ScimError::invalid_filter("Unbalanced parentheses in filter."));
            }
            return Ok(inner);
        }

        if self.peek_keyword("not") {
            self.next();
            if !matches!(self.peek(), Some(Token::LParen)) {
                return Err(ScimError::invalid_filter("'not' must be followed by a parenthesised filter."));
            }
            self.next();
            let inner = self.parse_value_or(outer, depth + 1)?;
            if !matches!(self.next(), Some(Token::RParen)) {
                return Err(ScimError::invalid_filter("Unbalanced parentheses in filter."));
            }
            self.count_node()?;
            return Ok(Filter::Not(Box::new(inner)));
        }

        let Some(Token::Word(raw)) = self.next() else {
            return Err(ScimError::invalid_filter("Expected an attribute name inside a value filter."));
        };

        // Inside `emails[...]`, `type` means `emails.type`.
        let qualified = format!("{}.{}", outer.base, raw.to_lowercase());
        let Some(path) = AttrPath::parse(&qualified) else {
            return Err(ScimError::invalid_filter(format!("Invalid attribute path '{raw}' in value filter.")));
        };

        if self.peek_keyword("pr") {
            self.next();
            self.count_node()?;
            self.require_known(&path)?;
            return Ok(Filter::Present(path));
        }

        let op = self.expect_operator(raw)?;
        let value = self.expect_value(op)?;

        self.count_node()?;
        self.require_known(&path)?;
        Ok(Filter::Compare {
            path,
            op,
            value,
        })
    }

    /// Reject attributes this resource type does not define.
    ///
    /// Silently treating an unknown attribute as "never matches" would make a mistyped filter look
    /// like an empty directory, which is a much worse failure mode for an operator to debug.
    fn require_known(&self, path: &AttrPath) -> ScimResult<()> {
        if find_spec(self.attrs, &path.path).is_some() {
            return Ok(());
        }
        Err(ScimError::invalid_filter(format!("Unknown or unsupported filter attribute '{}'.", path.path)))
    }
}

impl Filter {
    /// Parse a filter for the given resource type.
    pub fn parse(input: &str, attrs: &'static [AttrSpec]) -> ScimResult<Self> {
        if input.len() > MAX_FILTER_LEN {
            return Err(ScimError::invalid_filter(format!(
                "Filter is too long; the maximum is {MAX_FILTER_LEN} bytes."
            )));
        }

        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Err(ScimError::invalid_filter("Filter is empty."));
        }

        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
            nodes: 0,
            attrs,
        };
        let filter = parser.parse_or(0)?;

        if parser.pos != tokens.len() {
            return Err(ScimError::invalid_filter("Unexpected trailing input in filter."));
        }

        Ok(filter)
    }

    /// Find a string equality on one of `indexable` that **must** hold for this filter to match.
    ///
    /// The caller uses it to narrow a listing to a single indexed row instead of scanning the
    /// organization, and then re-applies the whole filter to whatever came back. That two-step is
    /// what makes it safe to be generous here: the result only has to be a *necessary* condition,
    /// never a sufficient one, so a candidate the full filter later rejects costs nothing.
    ///
    /// `indexable` is the caller's list of canonical lower-case attribute paths it can look up
    /// directly, so this module does not have to know which columns happen to be indexed.
    ///
    /// Only conjunctions and value paths are descended into. `or` and `not` are skipped, because
    /// neither side of an `or` is required to hold and a negation inverts the requirement.
    pub fn required_eq_on(&self, indexable: &[&str]) -> Option<(&str, &str)> {
        match self {
            Self::Compare {
                path,
                op: CompareOp::Eq,
                value: CompValue::Str(v),
            } if indexable.contains(&path.path.as_str()) => Some((path.path.as_str(), v.as_str())),

            // Both halves of an `and` have to hold, so either may narrow the search.
            Self::And(a, b) => a.required_eq_on(indexable).or_else(|| b.required_eq_on(indexable)),

            // `emails[type eq "work"].value eq "..."` -- the value path has to match, so a
            // requirement inside it is a requirement overall.
            Self::ValuePath {
                filter,
                ..
            } => filter.required_eq_on(indexable),

            Self::Or(..)
            | Self::Not(..)
            | Self::Present(..)
            | Self::Compare {
                ..
            } => None,
        }
    }

    /// Does this filter mention `attr` (a canonical lower-case base attribute name)?
    ///
    /// Callers use it to avoid loading data no filter is going to look at: evaluating a group
    /// filter that never mentions `members` does not need each group's membership, which would
    /// otherwise be one extra query per group in the organization.
    pub fn references(&self, attr: &str) -> bool {
        match self {
            Self::And(a, b) | Self::Or(a, b) => a.references(attr) || b.references(attr),
            Self::Not(inner) => inner.references(attr),
            Self::Present(path)
            | Self::Compare {
                path,
                ..
            } => path.base == attr,
            Self::ValuePath {
                path,
                filter,
            } => path.base == attr || filter.references(attr),
        }
    }

    /// Evaluate the filter against one resource.
    pub fn matches(&self, resource: &FilterResource, attrs: &'static [AttrSpec]) -> bool {
        match self {
            Self::And(a, b) => a.matches(resource, attrs) && b.matches(resource, attrs),
            Self::Or(a, b) => a.matches(resource, attrs) || b.matches(resource, attrs),
            Self::Not(inner) => !inner.matches(resource, attrs),
            // `pr` is true when the attribute has at least one value. A multi-valued attribute
            // such as `emails` is present when it has at least one element.
            Self::Present(path) => {
                resource.values_for(&path.path).is_some_and(|vs| !vs.is_empty())
                    || resource.elements_for(&path.path).is_some_and(|es| !es.is_empty())
            }
            Self::Compare {
                path,
                op,
                value,
            } => {
                let case_exact = find_spec(attrs, &path.path).is_some_and(|s| s.case_exact);
                match resource.values_for(&path.path) {
                    // `ne` against an absent attribute is true: nothing there equals the value.
                    None => *op == CompareOp::Ne,
                    Some(values) if values.is_empty() => *op == CompareOp::Ne,
                    Some(values) => {
                        if *op == CompareOp::Ne {
                            // Multi-valued `ne` means no element equals the value.
                            values.iter().all(|v| !compare(v, CompareOp::Eq, value, case_exact))
                        } else {
                            values.iter().any(|v| compare(v, *op, value, case_exact))
                        }
                    }
                }
            }
            Self::ValuePath {
                path,
                filter,
            } => resource
                .elements_for(&path.base)
                .is_some_and(|elements| elements.iter().any(|e| filter.matches(e, attrs))),
        }
    }
}

fn compare(actual: &FilterValue, op: CompareOp, expected: &CompValue, case_exact: bool) -> bool {
    match (actual, expected) {
        (FilterValue::Bool(a), CompValue::Bool(b)) => match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            // Ordering and substring operators are meaningless for booleans.
            _ => false,
        },
        (FilterValue::Str(a), CompValue::Str(b)) => {
            let (a, b) = if case_exact {
                (a.clone(), b.clone())
            } else {
                (a.to_lowercase(), b.to_lowercase())
            };
            match op {
                CompareOp::Eq => a == b,
                CompareOp::Ne => a != b,
                CompareOp::Co => a.contains(&b),
                CompareOp::Sw => a.starts_with(&b),
                CompareOp::Ew => a.ends_with(&b),
                CompareOp::Gt => a > b,
                CompareOp::Ge => a >= b,
                CompareOp::Lt => a < b,
                CompareOp::Le => a <= b,
            }
        }
        // A present value is never equal to null, and mismatched types (a number compared against
        // a string attribute, say) never match either. In both cases only `ne` can be true.
        _ => op == CompareOp::Ne,
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation target
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Str(String),
    Bool(bool),
}

impl FilterValue {
    pub fn str(v: impl Into<String>) -> Self {
        Self::Str(v.into())
    }
}

/// A resource flattened into the shape the evaluator needs.
///
/// `simple` maps a canonical lower-case path (`username`, `emails.value`) to its values, and
/// `complex` maps a multi-valued attribute name (`emails`, `members`) to its elements so that
/// `attr[subfilter]` can be evaluated element by element.
#[derive(Debug, Default, Clone)]
pub struct FilterResource {
    simple: HashMap<String, Vec<FilterValue>>,
    complex: HashMap<String, Vec<FilterResource>>,
}

impl FilterResource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a single-valued attribute. `None` leaves the attribute absent, which is what `pr` and
    /// the comparison operators need in order to behave correctly.
    pub fn set(&mut self, path: &str, value: Option<FilterValue>) -> &mut Self {
        if let Some(value) = value {
            self.simple.insert(path.to_owned(), vec![value]);
        }
        self
    }

    /// Add one element of a multi-valued attribute, together with the flattened sub-attribute
    /// values that `attr.sub eq ...` looks at.
    pub fn push_element(&mut self, attr: &str, element: FilterResource) -> &mut Self {
        for (sub_path, values) in &element.simple {
            self.simple.entry(sub_path.clone()).or_default().extend(values.iter().cloned());
        }
        self.complex.entry(attr.to_owned()).or_default().push(element);
        self
    }

    fn values_for(&self, path: &str) -> Option<&Vec<FilterValue>> {
        self.simple.get(path)
    }

    fn elements_for(&self, attr: &str) -> Option<&Vec<FilterResource>> {
        self.complex.get(attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every attribute either resource type defines, so the narrowing tests are about the AST
    /// walk rather than about any particular caller's index list.
    const ALL_ATTRS: &[&str] =
        &["id", "externalid", "username", "displayname", "emails.value", "emails.type", "members.value"];

    fn user_filter(input: &str) -> ScimResult<Filter> {
        Filter::parse(input, USER_ATTRS)
    }

    fn group_filter(input: &str) -> ScimResult<Filter> {
        Filter::parse(input, GROUP_ATTRS)
    }

    /// A user resource shaped the way `resource.rs` builds them.
    fn user(name: &str, external: Option<&str>, active: bool) -> FilterResource {
        let mut r = FilterResource::new();
        r.set("id", Some(FilterValue::str("member-1")));
        r.set("username", Some(FilterValue::str(name)));
        r.set("displayname", Some(FilterValue::str(name)));
        r.set("active", Some(FilterValue::Bool(active)));
        r.set("meta.resourcetype", Some(FilterValue::str("User")));
        if let Some(external) = external {
            r.set("externalid", Some(FilterValue::str(external)));
        }

        let mut email = FilterResource::new();
        email.set("emails.value", Some(FilterValue::str(name)));
        email.set("emails.type", Some(FilterValue::str("work")));
        email.set("emails.primary", Some(FilterValue::Bool(true)));
        r.push_element("emails", email);

        r
    }

    fn matches(input: &str, resource: &FilterResource) -> bool {
        user_filter(input).expect("filter should parse").matches(resource, USER_ATTRS)
    }

    // -- parsing -------------------------------------------------------------------------------

    #[test]
    fn parses_the_shape_entra_sends_for_users() {
        let filter = user_filter(r#"userName eq "alice@example.test""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("username", "alice@example.test")));
    }

    #[test]
    fn parses_the_shape_entra_sends_for_groups() {
        let filter = group_filter(r#"displayName eq "Engineering""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("displayname", "Engineering")));
    }

    #[test]
    fn attribute_names_are_case_insensitive() {
        assert_eq!(user_filter(r#"USERNAME eq "x""#).unwrap().required_eq_on(ALL_ATTRS), Some(("username", "x")));
        assert_eq!(user_filter(r#"UserName EQ "x""#).unwrap().required_eq_on(ALL_ATTRS), Some(("username", "x")));
    }

    #[test]
    fn strips_a_schema_urn_prefix() {
        let filter =
            user_filter(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bob@example.test""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("username", "bob@example.test")));
    }

    #[test]
    fn accepts_an_unquoted_value() {
        // Microsoft's SCIM documentation shows Entra ID sending `filter=externalId eq jyoung`.
        let filter = user_filter("externalId eq jyoung").unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("externalid", "jyoung")));

        // ...and it must not swallow the logical keyword that follows.
        let filter = user_filter("externalId eq jyoung and active eq true").unwrap();
        assert!(matches!(filter, Filter::And(..)), "{filter:?}");
    }

    #[test]
    fn parses_escaped_string_literals() {
        let filter = user_filter(r#"externalId eq "a\"b\\c""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("externalid", "a\"b\\c")));

        let filter = user_filter(r#"externalId eq "tab\there""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("externalid", "tab\there")));

        let filter = user_filter(r#"externalId eq "A""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("externalid", "A")));
    }

    #[test]
    fn rejects_unknown_attributes_rather_than_matching_nothing() {
        let err = user_filter(r#"nickname eq "x""#).unwrap_err();
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::InvalidFilter));
        assert!(err.detail.contains("nickname"));
    }

    #[test]
    fn rejects_attributes_belonging_to_another_resource_type() {
        // `members` is a Group attribute; asking for it on Users is a client bug.
        assert!(user_filter(r#"members eq "x""#).is_err());
        // ...and `userName` is not a Group attribute.
        assert!(group_filter(r#"userName eq "x""#).is_err());
    }

    #[test]
    fn rejects_malformed_filters() {
        assert!(user_filter("userName eq").is_err(), "missing value");
        assert!(user_filter(r#"userName "x""#).is_err(), "missing operator");
        assert!(user_filter(r#"userName xx "x""#).is_err(), "unknown operator");
        assert!(user_filter(r#"(userName eq "x""#).is_err(), "unbalanced parens");
        assert!(user_filter(r#"userName eq "x")"#).is_err(), "trailing paren");
        assert!(user_filter(r#"userName eq "unterminated"#).is_err(), "unterminated string");
        assert!(user_filter("").is_err(), "empty filter");
        assert!(user_filter("   ").is_err(), "whitespace-only filter");
        assert!(user_filter(r#"userName eq "x" and"#).is_err(), "dangling and");
        assert!(user_filter("not userName pr").is_err(), "not without parentheses");
    }

    #[test]
    fn rejects_sql_looking_input_as_a_filter_error() {
        // Not because it would ever reach SQL, but because it must not be silently ignored.
        for probe in [
            r#"userName eq "x" ; DROP TABLE users --"#,
            r#"userName eq "x'; DROP TABLE users; --""#,
            "1=1",
            "userName eq 'x'",
        ] {
            let parsed = user_filter(probe);
            if let Ok(filter) = parsed {
                // If it parses at all it must be a plain comparison against a literal, never
                // anything that could carry structure onward.
                assert!(
                    matches!(filter, Filter::Compare { .. }),
                    "unexpectedly structured parse of {probe}: {filter:?}"
                );
            }
        }
        // The SQL-ish ones specifically must fail.
        assert!(user_filter("1=1").is_err());
        assert!(user_filter(r#"userName eq 'x'"#).is_err());
    }

    // -- limits --------------------------------------------------------------------------------

    #[test]
    fn rejects_over_long_filters() {
        let long = format!(r#"userName eq "{}""#, "a".repeat(MAX_FILTER_LEN));
        let err = user_filter(&long).unwrap_err();
        assert!(err.detail.contains("too long"));
    }

    #[test]
    fn rejects_too_many_terms() {
        let term = r#"userName eq "a""#;
        let filter = std::iter::repeat_n(term, MAX_FILTER_NODES + 5).collect::<Vec<_>>().join(" or ");
        // Long enough to trip the node limit but still under the length limit.
        if filter.len() <= MAX_FILTER_LEN {
            let err = user_filter(&filter).unwrap_err();
            assert!(err.detail.contains("too complex"), "{}", err.detail);
        }
    }

    #[test]
    fn rejects_deeply_nested_filters() {
        let depth = MAX_FILTER_DEPTH + 10;
        let filter = format!("{}userName pr{}", "(".repeat(depth), ")".repeat(depth));
        let err = user_filter(&filter).unwrap_err();
        assert!(err.detail.contains("too deeply"), "{}", err.detail);
    }

    // -- evaluation ----------------------------------------------------------------------------

    #[test]
    fn eq_on_username_is_case_insensitive() {
        let u = user("alice@example.test", None, true);
        assert!(matches(r#"userName eq "alice@example.test""#, &u));
        assert!(matches(r#"userName eq "ALICE@EXAMPLE.TEST""#, &u));
        assert!(!matches(r#"userName eq "bob@example.test""#, &u));
    }

    #[test]
    fn eq_on_external_id_is_case_sensitive() {
        let u = user("alice@example.test", Some("AbC123"), true);
        assert!(matches(r#"externalId eq "AbC123""#, &u));
        assert!(!matches(r#"externalId eq "abc123""#, &u));
    }

    #[test]
    fn presence_reflects_whether_the_attribute_is_set() {
        let with = user("alice@example.test", Some("x"), true);
        let without = user("alice@example.test", None, true);

        assert!(matches("externalId pr", &with));
        assert!(!matches("externalId pr", &without));
    }

    #[test]
    fn ne_against_a_missing_attribute_is_true() {
        let without = user("alice@example.test", None, true);
        assert!(matches(r#"externalId ne "anything""#, &without));
    }

    #[test]
    fn boolean_comparison_works_for_active() {
        let active = user("a@example.test", None, true);
        let inactive = user("a@example.test", None, false);

        assert!(matches("active eq true", &active));
        assert!(!matches("active eq true", &inactive));
        assert!(matches("active eq false", &inactive));
        assert!(matches("active ne true", &inactive));
    }

    #[test]
    fn substring_operators_behave() {
        let u = user("alice@example.test", None, true);
        assert!(matches(r#"userName co "example""#, &u));
        assert!(matches(r#"userName sw "alice""#, &u));
        assert!(matches(r#"userName ew ".test""#, &u));
        assert!(!matches(r#"userName sw "bob""#, &u));
    }

    #[test]
    fn logical_operators_and_precedence() {
        let u = user("alice@example.test", Some("ext-1"), true);

        assert!(matches(r#"userName eq "alice@example.test" and active eq true"#, &u));
        assert!(!matches(r#"userName eq "alice@example.test" and active eq false"#, &u));
        assert!(matches(r#"userName eq "nobody" or externalId eq "ext-1""#, &u));
        assert!(matches("not (active eq false)", &u));

        // `and` binds tighter than `or`: false and false, or true -> true.
        assert!(matches(r#"userName eq "nobody" and active eq true or externalId eq "ext-1""#, &u));
        // Parentheses override that: false and (false or true) -> false.
        assert!(!matches(r#"userName eq "nobody" and (active eq true or externalId eq "ext-1")"#, &u));
    }

    #[test]
    fn value_path_filters_select_matching_elements() {
        let u = user("alice@example.test", None, true);

        assert!(matches(r#"emails[type eq "work"]"#, &u));
        assert!(!matches(r#"emails[type eq "home"]"#, &u));
        assert!(matches(r#"emails[value eq "alice@example.test"]"#, &u));
        assert!(matches(r#"emails[primary eq true]"#, &u));
    }

    #[test]
    fn value_path_with_a_trailing_sub_attribute_comparison() {
        // Microsoft requires this form for any attribute used to match users.
        let u = user("alice@example.test", None, true);

        assert!(matches(r#"emails[type eq "work"].value eq "alice@example.test""#, &u));
        assert!(!matches(r#"emails[type eq "work"].value eq "other@example.test""#, &u));
        // The bracket filter still has to match as well.
        assert!(!matches(r#"emails[type eq "home"].value eq "alice@example.test""#, &u));
    }

    #[test]
    fn a_trailing_sub_attribute_must_still_be_a_known_attribute() {
        assert!(user_filter(r#"emails[type eq "work"].nonsense eq "x""#).is_err());
    }

    #[test]
    fn sub_attribute_paths_work_outside_brackets_too() {
        let u = user("alice@example.test", None, true);
        assert!(matches(r#"emails.value eq "alice@example.test""#, &u));
        assert!(!matches(r#"emails.value eq "other@example.test""#, &u));
    }

    #[test]
    fn group_member_filters_work() {
        let mut g = FilterResource::new();
        g.set("id", Some(FilterValue::str("group-1")));
        g.set("displayname", Some(FilterValue::str("Engineering")));

        let mut member = FilterResource::new();
        member.set("members.value", Some(FilterValue::str("member-7")));
        g.push_element("members", member);

        let f = group_filter(r#"members[value eq "member-7"]"#).unwrap();
        assert!(f.matches(&g, GROUP_ATTRS));

        let f = group_filter(r#"members[value eq "member-8"]"#).unwrap();
        assert!(!f.matches(&g, GROUP_ATTRS));
    }

    // -- narrowing ------------------------------------------------------------------------------
    //
    // `required_eq` picks an equality the filter *must* satisfy, so the caller can fetch one row
    // instead of scanning. Returning a candidate that the full filter later rejects is harmless;
    // returning one for a filter that could match something else is not.

    #[test]
    fn a_conjunction_can_be_narrowed_by_either_side() {
        let filter = user_filter(r#"userName eq "a" and active eq true"#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("username", "a")));

        let filter = user_filter(r#"active eq true and externalId eq "x""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), Some(("externalid", "x")));
    }

    #[test]
    fn a_value_path_can_be_narrowed_by_its_inner_equality() {
        let filter = user_filter(r#"emails[type eq "work"].value eq "alice@example.test""#).unwrap();

        // Only attributes the caller says it can look up are offered, so the `type eq "work"`
        // half is skipped in favour of the one that resolves to a row.
        assert_eq!(filter.required_eq_on(&["emails.value"]), Some(("emails.value", "alice@example.test")));
    }

    #[test]
    fn references_finds_an_attribute_anywhere_in_the_filter() {
        // Used to skip loading group membership when no filter is going to look at it.
        assert!(group_filter(r#"members[value eq "m1"]"#).unwrap().references("members"));
        assert!(group_filter(r#"members.value eq "m1""#).unwrap().references("members"));
        assert!(group_filter(r#"displayName eq "Eng" and members[value eq "m1"]"#).unwrap().references("members"));
        assert!(group_filter(r#"not (members[value eq "m1"])"#).unwrap().references("members"));

        assert!(!group_filter(r#"displayName eq "Eng""#).unwrap().references("members"));
        assert!(!group_filter(r#"displayName eq "Eng" and externalId pr"#).unwrap().references("members"));
    }

    #[test]
    fn narrowing_never_offers_an_attribute_the_caller_cannot_look_up() {
        let filter = user_filter(r#"displayName eq "Alice""#).unwrap();
        assert_eq!(filter.required_eq_on(&["id", "username"]), None);
    }

    #[test]
    fn disjunctions_and_negations_are_never_narrowed() {
        // Either side of an `or` may be false, and a `not` inverts the requirement, so neither
        // yields an equality that has to hold.
        let filter = user_filter(r#"userName eq "a" or userName eq "b""#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), None);

        let filter = user_filter(r#"not (userName eq "a")"#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), None);

        // ...including when the disjunction is nested inside a conjunction on that same side.
        let filter = user_filter(r#"active eq true and (userName eq "a" or userName eq "b")"#).unwrap();
        assert_eq!(filter.required_eq_on(ALL_ATTRS), None);
    }

    #[test]
    fn only_string_equalities_are_narrowable() {
        // Booleans and the other operators are not indexed lookups.
        assert_eq!(user_filter("active eq true").unwrap().required_eq_on(ALL_ATTRS), None);
        assert_eq!(user_filter(r#"userName co "a""#).unwrap().required_eq_on(ALL_ATTRS), None);
        assert_eq!(user_filter(r#"userName ne "a""#).unwrap().required_eq_on(ALL_ATTRS), None);
        assert_eq!(user_filter("externalId pr").unwrap().required_eq_on(ALL_ATTRS), None);
    }
}

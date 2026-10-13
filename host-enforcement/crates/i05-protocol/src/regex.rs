//! The pattern subset of the I05 and I07 schemas (DESIGN §6): anchors (`^` at the start of the input; `$` only at the
//! end, as in ECMA-262, never before a trailing newline), literal characters, classes with ranges and a literal `-` at
//! either end, groups, alternation, `?`, `*`, `+`, `{n}` and `{m,n}`. Anything else is refused when the pattern is
//! compiled. Matching is a Thompson NFA simulation with `re.search` semantics (a match may start anywhere), so its cost
//! is linear in the input and it never backtracks.

/// Why a pattern is outside the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);

const MAX_STATES: usize = 100_000;
const MAX_REPEAT: u32 = 1000;
const MAX_NESTING: usize = 64;

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Class(Vec<(u32, u32)>),
    Start,
    End,
    Concat(Vec<Node>),
    Alternation(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

#[derive(Debug, Clone)]
enum State {
    Class(Vec<(u32, u32)>, usize),
    Split(usize, usize),
    AssertStart(usize),
    AssertEnd(usize),
    Match,
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Regex {
    states: Vec<State>,
    start: usize,
}

struct PatternParser {
    chars: Vec<char>,
    pos: usize,
}

fn refuse<T>(message: &str) -> Result<T, PatternError> {
    Err(PatternError(message.to_string()))
}

impl PatternParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let next = self.peek();
        if next.is_some() {
            self.pos = self.pos.saturating_add(1);
        }
        next
    }

    fn alternation(&mut self, nesting: usize) -> Result<Node, PatternError> {
        if nesting > MAX_NESTING {
            return refuse("pattern nesting too deep");
        }
        let mut branches = vec![self.concatenation(nesting)?];
        while self.peek() == Some('|') {
            self.bump();
            branches.push(self.concatenation(nesting)?);
        }
        Ok(if branches.len() == 1 { branches.pop().unwrap_or(Node::Empty) } else { Node::Alternation(branches) })
    }

    fn concatenation(&mut self, nesting: usize) -> Result<Node, PatternError> {
        let mut items = Vec::new();
        while let Some(next) = self.peek() {
            if next == '|' || next == ')' {
                break;
            }
            let atom = self.atom(nesting)?;
            items.push(self.quantified(atom)?);
        }
        Ok(Node::Concat(items))
    }

    fn atom(&mut self, nesting: usize) -> Result<Node, PatternError> {
        match self.bump() {
            Some('(') => {
                if self.peek() == Some('?') {
                    return refuse("group extensions are not supported");
                }
                let inner = self.alternation(nesting.saturating_add(1))?;
                if self.bump() != Some(')') {
                    return refuse("unbalanced group");
                }
                Ok(inner)
            }
            Some('[') => self.class(),
            Some('^') => Ok(Node::Start),
            Some('$') => Ok(Node::End),
            Some(c) if "\\.*+?{}])|".contains(c) => refuse("unsupported pattern syntax"),
            Some(c) => Ok(Node::Class(vec![(u32::from(c), u32::from(c))])),
            None => refuse("truncated pattern"),
        }
    }

    fn class(&mut self) -> Result<Node, PatternError> {
        let mut ranges = Vec::new();
        if matches!(self.peek(), Some('^' | ']')) {
            return refuse("negated or empty classes are not supported");
        }
        let mut first = true;
        loop {
            let c = match self.bump() {
                None => return refuse("unterminated class"),
                Some(']') => break,
                Some('\\' | '[') => return refuse("unsupported class syntax"),
                Some(c) => c,
            };
            let literal_dash = c == '-' && (first || self.peek() == Some(']'));
            if c == '-' && !literal_dash {
                return refuse("a range without a start");
            }
            if self.peek() == Some('-') && self.chars.get(self.pos.saturating_add(1)) != Some(&']') && !literal_dash {
                self.bump();
                let high = match self.bump() {
                    Some('\\' | '[' | ']') | None => return refuse("unsupported range"),
                    Some(high) => high,
                };
                if high < c {
                    return refuse("reversed range");
                }
                ranges.push((u32::from(c), u32::from(high)));
            } else {
                ranges.push((u32::from(c), u32::from(c)));
            }
            first = false;
        }
        Ok(Node::Class(ranges))
    }

    fn number(&mut self) -> Result<u32, PatternError> {
        let mut value: u32 = 0;
        let mut digits = 0;
        while let Some(c) = self.peek() {
            let Some(digit) = c.to_digit(10) else { break };
            value = value.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(PatternError("repeat too large".into()))?;
            digits += 1;
            self.bump();
        }
        if digits == 0 {
            return refuse("a repeat count is missing");
        }
        Ok(value)
    }

    fn quantified(&mut self, atom: Node) -> Result<Node, PatternError> {
        let (min, max) = match self.peek() {
            Some('?') => (0, Some(1)),
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('{') => {
                self.bump();
                let min = self.number()?;
                let max = if self.peek() == Some(',') {
                    self.bump();
                    self.number()?
                } else {
                    min
                };
                if self.peek() != Some('}') || max < min || max > MAX_REPEAT {
                    return refuse("unsupported repeat");
                }
                (min, Some(max))
            }
            _ => return Ok(atom),
        };
        self.bump();
        if matches!(self.peek(), Some('?' | '*' | '+' | '{')) {
            return refuse("lazy or repeated quantifiers are not supported");
        }
        if matches!(atom, Node::Start | Node::End) {
            return refuse("a quantified anchor");
        }
        Ok(Node::Repeat(Box::new(atom), min, max))
    }
}

struct Builder {
    states: Vec<State>,
}

impl Builder {
    fn push(&mut self, state: State) -> Result<usize, PatternError> {
        if self.states.len() >= MAX_STATES {
            return refuse("pattern too large");
        }
        self.states.push(state);
        Ok(self.states.len() - 1)
    }

    /// Builds `node` so that a match continues at `next`; returns its entry state.
    fn build(&mut self, node: &Node, next: usize) -> Result<usize, PatternError> {
        match node {
            Node::Empty => Ok(next),
            Node::Class(ranges) => self.push(State::Class(ranges.clone(), next)),
            Node::Start => self.push(State::AssertStart(next)),
            Node::End => self.push(State::AssertEnd(next)),
            Node::Concat(items) => {
                let mut entry = next;
                for item in items.iter().rev() {
                    entry = self.build(item, entry)?;
                }
                Ok(entry)
            }
            Node::Alternation(branches) => {
                let mut entries = Vec::with_capacity(branches.len());
                for branch in branches {
                    entries.push(self.build(branch, next)?);
                }
                let mut entry = entries.pop().unwrap_or(next);
                while let Some(other) = entries.pop() {
                    entry = self.push(State::Split(other, entry))?;
                }
                Ok(entry)
            }
            Node::Repeat(body, min, max) => {
                let mut entry = match max {
                    None => {
                        let looping = self.push(State::Split(next, next))?;
                        let body_entry = self.build(body, looping)?;
                        if let Some(state) = self.states.get_mut(looping) {
                            *state = State::Split(body_entry, next);
                        }
                        looping
                    }
                    Some(max) => {
                        let mut entry = next;
                        for _ in *min..*max {
                            let body_entry = self.build(body, entry)?;
                            entry = self.push(State::Split(body_entry, entry))?;
                        }
                        entry
                    }
                };
                for _ in 0..*min {
                    entry = self.build(body, entry)?;
                }
                Ok(entry)
            }
        }
    }
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, PatternError> {
        let mut parser = PatternParser { chars: pattern.chars().collect(), pos: 0 };
        let tree = parser.alternation(0)?;
        if parser.pos != parser.chars.len() {
            return refuse("unbalanced group");
        }
        let mut builder = Builder { states: Vec::new() };
        let accept = builder.push(State::Match)?;
        let start = builder.build(&tree, accept)?;
        Ok(Regex { states: builder.states, start })
    }

    /// Whether the pattern matches anywhere in `text` (Python `re.search`), over its code points.
    pub fn is_match(&self, text: &crate::json::JStr) -> bool {
        let input: Vec<u32> = text.code_points().collect();
        let mut current = StateSet::new(self.states.len());
        let mut following = StateSet::new(self.states.len());
        for pos in 0..=input.len() {
            self.add(&mut current, self.start, pos, input.len());
            if current.list.iter().any(|index| matches!(self.states.get(*index), Some(State::Match))) {
                return true;
            }
            let Some(&c) = input.get(pos) else { break };
            following.clear();
            for index in current.list.clone() {
                if let Some(State::Class(ranges, next)) = self.states.get(index) {
                    if ranges.iter().any(|(low, high)| *low <= c && c <= *high) {
                        self.add(&mut following, *next, pos.saturating_add(1), input.len());
                    }
                }
            }
            std::mem::swap(&mut current, &mut following);
        }
        false
    }

    fn add(&self, set: &mut StateSet, state: usize, pos: usize, end: usize) {
        let mut pending = vec![state];
        while let Some(index) = pending.pop() {
            if !set.insert(index) {
                continue;
            }
            match self.states.get(index) {
                Some(State::Split(first, second)) => {
                    pending.push(*second);
                    pending.push(*first);
                }
                Some(State::AssertStart(next)) if pos == 0 => pending.push(*next),
                Some(State::AssertEnd(next)) if pos == end => pending.push(*next),
                _ => {}
            }
        }
    }
}

struct StateSet {
    marks: Vec<bool>,
    list: Vec<usize>,
}

impl StateSet {
    fn new(size: usize) -> StateSet {
        StateSet { marks: vec![false; size], list: Vec::new() }
    }

    fn insert(&mut self, index: usize) -> bool {
        match self.marks.get_mut(index) {
            Some(mark) if !*mark => {
                *mark = true;
                self.list.push(index);
                true
            }
            _ => false,
        }
    }

    fn clear(&mut self) {
        for index in self.list.drain(..) {
            if let Some(mark) = self.marks.get_mut(index) {
                *mark = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::JStr;

    fn matches(pattern: &str, text: &str) -> bool {
        Regex::new(pattern).map(|regex| regex.is_match(&JStr::new(text))).unwrap_or(false)
    }

    /// The twelve distinct patterns of the I05 v3 and I07 v3 schemas.
    #[test]
    fn schema_patterns() {
        let hex64 = "0123456789abcdef".repeat(4);
        assert!(matches("^[0-9a-f]{64}$", &hex64));
        assert!(!matches("^[0-9a-f]{64}$", &hex64[1..]));
        assert!(!matches("^[0-9a-f]{64}$", &format!("{hex64}0")));
        assert!(!matches("^[0-9a-f]{64}$", &format!("{hex64}\n")), "ECMA-262 $ does not match before a newline");
        assert!(!matches("^[0-9a-f]{64}$", &hex64.to_uppercase()));
        assert!(matches("^sha256:[0-9a-f]{64}$", &format!("sha256:{hex64}")));
        assert!(!matches("^sha256:[0-9a-f]{64}$", &format!("sha257:{hex64}")));
        assert!(matches("^[A-Za-z0-9-]{1,128}$", "11111111-aaaa-4bbb-8ccc-000000000001"));
        assert!(!matches("^[A-Za-z0-9-]{1,128}$", ""));
        assert!(!matches("^[A-Za-z0-9-]{1,128}$", &"a".repeat(129)));
        assert!(!matches("^[A-Za-z0-9-]{1,128}$", "a_b"));
        assert!(matches("^[A-Za-z0-9]{1,64}$", "41"));
        assert!(!matches("^[A-Za-z0-9]{1,64}$", "4-1"));
        assert!(matches("^[a-z0-9][a-z0-9.-]{0,62}$", "run-one"));
        assert!(matches("^[a-z0-9][a-z0-9.-]{0,62}$", "r"));
        assert!(!matches("^[a-z0-9][a-z0-9.-]{0,62}$", "-run"));
        assert!(!matches("^[a-z0-9][a-z0-9.-]{0,62}$", &"r".repeat(64)));
        let dns = "^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$";
        assert!(matches(dns, "a") && matches(dns, "a.b-c") && !matches(dns, "a-") && !matches(dns, ""));
        assert!(matches(dns, &"a".repeat(253)) && !matches(dns, &"a".repeat(254)));
        let group = "^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?)?$";
        assert!(matches(group, "") && matches(group, "apps") && !matches(group, "-apps"));
        assert!(matches("^[ -~]*$", "") && matches("^[ -~]*$", "a b~") && !matches("^[ -~]*$", "\u{e9}"));
        assert!(!matches("^[ -~]+$", "") && matches("^[ -~]+$", " "));
        assert!(!matches("^[ -~]+$", "\u{7f}"));
        let label = "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$";
        assert!(matches(label, "planeon-qual") && !matches(label, "planeon.qual") && !matches(label, &"a".repeat(64)));
        assert!(matches("^[a-z][a-z0-9]{0,62}$", "configmaps") && !matches("^[a-z][a-z0-9]{0,62}$", "9a"));
        let version = "^v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$";
        for good in ["v1", "v10", "v1beta1", "v2alpha3"] {
            assert!(matches(version, good), "{good}");
        }
        for bad in ["v0", "v1beta", "v1gamma1", "1", "v1beta0", "V1"] {
            assert!(!matches(version, bad), "{bad}");
        }
    }

    #[test]
    fn search_semantics_and_operators() {
        assert!(matches("b", "abc"));
        assert!(!matches("^b", "abc"));
        assert!(matches("c$", "abc"));
        assert!(matches("^(a|bc)+$", "abca"));
        assert!(!matches("^(a|bc)+$", "abcb"));
        assert!(matches("^a?b*$", "bbb"));
        assert!(matches("^(a*)*$", "aaaa"), "an empty loop body terminates");
        assert!(matches("^x{2}$", "xx") && !matches("^x{2}$", "x") && !matches("^x{2}$", "xxx"));
        let surrogate = crate::json::parse("\"\\ud800\"").ok();
        if let Some(crate::json::Value::Str(ref text)) = surrogate {
            assert!(!Regex::new("^[ -~]*$").map(|regex| regex.is_match(text)).unwrap_or(true));
        }
    }

    #[test]
    fn refuses_outside_the_subset() {
        for pattern in ["a.b", "\\d", "[^a]", "[]", "(?:a)", "a{2,}", "a**", "a+?", "(a", "a)", "[a", "[z-a]", "a{1001}",
                        "^*", "[a-]b-]", "{", "a|*"] {
            assert!(Regex::new(pattern).is_err(), "{pattern:?}");
        }
    }
}

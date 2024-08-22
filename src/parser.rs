#[derive(Debug)]
pub enum RegexNode {
    /// Character literal
    Char(char),
    /// `^`
    Start,
    /// `.`
    Any,
    /// `[...]`
    Brackets(Vec<SetElement>),
    /// `[^...]`
    BracketsNegated(Vec<SetElement>),
    /// `(...)`
    SubExpr(Vec<RegexNode>),
    /// `*`
    Star(Box<RegexNode>),
    /// `+`
    Plus(Box<RegexNode>),
    /// `?`
    Optional(Box<RegexNode>),
    // /// `|`
    // Choice(Box<RegexNode>, Box<RegexNode>),
    /// `{n}`
    Repeat(Box<RegexNode>, u64),
    /// `{n,m}`
    RepeatRange(Box<RegexNode>, u64, u64),
    /// `$`
    End,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum SetElement {
    Char(char),
    /// Inclusive range
    Range(char, char),
}

pub fn parse_regex(pat: &str) -> Vec<RegexNode> {
    let mut it = pat.chars().peekable();
    parse_regex_inner(&mut it, false)
}

fn parse_regex_inner(
    iter: &mut std::iter::Peekable<std::str::Chars>,
    until_paren: bool,
) -> Vec<RegexNode> {
    let mut re = Vec::new();
    while let Some(c) = iter.next() {
        if c == '^' {
            re.push(RegexNode::Start);
            continue;
        }
        if c == '$' {
            re.push(RegexNode::End);
            continue;
        }

        let mut node = match c {
            '(' => RegexNode::SubExpr(parse_regex_inner(iter, true)),
            '[' => parse_set(iter),
            ')' if until_paren => {
                return re;
            }
            ']' | ')' | '}' => panic!("unmatched `{c}`"),
            '*' | '+' | '?' | '{' | '|' => {
                if re.is_empty() {
                    panic!("unmatched `{c}`")
                } else {
                    unreachable!("should have already matched `{c}`")
                }
            }
            '.' => RegexNode::Any,
            _ => RegexNode::Char(c),
        };

        match iter.peek() {
            Some('*') => {
                iter.next();
                node = RegexNode::Star(Box::new(node))
            }
            Some('+') => {
                iter.next();
                node = RegexNode::Plus(Box::new(node))
            }
            Some('?') => {
                iter.next();
                node = RegexNode::Optional(Box::new(node))
            }
            Some('|') => todo!("or not implemented"),
            Some('{') => node = parse_braces(iter, node),
            _ => (),
        }

        re.push(node);
    }
    re
}

/// Parse either a `{n}` or `{n,m}` postfix operator, placing an already parsed node in
fn parse_braces(iter: &mut std::iter::Peekable<std::str::Chars>, node: RegexNode) -> RegexNode {
    let node = Box::new(node);
    let x = iter.next();
    debug_assert_eq!(x, Some('{'));
    let mut number = None;
    while let Some(n) = iter.next_if(|x| x.is_ascii_digit()) {
        if let Some(num) = number.as_mut() {
            *num *= 10;
            *num += ((n as u8) - b'0') as u64;
        } else {
            number = Some(((n as u8) - b'0') as u64);
        }
    }
    let number = number.expect("parsing first number");

    let mut number_hi = None;
    match iter.next() {
        Some('}') => RegexNode::Repeat(node, number),
        Some(',') => {
            while let Some(n) = iter.next_if(|x| x.is_ascii_digit()) {
                if let Some(num) = number_hi.as_mut() {
                    *num *= 10;
                    *num += ((n as u8) - b'0') as u64;
                } else {
                    number_hi = Some(((n as u8) - b'0') as u64);
                }
            }
            let number_hi = number_hi.expect("parsing second number");
            assert_eq!(
                iter.next(),
                Some('}'),
                "expected `}}`, found end of pattern"
            );
            assert!(
                number_hi >= number,
                "`{number_hi}` should be greater than or equal to `{number}`"
            );
            RegexNode::RepeatRange(node, number, number_hi)
        }
        Some(c) => panic!("expected `}}` or `,`, found `{c}"),
        _ => panic!("expected `}}` or `,`, found end of pattern"),
    }
}

/// Parse either a [...] or [^...] set
fn parse_set(iter: &mut std::iter::Peekable<std::str::Chars>) -> RegexNode {
    let negated = iter.next_if_eq(&'^').is_some();
    let mut elts = vec![];

    while let Some(c) = iter.next_if(|&c| c != ']') {
        if iter.next_if_eq(&'-').is_some() {
            match iter.peek().expect("unmatched `[`") {
                ']' => {
                    elts.push(SetElement::Char(c));
                    elts.push(SetElement::Char('-'));
                }
                &c2 => {
                    elts.push(SetElement::Range(c, c2));
                    iter.next();
                }
            }
        } else {
            elts.push(SetElement::Char(c));
        }
    }
    let x = iter.next();
    debug_assert!(x == Some(']'));

    elts.sort();
    elts.dedup();
    if negated {
        RegexNode::BracketsNegated(elts)
    } else {
        RegexNode::Brackets(elts)
    }
}

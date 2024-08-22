use std::ptr::null_mut;

use iced_x86::{code_asm::*, IcedError};
use libc::{MAP_ANON, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};

use crate::{
    function::RegexFunction,
    parser::{RegexNode, SetElement},
};

pub struct RegexAssembler {
    ca: CodeAssembler,
    pattern: Vec<RegexNode>,
}

enum RepeatKind {
    ZeroOrMore,
    OneOrMore,
    Specific(u64),
    Range(u64, u64),
}

impl RegexAssembler {
    const PTR: AsmRegister64 = rdi;
    const STR_LEN: AsmRegister64 = rsi;
    const COUNTER: AsmRegister64 = rbx;

    pub fn new(pattern: Vec<RegexNode>) -> Self {
        Self {
            ca: CodeAssembler::new(std::mem::size_of::<*const ()>() as u32 * 8).unwrap(),
            pattern,
        }
    }

    pub fn assemble(mut self) -> RegexFunction {
        if std::env::var("DEBUG").is_ok() {
            self.ca.int3().unwrap();
        }
        self.try_assemble().expect("compiling code");
        self.finalize()
    }

    fn try_assemble(&mut self) -> Result<(), IcedError> {
        let mut fail = self.ca.create_label();
        self.ca.xor(Self::COUNTER, Self::COUNTER)?;

        self.ca.mov(r11, rsp)?;

        for node in std::mem::take(&mut self.pattern) {
            self.match_node(&node, fail)?;
        }

        self.ca.mov(eax, 1)?; //  mov eax, 1
        self.ca.mov(rsp, r11)?; //  mov rsp, r11
        self.ca.ret()?; //  ret
        self.ca.set_label(&mut fail)?; // fail:
        self.ca.xor(eax, eax)?; //  xor eax, eax
        self.ca.mov(rsp, r11)?; //  mov rsp, r11
        self.ca.ret()?; //  ret
        Ok(())
    }

    fn check_bounds(&mut self, len: usize, fail: CodeLabel) -> Result<(), IcedError> {
        let len: i32 = len.try_into().unwrap();
        let bounds_check = rax;
        self.ca.lea(bounds_check, Self::COUNTER + len as i32)?;
        self.ca.cmp(bounds_check, Self::STR_LEN)?;
        self.ca.ja(fail)?;
        Ok(())
    }

    fn match_node(&mut self, node: &RegexNode, fail: CodeLabel) -> Result<(), IcedError> {
        match node {
            RegexNode::Start => self.match_start(fail),
            RegexNode::Any => self.match_any(fail),
            RegexNode::End => self.match_end(fail),
            RegexNode::Char(c) => self.match_regular_character(*c, fail),
            RegexNode::Star(node) => self.match_repeat(&*node, RepeatKind::ZeroOrMore, fail),
            RegexNode::Plus(node) => self.match_repeat(&*node, RepeatKind::OneOrMore, fail),
            RegexNode::Repeat(node, n) => self.match_repeat(&*node, RepeatKind::Specific(*n), fail),
            RegexNode::RepeatRange(node, n, m) => {
                self.match_repeat(&*node, RepeatKind::Range(*n, *m), fail)
            }
            RegexNode::SubExpr(exprs) => {
                for node in exprs {
                    self.match_node(node, fail)?;
                }
                Ok(())
            }
            RegexNode::Brackets(set) => self.match_set(false, set, fail),
            RegexNode::BracketsNegated(set) => self.match_set(true, set, fail),
            _ => todo!("{node:?}"),
        }
    }

    fn match_regular_character(&mut self, c: char, fail: CodeLabel) -> Result<(), IcedError> {
        let mut utf8_buf = [0; 4];
        c.encode_utf8(&mut utf8_buf);
        let len = c.len_utf8();
        self.check_bounds(len, fail)?;
        for i in 0..len {
            let b = utf8_buf[i];
            self.ca
                .cmp(byte_ptr(Self::PTR + Self::COUNTER + i), b as u32)?;
            self.ca.jne(fail)?;
        }
        self.ca.add(Self::COUNTER, len as i32)?;
        Ok(())
    }

    fn match_start(&mut self, fail: CodeLabel) -> Result<(), IcedError> {
        self.ca.test(Self::COUNTER, Self::COUNTER)?;
        self.ca.jne(fail)?;
        Ok(())
    }

    fn match_end(&mut self, fail: CodeLabel) -> Result<(), IcedError> {
        self.ca.test(Self::COUNTER, Self::STR_LEN)?;
        self.ca.jne(fail)?;
        Ok(())
    }

    fn match_repeat(
        &mut self,
        node: &RegexNode,
        kind: RepeatKind,
        fail: CodeLabel,
    ) -> Result<(), IcedError> {
        // We must consume at least `min` of this pattern, and will consume a total of `max` (or fail)
        let (min, max) = match kind {
            RepeatKind::ZeroOrMore => (0, u64::MAX),
            RepeatKind::OneOrMore => (1, u64::MAX),
            RepeatKind::Specific(n) => (n, n),
            RepeatKind::Range(n, m) => (n, m),
        };
        debug_assert!(max >= min, "{max} < {min}");
        // FIXME: The loops in this function can result in mismatched stack push/pops
        // We fix this up before leaving the JIT function but this could be improved

        // First check to make sure if this matches
        if min == 0 {
            // No action needed
        } else if min == 1 {
            // Just one check
            self.match_node(node, fail)?;
        } else {
            // Loop until `min`
            let loop_counter = rcx;
            self.ca.mov(loop_counter, min)?;
            let mut loop_start = self.ca.create_label();

            self.ca.set_label(&mut loop_start)?;
            self.ca.push(loop_counter)?;
            self.match_node(node, fail)?;
            self.ca.pop(loop_counter)?;
            self.ca.loop_(loop_start)?;
        }

        let Some(remaining @ 1..) = max.checked_sub(min) else {
            return Ok(());
        };

        // Loop for `remaining`
        let loop_counter = rcx;
        let mut loop_done = self.ca.create_label();
        self.ca.mov(loop_counter, remaining)?;
        let mut loop_start = self.ca.create_label();
        self.ca.set_label(&mut loop_start)?;

        self.ca.push(loop_counter)?;
        self.match_node(node, loop_done)?;
        self.ca.pop(loop_counter)?;
        self.ca.loop_(loop_start)?;
        self.ca.set_label(&mut loop_done)?;

        Ok(())
    }

    fn match_set(
        &mut self,
        negated: bool,
        set: &[SetElement],
        fail: CodeLabel,
    ) -> Result<(), IcedError> {
        // FIXME: Support utf8
        self.check_bounds(1, fail)?;
        let jmpfn_a = if negated {
            CodeAssembler::jne
        } else {
            CodeAssembler::je
        };

        let jmpfn_b = if negated {
            CodeAssembler::je
        } else {
            CodeAssembler::jne
        };

        let mut success = self.ca.create_label();

        for &element in set {
            match element {
                SetElement::Char(c) => {
                    assert!(c.is_ascii(), "utf8 sets are not supported");
                    self.ca
                        .cmp(byte_ptr(Self::PTR + Self::COUNTER), c as u8 as i32)?;
                    jmpfn_a(&mut self.ca, success)?;
                }
                SetElement::Range(start, end) => {
                    assert!(
                        start.is_ascii() && end.is_ascii(),
                        "utf8 sets are not supported"
                    );
                    self.ca.xor(r8d, r8d)?;
                    self.ca.xor(r9d, r9d)?;
                    let greater = r8b;
                    let lesser = r9b;

                    self.ca
                        .cmp(byte_ptr(Self::PTR + Self::COUNTER), start as u8 as i32)?;
                    self.ca.setge(greater)?;
                    self.ca
                        .cmp(byte_ptr(Self::PTR + Self::COUNTER), end as u8 as i32)?;
                    self.ca.setle(lesser)?;

                    self.ca.test(lesser, greater)?;
                    jmpfn_b(&mut self.ca, success)?;
                }
            }
        }

        self.ca.jmp(fail)?;
        self.ca.set_label(&mut success)?;
        self.ca.inc(Self::COUNTER)?;

        Ok(())
    }

    // FIXME: This matches a single byte, not an actual character
    fn match_any(&mut self, fail: CodeLabel) -> Result<(), IcedError> {
        self.check_bounds(1, fail)?;
        self.ca.inc(Self::COUNTER)?;
        Ok(())
    }

    fn finalize(mut self) -> RegexFunction {
        let mut size = 0x1000;
        let mut ptr =
            unsafe { libc::mmap(null_mut(), size, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0) };
        let mut assembled = self
            .ca
            .assemble(ptr as usize as u64)
            .expect("error assembling code");

        // This will probably only happen zero or one times, but re-assembling at a new address could
        // possibly somehow make our code longer
        while assembled.len() > size {
            // If we have a HUGE regex function, we need to map more room for it
            let new_ptr = unsafe { libc::mremap(ptr, size, assembled.len(), 0) };
            size = assembled.len();
            if !std::ptr::addr_eq(ptr, new_ptr) {
                // Oh no, addresses have changed - need to re-assemble
                assembled = self
                    .ca
                    .assemble(new_ptr as usize as u64)
                    .expect("error assembling code");
            }
            ptr = new_ptr;
        }

        // SAFETY: The above loop ensures our mmap size is large enough to hold our assembled data
        unsafe {
            std::ptr::copy_nonoverlapping(assembled.as_ptr(), ptr as _, assembled.len());
            assert!(
                libc::mprotect(ptr, size, PROT_EXEC | PROT_READ) == 0,
                "making code executable"
            );
            RegexFunction::new(ptr, size)
        }
    }
}

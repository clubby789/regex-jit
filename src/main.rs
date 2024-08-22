mod assembler;
mod function;
mod parser;

fn matches(pat: &str, text: &str) -> bool {
    let func = assembler::RegexAssembler::new(parser::parse_regex(pat)).assemble();
    func.matches(text)
}

fn main() {
    dbg!(matches("[a-zA-Z0-9]+", "FOO"));
    dbg!(matches("[a-zA-Z0-9]+", "FoObAr"));
    dbg!(matches("[a-zA-Z0-9]+", "FoObAr123"));
    dbg!(matches("[a-zA-Z0-9]+", "+++++++"));
}

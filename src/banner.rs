use colored::*;

pub fn print_banner() {
    println!(
        "{}",
        r#"
⬡ PhantomBit v1.0
  Steganography • Metadata Analysis • Risk Scoring
"#
        .bright_blue()
        .bold()
    );
}

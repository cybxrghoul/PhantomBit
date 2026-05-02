use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "phantombit",
    version = "1.0.0",
    author = "cybxrghoul",
    about = "Rust-based steganography, metadata analysis, and risk scoring toolkit."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze file metadata and calculate risk score
    Analyze {
        #[arg(short, long)]
        file: String,
    },

    /// Encode hidden data into a file
    Encode {
        #[command(subcommand)]
        command: EncodeCommands,
    },

    /// Decode hidden data from a file
    Decode {
        #[command(subcommand)]
        command: DecodeCommands,
    },

    /// Generate analysis report
    Report {
        #[arg(short, long)]
        file: String,

        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Detect possible steganography in a file
    Detect {
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Subcommand)]
pub enum EncodeCommands {
    /// LSB image steganography
    Lsb {
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        output: String,

        #[arg(short, long)]
        message: String,

        #[arg(short, long)]
        passphrase: String,
    },

    /// Hybrid encrypted steganography mode
    Hybrid {
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        output: String,

        #[arg(short, long)]
        message: String,

        #[arg(short, long)]
        passphrase: String,
    },
}

#[derive(Subcommand)]
pub enum DecodeCommands {
    /// Decode LSB hidden data
    Lsb {
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        passphrase: String,
    },

    /// Decode hybrid hidden data
    Hybrid {
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        passphrase: String,
    },
}

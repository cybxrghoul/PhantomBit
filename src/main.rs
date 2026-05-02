mod banner;
mod cli;
mod crypto;
mod metadata;
mod report;
mod risk;
mod stego;
mod detection;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, EncodeCommands, DecodeCommands};

fn main() -> Result<()> {
    banner::print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { file } => {
            metadata::analyze_file(&file)?;
        }

        Commands::Encode { command } => match command {
            EncodeCommands::Lsb {
                input,
                output,
                message,
                passphrase,
            } => {
                stego::lsb::encode(&input, &output, &message, &passphrase)?;
            }

            EncodeCommands::Hybrid {
                input,
                output,
                message,
                passphrase,
            } => {
                stego::hybrid::encode(&input, &output, &message, &passphrase)?;
            }
        },

        Commands::Decode { command } => match command {
            DecodeCommands::Lsb { input, passphrase } => {
                stego::lsb::decode(&input, &passphrase)?;
            }

            DecodeCommands::Hybrid { input, passphrase } => {
                stego::hybrid::decode(&input, &passphrase)?;
            }
        },

        Commands::Report { file, format } => {
            report::generate_report(&file, &format)?;
        }

        Commands::Detect { file } => {
            detection::analyze_stego(&file)?;
        }
    }

    Ok(())
}

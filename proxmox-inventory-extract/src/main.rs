use clap::Parser;
use proxmox_inventory_extract::cli::Args;
use proxmox_inventory_extract::extractor::run_orchestrator;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let exit_code = run_orchestrator(args).await;
    std::process::exit(exit_code);
}

//! The `dig` binary (§4.4, §32).
//!
//! Usage and output behavior are courted against the pinned oracle binary by
//! the `CLI-DIG-*` courts.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rc = bind9_tools::dig::run(&args);
    std::process::exit(rc);
}

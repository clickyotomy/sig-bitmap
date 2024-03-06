use clap::Parser;
use sig_bitmap::{interpret, SigBitmapArgs};

/// Parse command line arguments, display the bitmap.
fn main() {
    let args: SigBitmapArgs = SigBitmapArgs::parse();
    interpret(&args);
}

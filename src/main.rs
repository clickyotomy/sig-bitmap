use clap::Parser;
use sig_bitmap::{sig_bitmap, SigBitmapArgs};

/// Parse command line arguments, display the bitmap.
fn main() {
    let args: SigBitmapArgs = SigBitmapArgs::parse();
    sig_bitmap(&args);
}

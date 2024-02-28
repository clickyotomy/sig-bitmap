use clap::Parser;
use sig_bitmap::{sig_bitmap, SigBitmapArgs};

fn main() {
    let args = SigBitmapArgs::parse();
    sig_bitmap(&args);
}

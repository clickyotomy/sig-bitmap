//! # Signal Bitmap Interpreter
//
//! A simple library to interpret signal bitmaps for a process, read
//! from `/proc/<pid>/status`. Supported signal bitmaps include pending
//! signals (`SigPnd`), shared pending signals (`ShdPnd`), blocked signals
//! (`SigBlk`), ignored signals (`SigIgn`), and caught signals (`SigCgt`).
#![warn(unused_extern_crates)]
use clap::{Parser, ValueEnum};
use std::{
    cmp::Ordering,
    fmt,
    fs::File,
    io::{BufRead, BufReader, Error},
};
use textwrap::{fill, Options};

// Maximum dosplay column width.
const MAX_WIDTH: usize = 80;

// Subsequent column width (after header).
const SUB_WIDTH: usize = 45;

// Total number of signals.
const NR_SIGS: u8 = 64;

// Realtime signals (min and max).
const SIGRTMIN_STR: &str = "RTMIN";
const SIGRTMAX_STR: &str = "RTMAX";

// Index of RT{MIN,MAX} signals (relative to the table).
const SIGRTMIN_IDX: u8 = 0x22;
const SIGRTMAX_IDX: u8 = 0x40;

// A table of string representation of signals.
static SIG_TAB: &[&str; 32] = &[
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1",
    "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP",
    "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
    "POLL", "IO", "PWR", "SYS",
];

// Range values for signals.
static POSIX_RANGE: std::ops::Range<u8> = 0x01..0x20;
static RTMIN_RANGE: std::ops::Range<u8> = 0x20..0x32;
static RTMAX_RANGE: std::ops::Range<u8> = 0x32..0x41;

/// The type of signal bitmap.
#[derive(ValueEnum, Clone, Debug, Default)]
pub enum BitmapType {
    /// Pending signals (thread).
    #[default]
    SigPnd,

    /// Pending signals (shared between threads in a process).
    ShdPnd,

    /// Blocked signals.
    SigBlk,

    /// Ignored signals.
    SigIgn,

    /// Caught signals.
    SigCgt,
}

/// Interpret signal bitmaps for a process.
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
pub struct SigBitmapArgs {
    /// PID of the process.
    #[arg(short, long)]
    pub pid: u32,

    /// Type of bitmap to interpret.
    #[arg(short, long, value_enum, default_value_t=BitmapType::SigPnd)]
    pub map: BitmapType,
}

// String representation (line prefix in `/proc<pid>/status`)
// of a signal bitmap type.
impl fmt::Display for BitmapType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BitmapType::SigPnd => write!(f, "SigPnd:"),
            BitmapType::ShdPnd => write!(f, "ShdPnd:"),
            BitmapType::SigBlk => write!(f, "SigBlk:"),
            BitmapType::SigIgn => write!(f, "SigIgn:"),
            BitmapType::SigCgt => write!(f, "SigCgt:"),
        }
    }
}

// Return the string representation of a signal number.
// This is specifically used for RT{MIN,MAX}+/-N.
fn fmt_range(idx: &u8, off: &u8, tmpl: &str) -> String {
    let diff: i8 = (*idx as i8) - (*off as i8);
    match diff.cmp(&0) {
        Ordering::Equal => tmpl.to_string(),
        _ => format!("{}{:+}", tmpl, diff),
    }
}

// Return a string describing the signal number
// index passed in the argument `idx`.
fn sigabbrev_np(idx: &u8) -> String {
    if POSIX_RANGE.contains(idx) {
        return SIG_TAB[(*idx as usize) - 1].to_string();
    }

    if RTMIN_RANGE.contains(idx) {
        return fmt_range(idx, &SIGRTMIN_IDX, SIGRTMIN_STR);
    }

    if RTMAX_RANGE.contains(idx) {
        return fmt_range(idx, &SIGRTMAX_IDX, SIGRTMAX_STR);
    }

    String::from("INVL")
}

/// Returns a list of signals interpreted from the specified bitmap.
/// # Arguments
/// * `map` - Reference to an unsigned 64-bit integer holding
///           the bitmap as its contents.
///
/// # Example
/// ```
/// use sig_bitmap::interpret;
/// let bit_map: u64 = 0xdead;
/// let sig_lst: Vec<String> = interpret(&bit_map);
/// let sig_exp: Vec<&str> = vec![
///     "HUP", "QUIT", "ILL", "ABRT", "FPE","USR1",
///     "SEGV", "USR2", "PIPE", "TERM", "STKFLT",
/// ];
/// assert_eq!(sig_lst, sig_exp);
/// ````
pub fn interpret(map: &u64) -> Vec<String> {
    let mut sig_idx: u8 = 0x1;
    let mut sig_vec: Vec<String> = Vec::new();

    while sig_idx < NR_SIGS {
        if (map & (0x1_u64 << (sig_idx - 1))) != 0 {
            sig_vec.push(sigabbrev_np(&sig_idx).to_string());
        }
        sig_idx += 1;
    }

    sig_vec
}

// Return the parsed value of the string representation
// of the signal bitmap.
fn proc_bitmap(pid: &u32, typ: &BitmapType) -> u64 {
    let lpfx: String = typ.to_string();
    let file: Result<File, Error> =
        File::open(format!("/proc/{}/status", pid).as_str());

    if let Ok(fread) = file {
        let fbuff: BufReader<File> = BufReader::new(fread);
        for line in fbuff.lines().flatten() {
            if line.starts_with(&lpfx) {
                return u64::from_str_radix(
                    line.trim_start_matches(&lpfx).trim(),
                    16,
                )
                .unwrap();
            }
        }
    }

    0x0
}

/// Displays the formatted string representaion of the specified
/// type of signal bitmap for a given process. This function outputs
/// an empty map if the process doesn't exist or if there is an error
/// interpreting the signal bitmap.
///
/// # Arguments
///
/// * `args` - A reference to an `enum` containing the process
///            ID (PID) and the signal bitmap type.
/// # Returns
///
/// A `Vec<String>` containing a list of interpreted signals.
///
/// # Example
/// ```
/// // Print the list of signals ignored by a process with PID: 42.
/// use sig_bitmap::{sig_bitmap, BitmapType, SigBitmapArgs};
/// let args: SigBitmapArgs = SigBitmapArgs{pid: 42, map: BitmapType::SigIgn};
/// sig_bitmap(&args);
/// ````
pub fn sig_bitmap(args: &SigBitmapArgs) {
    let bit_map: u64 = proc_bitmap(&args.pid, &args.map);
    let sub_fmt: &str = &" ".repeat(SUB_WIDTH);
    let sig_lst: Vec<String> = interpret(&bit_map);

    let lst_fmt: String = match sig_lst.is_empty() {
        true => String::from("NONE"),
        false => sig_lst.join(", "),
    };

    let out: String = fill(
        &format!(
            "PID: {:<6} {} {:<2} [0x{:016x}]: {}",
            args.pid,
            args.map,
            sig_lst.len(),
            bit_map,
            lst_fmt,
        ),
        Options::new(MAX_WIDTH)
            .subsequent_indent(sub_fmt)
            .word_splitter(textwrap::WordSplitter::NoHyphenation)
            .break_words(false),
    );

    println!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigabbrev_np() {
        let tests: Vec<(&str, u8)> = Vec::<(&str, u8)>::from([
            ("KILL", 0x09),
            ("RTMIN", 0x22),
            ("RTMIN+2", 0x24),
            ("RTMAX", 0x40),
            ("RTMAX-2", 0x3e),
            ("INVL", 0x00),
        ]);

        for test in tests {
            assert_eq!(test.0, sigabbrev_np(&test.1));
        }
    }

    #[test]
    fn test_bit_map_type_str() {
        let tests: Vec<(BitmapType, &str)> = Vec::<(BitmapType, &str)>::from([
            (BitmapType::SigPnd, "SigPnd"),
            (BitmapType::ShdPnd, "ShdPnd"),
            (BitmapType::SigBlk, "SigBlk"),
            (BitmapType::SigIgn, "SigIgn"),
            (BitmapType::SigCgt, "SigCgt"),
        ]);

        for test in tests {
            assert!(test.0.to_string().contains(test.1));
        }
    }
    #[test]
    fn test_interpret() {
        let bit_map: u64 = 0xbadc0ffee;
        let sig_chk: Vec<&str> = vec![
            "INT", "QUIT", "ILL", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV",
            "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "URG", "XCPU", "XFSZ",
            "PROF", "WINCH", "IO", "RTMIN-2", "RTMIN-1", "RTMIN", "RTMIN+2",
        ];
        let sig_ret: Vec<String> = interpret(&bit_map);
        assert_eq!(sig_ret, sig_chk);
    }
}

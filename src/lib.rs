//! # Signal Bitmap Interpreter
//
//! This module provides functionality to interpret signal
//! bitmaps read from `/proc/<pid>/status`. Supported signal
//! bitmaps include pending signals (`SigPnd`), shared pending
//! signals (`ShdPnd`), blocked signals (`SigBlk`), ignored
//! signals (`SigIgn`), and caught signals (`SigCgt`).
#![warn(unused_extern_crates)]
use clap::{Parser, ValueEnum};
use std::{
    cmp::Ordering,
    fmt,
    fs::File,
    io::{BufRead, BufReader, Error},
};
use textwrap::{fill, Options};

const SUB_WIDTH: usize = 45;
const MAX_WIDTH: usize = 80;

const NR_SIGS: u8 = 64;
const SIGRTMIN_STR: &str = "RTMIN";
const SIGRTMAX_STR: &str = "RTMAX";
const SIGRTMIN_IDX: u8 = 0x22;
const SIGRTMAX_IDX: u8 = 0x40;

static SIG_TAB: &[&str; 32] = &[
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1",
    "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP",
    "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
    "POLL", "IO", "PWR", "SYS",
];
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

    "INVL".to_string()
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

// Return the formatted string representation of all the
// signals contained in the signal bitmap `map`.
fn fmt_bitmap(map: &u64) -> (String, u8) {
    let mut sig_idx: u8 = 0x1;
    let mut sig_cnt: u8 = 0x0;
    let mut sig_vec: Vec<String> = Vec::new();

    while sig_idx < NR_SIGS {
        if (map & (0x1_u64 << (sig_idx - 1))) != 0 {
            sig_vec.push(sigabbrev_np(&sig_idx));
            sig_cnt += 1;
        }
        sig_idx += 1;
    }

    (sig_vec.join(", "), sig_cnt)
}

/// Displays the formatted string representaion of the specified type
/// of signal bitmap for a given process. This function doesn't output
/// anything if the process doesn't exist or if there is an error
/// interpreting the signal bitmap.
/// 
/// # Arguments
///
/// * `args` - A reference to an `enum` containing the process
///            ID (PID) and the signal bitmap type.
///
/// # Example
/// ```
/// // Print the list of signals ignored by a process with PID: 42.
/// let args: SigBitmapArgs = SigBitmapArgs{pid: 42, typ: BitmapType::SigIgn};
/// sig_bitmap(&args);
/// ````
pub fn interpret(args: &SigBitmapArgs) {
    let bmap: u64 = proc_bitmap(&args.pid, &args.map);
    let sfmt: &str = &" ".repeat(SUB_WIDTH);

    if bmap > 0 {
        let (lst, cnt): (String, u8) = fmt_bitmap(&bmap);
        let out: String = fill(
            &format!(
                "PID: {:<6} {} {:<2} [0x{:016x}]: {}",
                args.pid, args.map, cnt, bmap, lst,
            ),
            Options::new(MAX_WIDTH)
                .subsequent_indent(sfmt)
                .word_splitter(textwrap::WordSplitter::NoHyphenation)
                .break_words(false),
        );

        println!("{out}");
    }
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
    fn test_bitmaptype_str() {
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
    fn test_fmt_bitmap() {
        let bmap: u64 = 0xbadc0ffee;
        let sigs: &str = "INT, QUIT, ILL, ABRT, BUS, FPE, KILL, USR1, \
            SEGV, USR2, PIPE, ALRM, TERM, STKFLT, URG, XCPU, XFSZ, PROF, \
            WINCH, IO, RTMIN-2, RTMIN-1, RTMIN, RTMIN+2";
        let (sfmt, count): (String, u8) = fmt_bitmap(&bmap);
        assert_eq!(sfmt, sigs);
        assert_eq!(count, 24);
    }
}

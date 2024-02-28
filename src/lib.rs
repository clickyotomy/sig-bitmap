#![warn(unused_extern_crates)]
use clap::{Parser, ValueEnum};
use std::{
    cmp::Ordering,
    fmt,
    fs::File,
    io::{BufRead, BufReader, Error},
};
use textwrap::{fill, Options};

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum BitmapType {
    #[default]
    SigPnd,
    ShdPnd,
    SigBlk,
    SigIgn,
    SigCgt,
}

/// Interpret signal bit-maps for a process.
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
pub struct SigBitmapArgs {
    /// PID of the process.
    #[arg(short, long)]
    pid: u32,

    /// Type of bit-map to interpret.
    #[arg(short, long, value_enum, default_value_t=BitmapType::SigPnd)]
    map: BitmapType,
}

const NR_SIGS: u8 = 64;
const SUB_COL: usize = 45;
const MAX_COL: usize = 80;

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

fn proc_bitmap(pid: &u32, typ: &BitmapType) -> u64 {
    let lnpfx: String = typ.to_string();
    let fopen: Result<File, Error> =
        File::open(format!("/proc/{}/status", pid).as_str());

    if let Ok(fread) = fopen {
        let fbuff: BufReader<File> = BufReader::new(fread);
        for line in fbuff.lines().flatten() {
            if line.starts_with(&lnpfx) {
                if let Ok(bits) = u64::from_str_radix(
                    line.trim_start_matches(&lnpfx).trim(),
                    16,
                ) {
                    return bits;
                }
            }
        }
    }

    0x0
}

fn fmt_range(idx: &u8, off: &u8, tmpl: &str) -> String {
    let diff: i8 = (*idx as i8) - (*off as i8);
    match diff.cmp(&0) {
        Ordering::Equal => tmpl.to_string(),
        _ => format!("{}{:+}", tmpl, diff),
    }
}

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

pub fn sig_bitmap(args: &SigBitmapArgs) {
    let bmap: u64 = proc_bitmap(&args.pid, &args.map);
    let sfmt: &str = &" ".repeat(SUB_COL);

    if bmap > 0 {
        let (lst, cnt): (String, u8) = fmt_bitmap(&bmap);
        let raw: String = format!(
            "PID: {:<6} {} {:<2} [0x{:016x}]: {}",
            args.pid, args.map, cnt, bmap, lst
        );

        println!(
            "{}",
            fill(
                &raw,
                Options::new(MAX_COL)
                    .subsequent_indent(sfmt)
                    .word_splitter(textwrap::WordSplitter::NoHyphenation)
                    .break_words(false)
            )
        );
    }
}

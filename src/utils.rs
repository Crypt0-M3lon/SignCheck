use chrono::{DateTime, Utc};
use windows::Win32::Foundation::FILETIME;

/// Converts a Rust `&str` to a Windows wide string (`Vec<u16>`) with a
/// trailing null terminator suitable for passing to Win32 APIs.
pub fn to_wide_null_terminated(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Converts a Windows FILETIME structure to a DateTime<Utc>
///
/// # Arguments
/// * `ft` - The FILETIME structure to convert
///
/// # Returns
/// A DateTime<Utc> representing the same time, or Unix epoch if conversion fails
///
/// # Note
/// Windows FILETIME is the number of 100-nanosecond intervals since January 1, 1601 UTC.
/// We convert this to Unix timestamp (seconds since January 1, 1970 UTC).
pub fn filetime_to_datetime(ft: FILETIME) -> DateTime<Utc> {
    const FILETIME_TO_UNIX_EPOCH: u64 = 116444736000000000;
    const HUNDRED_NANOSECONDS_PER_SECOND: u64 = 10000000;

    let time = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    let unix = (time.saturating_sub(FILETIME_TO_UNIX_EPOCH)) / HUNDRED_NANOSECONDS_PER_SECOND;
    DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
}

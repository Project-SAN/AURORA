use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use uefi::table::runtime::Time;

const TICK_MS: u64 = 10;
const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = 24 * 60 * 60;

static BASE_EPOCH: AtomicU64 = AtomicU64::new(0);
static BASE_TICKS: AtomicU64 = AtomicU64::new(0);
static HAS_TIME: AtomicBool = AtomicBool::new(false);

pub fn init_from_uefi(time: Time, ticks_now: u64) -> bool {
    if !time.is_valid() {
        return false;
    }
    let epoch = match unix_epoch_seconds(&time) {
        Some(val) => val,
        None => return false,
    };
    BASE_EPOCH.store(epoch, Ordering::Release);
    BASE_TICKS.store(ticks_now, Ordering::Release);
    HAS_TIME.store(true, Ordering::Release);
    true
}

pub fn epoch_seconds_now(ticks_now: u64) -> Option<u64> {
    if !HAS_TIME.load(Ordering::Acquire) {
        return None;
    }
    let base_epoch = BASE_EPOCH.load(Ordering::Acquire);
    let base_ticks = BASE_TICKS.load(Ordering::Acquire);
    let delta_ticks = ticks_now.saturating_sub(base_ticks);
    let delta_ms = (delta_ticks as u128) * (TICK_MS as u128);
    let delta_sec = (delta_ms / 1000) as u64;
    Some(base_epoch.saturating_add(delta_sec))
}

fn unix_epoch_seconds(time: &Time) -> Option<u64> {
    let year = time.year() as i32;
    let month = time.month() as i32;
    let day = time.day() as i32;
    let hour = time.hour() as i64;
    let minute = time.minute() as i64;
    let second = time.second() as i64;

    if year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    days += days_before_month(year, month);
    days += (day - 1) as i64;

    let mut secs = days * SECS_PER_DAY + hour * SECS_PER_HOUR + minute * SECS_PER_MIN + second;
    if let Some(offset_min) = time.time_zone() {
        secs -= (offset_min as i64) * SECS_PER_MIN;
    }

    if secs < 0 {
        return None;
    }
    Some(secs as u64)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_before_month(year: i32, month: i32) -> i64 {
    const DAYS_BEFORE: [i32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = DAYS_BEFORE[(month - 1) as usize] as i64;
    if is_leap(year) && month > 2 {
        days += 1;
    }
    days
}

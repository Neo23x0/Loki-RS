use std::time::{Duration, Instant};
use std::thread;
use std::cell::RefCell;

thread_local! {
    pub static THROTTLER: RefCell<CpuThrottler> = RefCell::new(CpuThrottler::new(100));
}

pub struct CpuThrottler {
    target_percent: u8,
    work_start: Option<Instant>,
    accumulated_work_ns: u64,
    last_throttle_check: Instant,
}

impl CpuThrottler {
    pub fn new(target_percent: u8) -> Self {
        let percent = target_percent.clamp(1, 100);
        Self {
            target_percent: percent,
            work_start: None,
            accumulated_work_ns: 0,
            last_throttle_check: Instant::now(),
        }
    }

    pub fn set_target(&mut self, target_percent: u8) {
        self.target_percent = target_percent.clamp(1, 100);
    }

    pub fn start_work(&mut self) {
        if self.target_percent >= 100 {
            return;
        }
        self.work_start = Some(Instant::now());
    }

    pub fn end_work_and_throttle(&mut self) {
        if self.target_percent >= 100 {
            return;
        }

        if let Some(start) = self.work_start.take() {
            let work_duration = start.elapsed();
            self.accumulated_work_ns += work_duration.as_nanos() as u64;

            let min_batch_ns: u64 = 10_000_000;
            if self.accumulated_work_ns >= min_batch_ns {
                let sleep_ns = self.calculate_sleep_ns(self.accumulated_work_ns);
                if sleep_ns > 0 {
                    thread::sleep(Duration::from_nanos(sleep_ns));
                }
                self.accumulated_work_ns = 0;
                self.last_throttle_check = Instant::now();
            }
        }
    }

    fn calculate_sleep_ns(&self, work_ns: u64) -> u64 {
        if self.target_percent >= 100 || self.target_percent == 0 {
            return 0;
        }
        let target = self.target_percent as u64;
        (work_ns * (100 - target)) / target
    }
}

pub fn init_thread_throttler(target_percent: u8) {
    THROTTLER.with(|t| {
        t.borrow_mut().set_target(target_percent);
    });
}

pub fn throttle_start() {
    THROTTLER.with(|t| {
        t.borrow_mut().start_work();
    });
}

pub fn throttle_end() {
    THROTTLER.with(|t| {
        t.borrow_mut().end_work_and_throttle();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_throttler_creation_default() {
        let throttler = CpuThrottler::new(100);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_creation_clamped_high() {
        let throttler = CpuThrottler::new(150);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_creation_clamped_low() {
        let throttler = CpuThrottler::new(0);
        assert_eq!(throttler.target_percent, 1);
    }

    #[test]
    fn test_throttler_set_target() {
        let mut throttler = CpuThrottler::new(100);
        throttler.set_target(50);
        assert_eq!(throttler.target_percent, 50);
    }

    #[test]
    fn test_throttler_set_target_clamped() {
        let mut throttler = CpuThrottler::new(100);
        throttler.set_target(0);
        assert_eq!(throttler.target_percent, 1);
        throttler.set_target(200);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_100_percent_no_sleep() {
        let mut throttler = CpuThrottler::new(100);
        let start = Instant::now();
        throttler.start_work();
        std::thread::sleep(Duration::from_millis(1));
        throttler.end_work_and_throttle();
        assert!(start.elapsed().as_millis() < 50);
    }

    #[test]
    fn test_calculate_sleep_ns_50_percent() {
        let throttler = CpuThrottler::new(50);
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        assert_eq!(sleep_ns, 10_000_000);
    }

    #[test]
    fn test_calculate_sleep_ns_100_percent() {
        let throttler = CpuThrottler::new(100);
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        assert_eq!(sleep_ns, 0);
    }

    #[test]
    fn test_thread_local_functions() {
        init_thread_throttler(50);
        THROTTLER.with(|t| {
            assert_eq!(t.borrow().target_percent, 50);
        });

        throttle_start();
        THROTTLER.with(|t| {
            assert!(t.borrow().work_start.is_some());
        });
    }
}

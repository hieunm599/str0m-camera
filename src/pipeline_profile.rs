//! Local opt-in pipeline diagnostics. Never hold a context or span across await.
#![allow(missing_docs)]
use std::{
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Default, Clone)]
pub struct Metric {
    pub calls: u64,
    pub wall_us: u64,
    pub cpu_us: u64,
    pub exclusive_cpu_us: u64,
    pub cpu_samples: u64,
    pub bytes: u64,
    pub max_us: u64,
    pub histogram: [u64; 32],
}
impl Metric {
    fn record(&mut self, wall: u64, cpu: Option<u64>, children: u64, bytes: usize) {
        self.calls += 1;
        self.wall_us += wall;
        if let Some(cpu) = cpu {
            self.cpu_samples += 1;
            self.cpu_us += cpu;
            self.exclusive_cpu_us += cpu.saturating_sub(children);
        }
        self.bytes += bytes as u64;
        self.max_us = self.max_us.max(wall);
        self.histogram[bucket(wall)] += 1;
    }
    pub fn percentile_upper_us(&self, percent: u64) -> u64 {
        let target = (self.calls * percent).div_ceil(100);
        let mut n = 0;
        for (i, count) in self.histogram.iter().enumerate() {
            n += count;
            if n >= target {
                return if i == 31 {
                    self.max_us
                } else {
                    (1u64 << i).min(self.max_us)
                };
            }
        }
        self.max_us
    }
}
fn bucket(us: u64) -> usize {
    if us <= 1 {
        0
    } else {
        (64 - (us - 1).leading_zeros() as usize).min(31)
    }
}
struct State {
    since: Instant,
    window: u64,
    metrics: BTreeMap<(&'static str, &'static str), Metric>,
}
#[derive(Clone)]
pub struct Collector {
    pub peer: u32,
    cpu: fn() -> Option<u64>,
    every: u64,
    entries: Arc<std::sync::atomic::AtomicU32>,
    state: Arc<Mutex<State>>,
}
impl Collector {
    pub fn new(peer: u32, cpu: fn() -> Option<u64>) -> Self {
        Self {
            peer,
            cpu,
            every: if std::env::var("LUMI_PIPELINE_PROFILE").as_deref() == Ok("0")
                || std::env::var("LUMI_CRYPTO_PROFILE").as_deref() == Ok("0")
            {
                0
            } else if std::env::var("LUMI_PIPELINE_EVERY").as_deref() == Ok("64") {
                64
            } else {
                1
            },
            entries: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            state: Arc::new(Mutex::new(State {
                since: Instant::now(),
                window: 0,
                metrics: BTreeMap::new(),
            })),
        }
    }
    pub fn enter(&self) -> Context {
        let selected = self.every > 0
            && self.entries.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64
                % self.every == 0;
        let previous = CURRENT.with(|c| c.replace(selected.then(|| self.clone())));
        Context {
            previous,
            _local: PhantomData,
        }
    }
    pub fn observe(&self, phase: &'static str, us: u64, bytes: usize) {
        if self.every==0 {return;}
        self.state
            .lock()
            .unwrap()
            .metrics
            .entry((phase, "wall_only"))
            .or_default()
            .record(us, None, 0, bytes);
    }
    pub fn report(&self, force: bool) {
        let mut s = self.state.lock().unwrap();
        let elapsed = s.since.elapsed();
        if !force && elapsed.as_secs() < 5 {
            return;
        }
        s.window += 1;
        let report_unix_us = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros()).unwrap_or(0);
        for ((phase, parent), m) in &s.metrics {
            eprintln!(
                "component=webrtc event=pipeline_profile report_unix_us={report_unix_us} peer={} window={} interval_us={} phase={} parent={} calls={} wall_us={} cpu_us={} exclusive_cpu_us={} cpu_samples={} bytes={} max_us={} p50_upper_us={} p95_upper_us={} p99_upper_us={}",
                self.peer,
                s.window,
                elapsed.as_micros(),
                phase,
                parent,
                m.calls,
                m.wall_us,
                m.cpu_us,
                m.exclusive_cpu_us,
                m.cpu_samples,
                m.bytes,
                m.max_us,
                m.percentile_upper_us(50),
                m.percentile_upper_us(95),
                m.percentile_upper_us(99)
            );
        }
        s.metrics.clear();
        s.since = Instant::now();
    }
}
thread_local! {
    static CURRENT: RefCell<Option<Collector>> = const { RefCell::new(None) };
    static STACK: RefCell<Vec<(&'static str, u64)>> = const { RefCell::new(Vec::new()) };
}
pub struct Context {
    previous: Option<Collector>,
    _local: PhantomData<Rc<()>>,
}
impl Drop for Context {
    fn drop(&mut self) {
        CURRENT.with(|c| {
            c.replace(self.previous.take());
        });
    }
}
pub struct Span {
    collector: Option<Collector>,
    phase: &'static str,
    parent: &'static str,
    wall: Option<Instant>,
    cpu: Option<u64>,
    bytes: usize,
    _local: PhantomData<Rc<()>>,
}
impl Span {
    pub fn new(phase: &'static str, bytes: usize) -> Self {
        let collector = CURRENT.with(|c| c.borrow().clone());
        let parent = if collector.is_some() {
            STACK.with(|s| {
                let mut s = s.borrow_mut();
                let parent = s.last().map_or("root", |x| x.0);
                s.push((phase, 0));
                parent
            })
        } else {
            "unattributed"
        };
        let cpu = collector.as_ref().and_then(|c| (c.cpu)());
        let wall=collector.as_ref().map(|_|Instant::now());
        Self {
            collector,
            phase,
            parent,
            wall,
            cpu,
            bytes,
            _local: PhantomData,
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(c) = &self.collector else {
            return;
        };
        let cpu = self.cpu.zip((c.cpu)()).map(|(a, b)| b.saturating_sub(a));
        let wall = self.wall.unwrap().elapsed().as_micros() as u64;
        let children = STACK.with(|s| {
            let mut s = s.borrow_mut();
            let (phase, children) = s.pop().expect("span stack");
            debug_assert_eq!(phase, self.phase);
            if let Some(parent) = s.last_mut() {
                parent.1 += cpu.unwrap_or(0);
            }
            children
        });
        c.state
            .lock()
            .unwrap()
            .metrics
            .entry((self.phase, self.parent))
            .or_default()
            .record(wall, cpu, children, self.bytes);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_and_sparse_contexts_do_not_attribute_unsampled_spans() {
        let mut collector=Collector::new(77, ||Some(0));
        collector.every=0;
        {let _ctx=collector.enter(); let _span=Span::new("disabled",1);}
        assert!(collector.state.lock().unwrap().metrics.is_empty());
        collector.every=64;
        for _ in 0..129 {
            let _ctx=collector.enter();
            let _outer=Span::new("sampled",0);
            let _inner=Span::new("cipher",100);
        }
        let state=collector.state.lock().unwrap();
        assert_eq!(state.metrics[&("sampled","root")].calls,3);
        assert_eq!(state.metrics[&("cipher","sampled")].bytes,300);
        CURRENT.with(|c|assert!(c.borrow().is_none()));
    }
    #[test]
    fn histogram_bounds_and_missing_clock() {
        let mut m = Metric::default();
        for us in [0, 1, 2, 3, 4, 100] {
            m.record(us, None, 0, 0);
        }
        assert_eq!(m.percentile_upper_us(50), 2);
        assert_eq!(m.percentile_upper_us(95), 100);
        assert_eq!(m.cpu_samples, 0);
    }
    #[test]
    fn exclusive_accounting_subtracts_children() {
        let mut m = Metric::default();
        m.record(600, Some(500), 300, 1200);
        assert_eq!(m.cpu_us, 500);
        assert_eq!(m.exclusive_cpu_us, 200);
        assert_eq!(m.cpu_samples, 1);
    }
    #[test]
    fn nested_spans_are_attributed_to_peer_and_parent() {
        let a = Collector::new(1, || Some(0));
        let b = Collector::new(2, || None);
        {
            let _ctx = a.enter();
            let _root = Span::new("poll", 0);
            {
                let _child = Span::new("cipher", 1200);
            }
        }
        {
            let _ctx = b.enter();
            let _root = Span::new("poll", 0);
        }
        let a = a.state.lock().unwrap();
        assert_eq!(a.metrics[&("cipher", "poll")].bytes, 1200);
        assert_eq!(a.metrics[&("poll", "root")].calls, 1);
        assert_eq!(b.state.lock().unwrap().metrics.len(), 1);
        CURRENT.with(|c| assert!(c.borrow().is_none()));
    }
}

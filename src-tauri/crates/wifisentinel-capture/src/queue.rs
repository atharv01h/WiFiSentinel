// wifisentinel-capture/src/queue.rs
// Bounded packet queue with backpressure.
//
// Prevents unbounded memory growth during high-rate capture.
// When the queue is full, new frames are dropped and the drop counter increments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A raw captured frame.
#[derive(Debug)]
pub struct RawFrame {
    /// Frame data (including Radiotap header if present).
    pub data: Vec<u8>,
    /// Capture timestamp (microseconds since epoch).
    pub timestamp_us: u64,
    /// Original length before any truncation.
    pub original_len: u32,
    /// Captured length (may be < original_len if snaplen truncated).
    pub captured_len: u32,
}

/// A bounded packet queue with backpressure counters.
pub struct BoundedQueue {
    sender: mpsc::Sender<RawFrame>,
    receiver: Option<mpsc::Receiver<RawFrame>>,
    dropped: Arc<AtomicU64>,
    capacity: usize,
}

impl BoundedQueue {
    /// Create a new bounded queue.
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            sender: tx,
            receiver: Some(rx),
            dropped: Arc::new(AtomicU64::new(0)),
            capacity,
        }
    }

    /// Try to enqueue a frame. If the queue is full, drops the frame and
    /// increments the drop counter (backpressure).
    pub fn try_send(&self, frame: RawFrame) {
        match self.sender.try_send(frame) {
            Ok(()) => {}
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Take the receiver (can only be done once).
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<RawFrame>> {
        self.receiver.take()
    }

    /// Clone the sender for use in the capture thread.
    pub fn sender(&self) -> mpsc::Sender<RawFrame> {
        self.sender.clone()
    }

    /// Returns the total number of dropped frames since creation.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns the queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns an Arc clone of the drop counter for sharing with the capture thread.
    pub fn drop_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }
}

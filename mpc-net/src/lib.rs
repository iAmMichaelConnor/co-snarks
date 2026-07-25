//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};

// Shared async-transport core, used by the QUIC and ephemeral-TCP-session backends.
#[cfg(any(feature = "quic", feature = "tcp-session"))]
mod async_net;
// Shared blocking-transport core, used by the TCP and TLS backends.
#[cfg(any(feature = "tcp", feature = "tls"))]
mod blocking;
pub mod config;
#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "tcp-session")]
pub mod tcp_session;
#[cfg(feature = "tls")]
pub mod tls;

/// The default max frame length for sending messages
pub const DEFAULT_MAX_FRAME_LENGTH: usize = 64 * 1024 * 1024; // 64MB

/// A MPC network that can be used to send and receive data to and from other parties
///
/// Can be used to send to multiple parties in parallel, but sending to the same party must happen in sequence.
pub trait Network: Send + Sync {
    /// The id of the party
    fn id(&self) -> usize;
    /// Send data to other party.
    ///
    /// Takes [`Bytes`] so the same buffer can be cheaply handed to multiple peers
    /// (a reference-count bump per recipient, e.g. when broadcasting) and so backends
    /// that buffer sends can enqueue it without copying.
    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()>;
    /// Receive data from other party.
    ///
    /// Returns [`Bytes`] so backends whose framing already produces a reference-counted
    /// buffer (e.g. QUIC) can hand it back without an extra copy.
    fn recv(&self, from: usize) -> eyre::Result<Bytes>;

    /// Ensure all previously [`send`](Network::send)ed data has been handed off to
    /// the operating system, and surface any error encountered while doing so.
    ///
    /// Backends that buffer sends on a background writer (e.g. TCP/TLS) flush their
    /// queues here; backends that write inline return `Ok(())`. Call this at the end
    /// of a protocol to confirm that the final sends — which may not be followed by a
    /// receive — actually left the process.
    fn flush(&self) -> eyre::Result<()> {
        Ok(())
    }

    /// Get connection statistics for the Network.
    /// The returned HashMap maps party_id to a tuple of (sent_bytes, received_bytes).
    fn get_connection_stats(&self) -> ConnectionStats;
}

// This implements a dummy network that is used for plain variants of MPC protocols
impl Network for () {
    fn id(&self) -> usize {
        0
    }

    fn send(&self, _to: usize, _data: Bytes) -> eyre::Result<()> {
        Ok(())
    }

    fn recv(&self, _from: usize) -> eyre::Result<Bytes> {
        Ok(Bytes::new())
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            my_id: 0,
            stats: BTreeMap::new(),
            msgs: BTreeMap::new(),
        }
    }
}

/// Per-direction traffic counters for one peer connection: application payload bytes
/// and framed message count (one `send`/`recv` call = one message). Updated with
/// `Relaxed` atomics so the per-message overhead is negligible.
#[cfg(any(
    feature = "tcp",
    feature = "tls",
    feature = "quic",
    feature = "tcp-session",
    feature = "local"
))]
#[derive(Debug, Default)]
pub(crate) struct TrafficCounters {
    bytes: std::sync::atomic::AtomicUsize,
    msgs: std::sync::atomic::AtomicUsize,
}

#[cfg(any(
    feature = "tcp",
    feature = "tls",
    feature = "quic",
    feature = "tcp-session",
    feature = "local"
))]
impl TrafficCounters {
    /// Record one message of `len` payload bytes.
    pub(crate) fn record(&self, len: usize) {
        self.bytes
            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        self.msgs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Load the current (bytes, messages) counts.
    pub(crate) fn load(&self) -> (usize, usize) {
        (
            self.bytes.load(std::sync::atomic::Ordering::Relaxed),
            self.msgs.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Statistics about the number of bytes and framed messages sent over the network.
pub struct ConnectionStats {
    my_id: usize,
    stats: BTreeMap<usize, (usize, usize)>,
    msgs: BTreeMap<usize, (usize, usize)>,
}

impl ConnectionStats {
    /// Create new `ConnectionStats` from per-peer (sent_bytes, recv_bytes) counts.
    /// Message counts are reported as zero; backends that track them should use
    /// [`ConnectionStats::new_with_msgs`] instead.
    pub fn new(my_id: usize, stats: BTreeMap<usize, (usize, usize)>) -> Self {
        let msgs = stats.keys().map(|&id| (id, (0, 0))).collect();
        Self { my_id, stats, msgs }
    }

    /// Create new `ConnectionStats` from per-peer (sent_bytes, recv_bytes) and
    /// (sent_msgs, recv_msgs) counts.
    pub fn new_with_msgs(
        my_id: usize,
        stats: BTreeMap<usize, (usize, usize)>,
        msgs: BTreeMap<usize, (usize, usize)>,
    ) -> Self {
        Self { my_id, stats, msgs }
    }
    /// Get connection statistics for a specific party.
    /// Returns a tuple of (sent_bytes, received_bytes) if the party_id exists, otherwise returns None.
    pub fn get(&self, party_id: usize) -> Option<(usize, usize)> {
        self.stats.get(&party_id).cloned()
    }

    /// Get an iterator over the connection statistics.
    /// Iterates over the parties in ascending order of their IDs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, (usize, usize))> {
        self.stats.iter().map(|(&id, &stats)| (id, stats))
    }

    /// Get per-party message counts as a tuple of (sent_msgs, received_msgs), or None if
    /// the party_id does not exist. One framed message corresponds to one `send`/`recv`
    /// call on the network; backends that do not track messages report zeros.
    ///
    /// The received-message count doubles as a proxy for the number of sequential MPC
    /// rounds: the protocols are synchronous, so every received message was waited on,
    /// and the count of messages received from a fixed peer (e.g. the REP3 ring
    /// predecessor) bounds the length of the sequential round chain executed with that
    /// peer.
    pub fn get_msgs(&self, party_id: usize) -> Option<(usize, usize)> {
        self.msgs.get(&party_id).cloned()
    }

    /// Get an iterator over the per-party message counts (sent_msgs, received_msgs).
    /// Iterates over the parties in ascending order of their IDs.
    pub fn iter_msgs(&self) -> impl Iterator<Item = (usize, (usize, usize))> {
        self.msgs.iter().map(|(&id, &msgs)| (id, msgs))
    }

    /// Get connection statistics for a given time period by calculating the difference between two ConnectionStats instances.
    pub fn get_diff_to(&self, other: &ConnectionStats) -> HashMap<usize, (usize, usize)> {
        let mut diff = HashMap::new();
        for (&id, &(sent, recv)) in &self.stats {
            if let Some(&(other_sent, other_recv)) = other.stats.get(&id) {
                diff.insert(id, (sent - other_sent, recv - other_recv));
            } else {
                diff.insert(id, (sent, recv));
            }
        }
        diff
    }
}

impl std::fmt::Display for ConnectionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (id, (sent, recv)) in self.iter() {
            let (sent_msgs, recv_msgs) = self.get_msgs(id).unwrap_or((0, 0));
            writeln!(
                f,
                "Party {my_id} <-> {id}: SENT {sent} bytes ({sent_msgs} msgs), RECV {recv} bytes ({recv_msgs} msgs)",
                my_id = self.my_id
            )?;
        }
        Ok(())
    }
}

/// Run 2 network closures
#[inline(always)]
pub fn join<R0: Send, R1: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
) -> (R0, R1) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = f1();
        (r0.join().expect("can join"), r1)
    })
}

/// Run 3 network closures
#[inline(always)]
pub fn join3<R0: Send, R1: Send, R2: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
) -> (R0, R1, R2) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = f2();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2,
        )
    })
}

/// Run 4 network closures
#[inline(always)]
pub fn join4<R0: Send, R1: Send, R2: Send, R3: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
) -> (R0, R1, R2, R3) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = f3();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3,
        )
    })
}

/// Run 5 network closures
#[inline(always)]
pub fn join5<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
) -> (R0, R1, R2, R3, R4) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = f4();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4,
        )
    })
}

/// Run 6 network closures
#[inline(always)]
pub fn join6<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
) -> (R0, R1, R2, R3, R4, R5) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = f5();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5,
        )
    })
}

/// Run 7 network closures
#[inline(always)]
pub fn join7<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send, R6: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
    f6: impl FnOnce() -> R6 + Send,
) -> (R0, R1, R2, R3, R4, R5, R6) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = s.spawn(f5);
        let r6 = f6();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5.join().expect("can join"),
            r6,
        )
    })
}

/// Run 8 network closures
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn join8<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send, R6: Send, R7: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
    f6: impl FnOnce() -> R6 + Send,
    f7: impl FnOnce() -> R7 + Send,
) -> (R0, R1, R2, R3, R4, R5, R6, R7) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = s.spawn(f5);
        let r6 = s.spawn(f6);
        let r7 = f7();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5.join().expect("can join"),
            r6.join().expect("can join"),
            r7,
        )
    })
}

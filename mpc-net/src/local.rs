//! Local MPC network

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use eyre::ContextCompat;
use intmap::IntMap;
use std::time::{Duration, Instant};

use crate::{ConnectionStats, Network, RoundCounters, RoundStats, TrafficCounters};

/// A MPC network using channels. Used for testing.
#[derive(Debug)]
pub struct LocalNetwork {
    id: usize,
    timeout: Option<Duration>,
    send: IntMap<usize, (Sender<Bytes>, TrafficCounters)>,
    recv: IntMap<usize, (Receiver<Bytes>, TrafficCounters, RoundCounters)>,
}

impl LocalNetwork {
    /// Create new [LocalNetwork]s for `num_parties`.
    pub fn new(num_parties: usize) -> Vec<Self> {
        Self::new_with_timeout(num_parties, None)
    }

    /// Create new [LocalNetwork]s for `num_parties`, setting a timeout.
    pub fn new_with_timeout(num_parties: usize, timeout: Option<Duration>) -> Vec<Self> {
        let mut networks = Vec::with_capacity(num_parties);
        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for _ in 0..num_parties {
            senders.push(IntMap::new());
            receivers.push(IntMap::new());
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..num_parties {
            for j in 0..num_parties {
                if i != j {
                    let (tx, rx) = crossbeam_channel::bounded(32);
                    senders[i].insert(j, (tx, TrafficCounters::default()));
                    receivers[j].insert(
                        i,
                        (rx, TrafficCounters::default(), RoundCounters::default()),
                    );
                }
            }
        }

        for (id, (send, recv)) in senders.into_iter().zip(receivers).enumerate() {
            networks.push(LocalNetwork {
                id,
                timeout,
                send,
                recv,
            });
        }

        networks
    }

    /// Create new [LocalNetwork]s for 3 parties.
    pub fn new_3_parties() -> [Self; 3] {
        Self::new(3).try_into().expect("correct len")
    }
}

impl Network for LocalNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        let (sender, sent) = self.send.get(to).context("party id out-of-bounds")?;
        sent.record(data.len());
        if let Some(timeout) = self.timeout {
            sender
                .send_timeout(data, timeout)
                .map_err(|_| eyre::eyre!("send to party {to} timed out"))?;
        } else {
            sender.send(data)?;
        }
        Ok(())
    }

    /// Receive the next value from `from`. Peeks with a non-blocking
    /// `try_recv` first to detect a logical round boundary (a wait for the
    /// peer's next send) before falling through to the real receive — see
    /// [`RoundStats`]; observation-only, same as the TCP/TLS
    /// backend's `recv` in `blocking.rs`.
    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let (receiver, recv, rounds) = self.recv.get(from).context("party id out-of-bounds")?;
        let data = match receiver.try_recv() {
            Ok(data) => data,
            Err(_) => {
                rounds.open_boundary();
                let wait_start = Instant::now();
                let data = if let Some(timeout) = self.timeout {
                    receiver
                        .recv_timeout(timeout)
                        .map_err(|_| eyre::eyre!("recv from party {from} timed out"))?
                } else {
                    receiver.recv()?
                };
                rounds.record_wait(wait_start.elapsed());
                data
            }
        };
        recv.record(data.len());
        rounds.note_recv(data.len());
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        let mut msgs = std::collections::BTreeMap::new();
        let mut rounds = std::collections::BTreeMap::new();
        for (id, (_, sent)) in self.send.iter() {
            let (_, recv, round_counters) =
                self.recv.get(id).expect("was in send so must be in recv");
            let (sent_bytes, sent_msgs) = sent.load();
            let (recv_bytes, recv_msgs) = recv.load();
            let (n_rounds, blocked_recv_nanos, recv_bytes_histogram) =
                round_counters.finalize_and_load();
            stats.insert(id, (sent_bytes, recv_bytes));
            msgs.insert(id, (sent_msgs, recv_msgs));
            rounds.insert(
                id,
                RoundStats {
                    rounds: n_rounds,
                    blocked_recv_nanos,
                    recv_bytes_histogram,
                },
            );
        }
        ConnectionStats::new_with_msgs_and_rounds(self.id, stats, msgs, rounds)
    }
}

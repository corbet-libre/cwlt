//! Wave wallet job journal.
//!
//! A member's wave action (reserve, Answer, Close, Silence, Punish) is
//! recorded as a job at once and shows as done in the journal and UI. Building the
//! witness, proving and submitting follow in a background worker. A failed or
//! uncertain proof never removes the job: it returns to `Recorded` for another
//! attempt or becomes `Stalled`, which stays visible. Nothing here proves, signs or
//! grants authority; it only orders the work and keeps it from being lost.
use serde::{Deserialize, Serialize};

/// Attempts before a job stops retrying on its own and waits for attention.
pub const MAX_ATTEMPTS: u8 = 5;
/// Bound on retained jobs (finished jobs are pruned first).
pub const MAX_JOBS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Why a job change was refused.
pub enum Error {
    /// A job with this identifier exists.
    Duplicate,
    /// Too many unfinished jobs.
    Limit,
    /// No such job.
    Unknown,
    /// The transition is not allowed from the job's stage.
    Stage,
    /// Malformed encoding.
    Encoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// What the member did.
pub enum Operation {
    /// Reserve a slot as sender (role 0) or recipient (role 1).
    Reserve {
        /// 0 for the sender, 1 for the recipient.
        role: u8,
    },
    /// Answer a wave.
    Answer,
    /// Decline a wave.
    Close,
    /// Let a wave expire unanswered (the sender's refund).
    Silence,
    /// Punish the peer.
    Punish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Where a job stands.
pub enum Stage {
    /// Applied to the member's journal; no work started.
    Recorded,
    /// A worker is building the witness and proving.
    Proving,
    /// Handed to the issuer; the result is not yet known.
    Submitted,
    /// The issuer accepted it (or the job needs no issuer step).
    Done,
    /// Retries are used up; visible, never dropped.
    Stalled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One recorded wallet action.
pub struct Job {
    /// Stable identifier chosen by the caller, for example a hash of the wave nonce and operation.
    pub id: [u8; 32],
    /// The action.
    pub operation: Operation,
    /// Progress.
    pub stage: Stage,
    /// Proving attempts started so far.
    pub attempts: u8,
    /// Time of the last change.
    pub updated_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The retained jobs of one member and community.
pub struct Jobs {
    entries: Vec<Job>,
}

impl Jobs {
    /// Restore the journal from its stored bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let jobs: Self = serde_json::from_slice(bytes).map_err(|_| Error::Encoding)?;
        if jobs.entries.len() > MAX_JOBS {
            return Err(Error::Limit);
        }
        Ok(jobs)
    }
    /// The bytes to store in the member's encrypted Store.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("Jobs derives Serialize over JSON-native types only; to_vec cannot fail")
    }
    /// One job by identifier.
    pub fn get(&self, id: &[u8; 32]) -> Option<&Job> {
        self.entries.iter().find(|job| &job.id == id)
    }
    /// Jobs a worker should pick up, oldest first.
    pub fn pending(&self) -> impl Iterator<Item = &Job> {
        self.entries
            .iter()
            .filter(|job| job.stage == Stage::Recorded)
    }
    /// Jobs that need attention.
    pub fn stalled(&self) -> impl Iterator<Item = &Job> {
        self.entries
            .iter()
            .filter(|job| job.stage == Stage::Stalled)
    }

    /// Record the member's action. Always succeeds unless the identifier repeats
    /// or too many jobs are unfinished.
    pub fn record(&mut self, id: [u8; 32], operation: Operation, now: u64) -> Result<(), Error> {
        if self.get(&id).is_some() {
            return Err(Error::Duplicate);
        }
        if self.entries.len() >= MAX_JOBS {
            self.entries.retain(|job| job.stage != Stage::Done);
            if self.entries.len() >= MAX_JOBS {
                return Err(Error::Limit);
            }
        }
        self.entries.push(Job {
            id,
            operation,
            stage: Stage::Recorded,
            attempts: 0,
            updated_at: now,
        });
        Ok(())
    }

    fn step(&mut self, id: &[u8; 32], from: Stage, to: Stage, now: u64) -> Result<&mut Job, Error> {
        let job = self
            .entries
            .iter_mut()
            .find(|job| &job.id == id)
            .ok_or(Error::Unknown)?;
        if job.stage != from {
            return Err(Error::Stage);
        }
        job.stage = to;
        job.updated_at = now;
        Ok(job)
    }

    /// A worker begins proving.
    pub fn start(&mut self, id: &[u8; 32], now: u64) -> Result<(), Error> {
        self.step(id, Stage::Recorded, Stage::Proving, now)
            .map(|job| job.attempts += 1)
    }
    /// The proof was built and handed to the issuer.
    pub fn submitted(&mut self, id: &[u8; 32], now: u64) -> Result<(), Error> {
        self.step(id, Stage::Proving, Stage::Submitted, now)
            .map(|_| ())
    }
    /// Building or proving failed before anything reached the issuer.
    pub fn failed(&mut self, id: &[u8; 32], now: u64) -> Result<(), Error> {
        let job = self.step(id, Stage::Proving, Stage::Recorded, now)?;
        if job.attempts >= MAX_ATTEMPTS {
            job.stage = Stage::Stalled;
        }
        Ok(())
    }
    /// The issuer's answer is known: accepted, or not (then the job is retried).
    /// An uncertain submission is reconciled from the issuer's committed frontier,
    /// never by repeating a possibly accepted proof.
    pub fn reconciled(&mut self, id: &[u8; 32], accepted: bool, now: u64) -> Result<(), Error> {
        if accepted {
            self.step(id, Stage::Submitted, Stage::Done, now)
                .map(|_| ())
        } else {
            let job = self.step(id, Stage::Submitted, Stage::Recorded, now)?;
            if job.attempts >= MAX_ATTEMPTS {
                job.stage = Stage::Stalled;
            }
            Ok(())
        }
    }
    /// Give a stalled job a fresh set of attempts.
    pub fn retry(&mut self, id: &[u8; 32], now: u64) -> Result<(), Error> {
        self.step(id, Stage::Stalled, Stage::Recorded, now)
            .map(|job| job.attempts = 0)
    }
    /// A restart found the worker gone: proving jobs go back to the queue.
    pub fn recover(&mut self, now: u64) {
        for job in &mut self.entries {
            if job.stage == Stage::Proving {
                job.stage = Stage::Recorded;
                job.updated_at = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1; 32];

    #[test]
    fn an_action_is_recorded_before_any_work_and_finishes() {
        let mut jobs = Jobs::default();
        jobs.record(A, Operation::Answer, 10).unwrap();
        assert_eq!(jobs.pending().count(), 1);
        jobs.start(&A, 11).unwrap();
        assert_eq!(jobs.pending().count(), 0);
        jobs.submitted(&A, 12).unwrap();
        jobs.reconciled(&A, true, 13).unwrap();
        let job = jobs.get(&A).unwrap();
        assert_eq!(
            (job.stage, job.attempts, job.updated_at),
            (Stage::Done, 1, 13)
        );
        assert_eq!(Jobs::decode(&jobs.encode()).unwrap(), jobs);
    }

    #[test]
    fn failures_and_refusals_never_lose_the_action() {
        let mut jobs = Jobs::default();
        jobs.record(A, Operation::Reserve { role: 0 }, 1).unwrap();
        assert_eq!(jobs.record(A, Operation::Close, 2), Err(Error::Duplicate));
        assert_eq!(jobs.submitted(&A, 2), Err(Error::Stage));
        assert_eq!(jobs.start(&[9; 32], 2), Err(Error::Unknown));
        for attempt in 1..=MAX_ATTEMPTS {
            jobs.start(&A, 2).unwrap();
            if attempt % 2 == 0 {
                jobs.submitted(&A, 3).unwrap();
                jobs.reconciled(&A, false, 4).unwrap();
            } else {
                jobs.failed(&A, 3).unwrap();
            }
        }
        assert_eq!(jobs.get(&A).unwrap().stage, Stage::Stalled);
        assert_eq!(jobs.stalled().count(), 1);
        assert_eq!(jobs.pending().count(), 0);
        jobs.retry(&A, 5).unwrap();
        assert_eq!(jobs.get(&A).unwrap().attempts, 0);
        assert_eq!(jobs.pending().count(), 1);
        // A restart returns work in flight to the queue.
        jobs.start(&A, 6).unwrap();
        jobs.recover(7);
        assert_eq!(jobs.get(&A).unwrap().stage, Stage::Recorded);
        // A job that exhausts its attempts through an unaccepted submission stalls too.
        jobs.record([2; 32], Operation::Punish, 8).unwrap();
        for _ in 0..MAX_ATTEMPTS {
            jobs.start(&[2; 32], 9).unwrap();
            jobs.submitted(&[2; 32], 9).unwrap();
            jobs.reconciled(&[2; 32], false, 9).unwrap();
        }
        assert_eq!(jobs.get(&[2; 32]).unwrap().stage, Stage::Stalled);
    }

    #[test]
    fn bounds_and_encoding() {
        let mut jobs = Jobs::default();
        for n in 0..MAX_JOBS {
            let id = [(n % 256) as u8; 32];
            jobs.record(id, Operation::Punish, 1).unwrap();
        }
        assert_eq!(
            jobs.record([0; 32], Operation::Silence, 1),
            Err(Error::Duplicate)
        );
        let mut other = [255u8; 32];
        other[0] = 7;
        assert_eq!(jobs.record(other, Operation::Silence, 1), Err(Error::Limit));
        // Finished jobs make room.
        let id = [3; 32];
        jobs.start(&id, 2).unwrap();
        jobs.submitted(&id, 2).unwrap();
        jobs.reconciled(&id, true, 2).unwrap();
        jobs.record(other, Operation::Silence, 3).unwrap();
        assert!(jobs.get(&id).is_none());
        assert_eq!(Jobs::decode(b"{"), Err(Error::Encoding));
        let big = serde_json::to_vec(&Jobs {
            entries: vec![
                Job {
                    id: A,
                    operation: Operation::Close,
                    stage: Stage::Done,
                    attempts: 0,
                    updated_at: 0
                };
                MAX_JOBS + 1
            ],
        })
        .unwrap();
        assert_eq!(Jobs::decode(&big), Err(Error::Limit));
    }
}

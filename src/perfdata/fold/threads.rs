use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

#[derive(Clone, Copy)]
struct ReplayThread {
    pid: u32,
    maps: u32,
}

/// Map-table bucket keys are internal identities, not necessarily process IDs.
/// A surviving thread and a recreated leader can have different map groups
/// with the same PID (perf `thread.c:thread__init_maps()`).
#[derive(Default)]
pub(super) struct ThreadMaps {
    threads: HashMap<u32, ReplayThread, FxBuildHasher>,
    references: HashMap<u32, usize, FxBuildHasher>,
    next_key: u32,
    retired: Vec<u32>,
}

impl ThreadMaps {
    pub(super) fn pid(&self, tid: u32) -> Option<u32> {
        self.threads.get(&tid).map(|thread| thread.pid)
    }

    pub(super) fn find_or_create(&mut self, pid: u32, tid: u32) -> u32 {
        if let Some(thread) = self.threads.get(&tid).copied() {
            if thread.pid != u32::MAX || pid == u32::MAX {
                return thread.maps;
            }
            // machine.c:machine__update_thread_pid joins the leader's maps
            // when a previously unknown PID becomes known.
            self.remove(tid);
        }
        let maps = if pid == tid || pid == u32::MAX {
            self.new_group(pid)
        } else {
            self.find_or_create(pid, pid)
        };
        self.retain(maps);
        self.threads.insert(tid, ReplayThread { pid, maps });
        maps
    }

    fn new_group(&mut self, pid: u32) -> u32 {
        // Preserve ordinary PID bucket keys where free, but never collide
        // with another live group or the global kernel bucket (u32::MAX).
        let key = if pid != u32::MAX
            && !self.references.contains_key(&pid)
            && !self.retired.contains(&pid)
        {
            pid
        } else {
            while self.references.contains_key(&self.next_key)
                || self.retired.contains(&self.next_key)
                || self.next_key == u32::MAX
            {
                self.next_key = self.next_key.wrapping_add(1);
            }
            let key = self.next_key;
            self.next_key = self.next_key.wrapping_add(1);
            key
        };
        self.references.insert(key, 0);
        key
    }

    pub(super) fn retain(&mut self, maps: u32) {
        *self.references.get_mut(&maps).expect("live map group") += 1;
    }

    pub(super) fn release(&mut self, maps: u32) {
        let references = self.references.get_mut(&maps).expect("live map group");
        *references -= 1;
        if *references == 0 {
            self.references.remove(&maps);
            self.retired.push(maps);
        }
    }

    pub(super) fn remove(&mut self, tid: u32) {
        if let Some(thread) = self.threads.remove(&tid) {
            self.release(thread.maps);
        }
    }

    pub(super) fn take_retired(&mut self) -> impl Iterator<Item = u32> + '_ {
        self.retired.drain(..)
    }
}

#[cfg(test)]
mod tests {
    use super::ThreadMaps;

    #[test]
    fn leader_exit_preserves_survivor_and_creates_an_independent_group() {
        let mut threads = ThreadMaps::default();
        let old = threads.find_or_create(11, 12);
        threads.remove(11);
        let new = threads.find_or_create(11, 13);
        assert_ne!(old, new);
        assert_eq!(threads.find_or_create(11, 12), old);
        assert_eq!(threads.find_or_create(11, 11), new);
        assert_eq!(threads.take_retired().count(), 0);
        threads.remove(12);
        assert_eq!(threads.take_retired().collect::<Vec<_>>(), [old]);
    }

    #[test]
    fn a_real_pid_cannot_alias_an_internal_group_key() {
        let mut threads = ThreadMaps::default();
        let old = threads.find_or_create(11, 12);
        threads.remove(11);
        let split = threads.find_or_create(11, 13);
        let other = threads.find_or_create(split, split);
        assert_ne!(old, split);
        assert_ne!(split, other);
        assert_eq!(threads.find_or_create(11, 13), split);
    }

    #[test]
    fn unknown_pid_thread_joins_its_known_leaders_maps() {
        let mut threads = ThreadMaps::default();
        let unknown = threads.find_or_create(u32::MAX, 12);
        let leader = threads.find_or_create(11, 11);
        assert_ne!(unknown, leader);
        assert_eq!(threads.find_or_create(11, 12), leader);
        assert_eq!(threads.pid(12), Some(11));
        assert_eq!(threads.take_retired().collect::<Vec<_>>(), [unknown]);
    }

    #[test]
    fn a_held_group_survives_thread_replacement_until_copy_finishes() {
        let mut threads = ThreadMaps::default();
        let old = threads.find_or_create(11, 11);
        threads.retain(old);
        threads.remove(11);
        assert_eq!(threads.take_retired().count(), 0);
        let new = threads.find_or_create(11, 11);
        assert_ne!(old, new);
        threads.release(old);
        assert_eq!(threads.take_retired().collect::<Vec<_>>(), [old]);
    }
}

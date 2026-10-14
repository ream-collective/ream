//! Locking for the state caches. A panic while a cache was locked can leave it half-updated, so a
//! poisoned cache is emptied and rebuilt instead of being trusted or failing every later caller.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(crate) fn lock<T: Default>(cache: &Mutex<T>) -> MutexGuard<'_, T> {
    cache.lock().unwrap_or_else(|poisoned| {
        cache.clear_poison();
        let mut guard = poisoned.into_inner();
        *guard = T::default();
        guard
    })
}

pub(crate) fn read<T: Default>(cache: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    loop {
        match cache.read() {
            Ok(guard) => return guard,
            // Release the read guard before emptying the cache under the write lock.
            Err(err) => {
                drop(err);
                drop(write(cache));
            }
        }
    }
}

pub(crate) fn write<T: Default>(cache: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    cache.write().unwrap_or_else(|poisoned| {
        cache.clear_poison();
        let mut guard = poisoned.into_inner();
        *guard = T::default();
        guard
    })
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Mutex, RwLock},
    };

    use super::{lock, read, write};

    #[test]
    fn a_poisoned_cache_is_emptied() {
        let cache = Mutex::new(vec![1, 2, 3]);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut entries = cache.lock().expect("not poisoned yet");
            entries.push(4);
            panic!("half-updated");
        }));
        assert!(cache.is_poisoned());
        assert!(lock(&cache).is_empty());
        assert!(!cache.is_poisoned());

        let cache = RwLock::new(vec![1, 2, 3]);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _entries = cache.write().expect("not poisoned yet");
            panic!("half-updated");
        }));
        assert!(read(&cache).is_empty());
        write(&cache).push(5);
        assert_eq!(*read(&cache), vec![5]);
    }
}

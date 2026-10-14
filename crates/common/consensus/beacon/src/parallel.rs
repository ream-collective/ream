//! Splitting work across the available cores. zkVM guests have no threads, so they run it on the
//! calling thread.

/// Threads to split work across: one per core, or one in a zkVM guest.
pub(crate) fn thread_count() -> usize {
    if cfg!(target_os = "zkvm") {
        return 1;
    }
    std::thread::available_parallelism().map_or(1, |threads| threads.get())
}

/// `items.iter().map(map).collect()`, split across cores when there are at least `threshold`
/// items. The results keep the order of `items`.
pub(crate) fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    threshold: usize,
    map: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let threads = thread_count();
    if threads == 1 || items.len() < threshold {
        return items.iter().map(map).collect();
    }
    let chunk_size = items.len().div_ceil(threads);
    let map = &map;
    std::thread::scope(|scope| {
        let workers: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(map).collect::<Vec<R>>()))
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("map worker does not panic"))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::parallel_map;

    #[test]
    fn keeps_the_order_of_the_items() {
        let items: Vec<u64> = (0..10_000).collect();
        let doubled = parallel_map(&items, 2, |item| item * 2);
        assert_eq!(
            doubled,
            items.iter().map(|item| item * 2).collect::<Vec<_>>()
        );
        assert_eq!(parallel_map(&items[..1], 2, |item| item + 1), vec![1]);
    }
}

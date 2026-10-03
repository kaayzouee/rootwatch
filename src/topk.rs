// SPDX-License-Identifier: GPL-3.0-only
//
// Bounded top-K selection. Pushing N candidates costs O(N log K) in the worst
// case and O(N) in practice, because candidates that cannot beat the current
// K-th best are rejected by a single integer comparison before anything is
// allocated or sifted.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

struct Entry<T> {
    key: (u64, u64),
    item: T,
}

impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl<T> Eq for Entry<T> {}
impl<T> PartialOrd for Entry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Entry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

pub struct TopK<T> {
    k: usize,
    heap: BinaryHeap<Reverse<Entry<T>>>,
}

impl<T> TopK<T> {
    pub fn new(k: usize) -> Self {
        Self {
            k,
            heap: BinaryHeap::with_capacity(k.saturating_add(1).min(4096)),
        }
    }

    /// Smallest primary key that could still enter the heap. Anything strictly
    /// below this is guaranteed to be rejected.
    #[inline]
    pub fn floor(&self) -> u64 {
        if self.k == 0 {
            return u64::MAX;
        }
        if self.heap.len() < self.k {
            0
        } else {
            self.heap.peek().map_or(0, |e| e.0.key.0)
        }
    }

    /// Cheap pre-check so callers can skip building `item` entirely.
    #[inline]
    pub fn might_accept(&self, key: u64) -> bool {
        self.k != 0 && (self.heap.len() < self.k || key >= self.floor())
    }

    /// `key` is (primary, tiebreak); larger is better.
    pub fn push(&mut self, key: (u64, u64), item: T) {
        if self.k == 0 {
            return;
        }
        if self.heap.len() < self.k {
            self.heap.push(Reverse(Entry { key, item }));
        } else if let Some(min) = self.heap.peek() {
            if key > min.0.key {
                self.heap.pop();
                self.heap.push(Reverse(Entry { key, item }));
            }
        }
    }

    /// Best first.
    pub fn into_sorted_desc(self) -> Vec<T> {
        let mut v: Vec<_> = self.heap.into_vec();
        v.sort_unstable_by(|a, b| b.0.key.cmp(&a.0.key));
        v.into_iter().map(|e| e.0.item).collect()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_k_largest_in_order() {
        let mut t = TopK::new(3);
        for (i, v) in [5u64, 1, 9, 3, 7, 7, 2].into_iter().enumerate() {
            t.push((v, i as u64), v);
        }
        assert_eq!(t.into_sorted_desc(), vec![9, 7, 7]);
    }

    #[test]
    fn zero_capacity_accepts_nothing() {
        let mut t: TopK<u8> = TopK::new(0);
        assert!(!t.might_accept(u64::MAX));
        t.push((1, 1), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn floor_rejects_cheaply_once_full() {
        let mut t = TopK::new(2);
        t.push((10, 0), ());
        assert!(t.might_accept(0));
        t.push((20, 1), ());
        assert!(!t.might_accept(9));
        assert!(t.might_accept(10));
    }
}

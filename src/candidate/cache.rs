use std::collections::{HashMap, VecDeque};

#[derive(Debug)]
pub struct BoundedCache<K, V> {
    capacity: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> BoundedCache<K, V>
where
    K: Clone + Eq + std::hash::Hash,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    pub fn get(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.map.get(key).cloned()?;
        self.touch(key.clone());
        Some(value)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.map.insert(key.clone(), value);
            self.touch(key);
            return;
        }

        if self.map.len() >= self.capacity {
            while let Some(oldest) = self.order.pop_front() {
                if self.map.remove(&oldest).is_some() {
                    break;
                }
            }
        }

        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    fn touch(&mut self, key: K) {
        if let Some(pos) = self.order.iter().position(|existing| existing == &key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedCache;

    #[test]
    fn evicts_oldest_entry() {
        let mut cache = BoundedCache::new(2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        assert!(cache.get(&1).is_none());
        assert_eq!(cache.get(&2), Some("b"));
        assert_eq!(cache.get(&3), Some("c"));
    }

    #[test]
    fn get_touches_entry() {
        let mut cache = BoundedCache::new(2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        assert_eq!(cache.get(&1), Some("a"));
        cache.insert(3, "c");
        assert_eq!(cache.get(&1), Some("a"));
        assert!(cache.get(&2).is_none());
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut cache = BoundedCache::new(2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.clear();
        assert!(cache.get(&1).is_none());
        assert!(cache.get(&2).is_none());
    }
}

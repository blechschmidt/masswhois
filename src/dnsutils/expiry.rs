use std::time::{SystemTime, Duration};
use std::collections::{LinkedList};

pub struct ExpiryHandler<T> {
    buckets: Vec<LinkedList<T>>,
    start_time: SystemTime,
    bucket_seconds: usize,
    maximum_duration: Duration,
    minimum_duration: Duration,
    last_cleaned: SystemTime,
    clean_next: SystemTime,
    clean_next_bucket: usize,
    bucket_count: usize
}

impl<T> ExpiryHandler<T> {
    pub fn new(bucket_count: usize, bucket_seconds: usize) -> Self {
        let now = SystemTime::now();
        let minimum_duration = Duration::from_secs(bucket_seconds as u64);
        let mut result = ExpiryHandler {
            buckets: Vec::with_capacity(bucket_count),
            start_time: now,
            bucket_seconds: bucket_seconds,
            maximum_duration: Duration::from_secs((bucket_count * bucket_seconds - 1) as u64),
            minimum_duration: minimum_duration,
            last_cleaned: now,
            clean_next: now + minimum_duration,
            clean_next_bucket: 0,
            bucket_count: bucket_count
        };
        for _ in 0..bucket_count {
            result.buckets.push(LinkedList::new());
        }
        result
    }

    pub fn add(&mut self, element: T, lifetime: Duration) {
        let mut duration = lifetime;
        if duration > self.maximum_duration {
            duration = self.maximum_duration;
        }
        if duration < self.minimum_duration {
            duration = self.minimum_duration;
        }
        let elapsed_secs = (SystemTime::now().duration_since(self.start_time).unwrap()
            + duration).as_secs() as usize;
        let bucket = (elapsed_secs / self.bucket_seconds) % self.bucket_count;
        self.buckets[bucket].push_back(element);
    }

    pub fn clean(&mut self, fun: &mut FnMut(&T)) {
        let now = SystemTime::now();
        if now < self.clean_next {
            return;
        }
        let mut buckets_to_clean = (now.duration_since(self.last_cleaned).unwrap().as_secs() as usize) / self.bucket_seconds;
        if buckets_to_clean > self.bucket_count {
            buckets_to_clean = self.bucket_count;
        }
        for i in 0..buckets_to_clean {
            let ref mut bucket = self.buckets[(self.clean_next_bucket + i) % self.bucket_count];
            for j in bucket.iter() {
                fun(&j);
            }
            bucket.clear();
        }
        self.clean_next_bucket = (self.clean_next_bucket + buckets_to_clean) % self.bucket_count;
        self.last_cleaned = self.start_time + Duration::from_secs((((now.duration_since(self.start_time).unwrap().as_secs() as usize)
            / self.bucket_seconds) * self.bucket_seconds) as u64);
        self.clean_next = self.last_cleaned + self.minimum_duration;
    }
}
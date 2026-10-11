use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

fn main() {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = Arc::clone(&flag);

    let handle = thread::spawn(move || {
        flag_clone.store(true, Ordering::SeqCst);
    });

    handle.join().expect("thread join failed");
    assert!(flag.load(Ordering::SeqCst));
    println!("Thread completed successfully!");
}

use std::fs::{self, File};
use std::io::{Read, Write};

fn main() {
    let filename = "census_rust_test.txt";
    {
        let mut file = File::create(filename).expect("failed to create file");
        file.write_all(b"carrick-nt-rust-io").expect("failed to write file");
    }
    {
        let mut file = File::open(filename).expect("failed to open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("failed to read file");
        assert_eq!(contents, "carrick-nt-rust-io");
    }
    let _ = fs::remove_file(filename);
}

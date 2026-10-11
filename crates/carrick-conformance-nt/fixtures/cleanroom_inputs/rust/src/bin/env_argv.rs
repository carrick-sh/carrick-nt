use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if !args.is_empty() {
        println!("Arg 0: {}", args[0]);
    }
    let path_var = env::var("PATH").unwrap_or_default();
    println!("PATH length: {}", path_var.len());
    env::set_var("CARRICK_TEST", "1");
    assert_eq!(env::var("CARRICK_TEST").unwrap(), "1");
}

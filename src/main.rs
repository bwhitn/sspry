/// Delegates process startup to the CLI application entrypoint and exits with
/// the returned status code.
fn main() {
    std::process::exit(sspry::app::main(None));
}

extern crate cbindgen;

use cbindgen::{Config, ParseExpandConfig};
use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let config = Config {
        language: cbindgen::Language::C,
        cpp_compat: true,
        include_guard: Some("DUMB_API_H".to_string()),
        autogen_warning: Some("/* auto generated, do not edit */".to_string()),
        style: cbindgen::Style::Both,
        parse: cbindgen::ParseConfig {
            parse_deps: true,
            clean: true,
            expand: ParseExpandConfig::default(),
            include: vec![].into(),
            exclude: vec![],
            extra_bindings: vec![],
        },
        ..Default::default()
    };

    match cbindgen::Builder::new().with_crate(crate_dir).with_config(config).generate() {
        Ok(bindings) => {
            bindings.write_to_file("anse2.h");
            println!("bindings generated successfully");
        }
        Err(e) => {
            eprintln!("cbindgen failed: {}", e);
        }
    }
}

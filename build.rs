extern crate clap;
#[macro_use]
extern crate failure;
extern crate path_abs;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate toml;

use clap::Shell;
use structopt::StructOpt;

mod src;

fn main() {
    let mut app = src::config::Config::clap();
    app.gen_completions("oktaws", Shell::Bash, "complete");
    app.gen_completions("oktaws", Shell::Fish, "complete");
    app.gen_completions("oktaws", Shell::Zsh, "complete");
}

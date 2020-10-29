use cmdr::*; // cli repl

use qp2p::{self, Config, Error, Message, QuicP2p, Result};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

fn qp2p() -> QuicP2p {
    QuicP2p::with_config(
        Some(Config {
            port: Some(0),
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..Default::default()
        }),
        // Make sure we start with an empty cache. Otherwise, we might get into unexpected state.
        Default::default(),
        true,
    )
    .expect("Error creating QuicP2p object")
}

enum Op {
    Add(u8),
    Remove(u8),
}

struct Proc {
    qp2p: QuicP2p,
    peers: HashSet<qp2p::Endpoint>,
    state: HashSet<u8>,
}

#[cmdr]
impl Proc {
    fn new() -> Self {
        Self {
            qp2p: qp2p(),
            peers: Default::default(),
            state: Default::default(),
        }
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Add(v) => self.state.insert(v),
            Op::Remove(v) => self.state.remove(&v),
        };
    }

    #[cmd]
    fn add(&mut self, args: &[String]) -> CommandResult {
        if args.len() > 0 {
            match args[0].parse::<u8>() {
                Ok(v) => self.apply(Op::Add(v)),
                Err(_) => {
                    println!("Failed to parse: {:?}", args);
                }
            }
        }
        CommandResult::Ok
    }

    #[cmd]
    fn remove(&mut self, args: &[String]) -> CommandResult {
        if args.len() > 0 {
            match args[0].parse::<u8>() {
                Ok(v) => self.apply(Op::Remove(v)),
                Err(e) => {
                    println!("Failed to parse: {:?}", args);
                }
            }
        }

        CommandResult::Ok
    }

    #[cmd]
    fn show(&mut self, args: &[String]) -> CommandResult {
        println!("{:?}", self.state);
        CommandResult::Ok
    }
}

#[tokio::main]
async fn main() {
    cmd_loop(&mut Proc::new());
}

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};

use cmdr::*; // cli repl

use qp2p::{self, Config, Endpoint, Message, QuicP2p};
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

#[derive(Default, Debug)]
struct State {
    v: HashSet<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Op {
    Add(u8),
    Remove(u8),
}

impl State {
    fn apply(&mut self, op: Op) {
        match op {
            Op::Add(v) => self.v.insert(v),
            Op::Remove(v) => self.v.remove(&v),
        };
    }

    fn read(&self) -> HashSet<u8> {
        self.v.clone()
    }
}

#[derive(Debug, Clone)]
struct SharedState {
    shared: Arc<Mutex<State>>,
}
impl SharedState {
    fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Default::default())),
        }
    }

    fn apply(&self, op: Op) {
        self.shared.lock().unwrap().apply(op);
    }

    fn read(&self) -> HashSet<u8> {
        self.shared.lock().unwrap().read()
    }
}

#[derive(Debug)]
struct Proc {
    qp2p: QuicP2p,
    listeners: Vec<tokio::task::JoinHandle<()>>,
    peers: HashSet<qp2p::Endpoint>,
}

#[derive(Debug)]
struct Repl {
    state: SharedState,
    network_tx: mpsc::Sender<NetworkEvent>,
}

#[cmdr]
impl Repl {
    fn new(state: SharedState, network_tx: mpsc::Sender<NetworkEvent>) -> Self {
        Self { state, network_tx }
    }

    #[cmd]
    fn peer(&mut self, args: &[String]) -> CommandResult {
        match args {
            [ip_port] => match ip_port.parse::<SocketAddr>() {
                Ok(addr) => {
                    println!("Parsed an addr {:?}", addr);
                    self.network_tx.try_send(NetworkEvent::AddPeer(addr));
                }
                Err(e) => println!("Bad peer spec {:?}", e),
            },
            _ => println!("Bad peer spec {:?}", args),
        };
        Ok(Action::Done)
    }

    #[cmd]
    fn add(&mut self, args: &[String]) -> CommandResult {
        if args.len() > 0 {
            match args[0].parse::<u8>() {
                Ok(v) => self.state.apply(Op::Add(v)),
                Err(_) => {
                    println!("Failed to parse: {:?}", args);
                }
            }
        }

        Ok(Action::Done)
    }

    #[cmd]
    fn remove(&mut self, args: &[String]) -> CommandResult {
        if args.len() > 0 {
            match args[0].parse::<u8>() {
                Ok(v) => self.state.apply(Op::Remove(v)),
                Err(e) => {
                    println!("Failed to parse: {:?}", args);
                }
            }
        }

        Ok(Action::Done)
    }

    #[cmd]
    fn read(&mut self, args: &[String]) -> CommandResult {
        println!("{:?}", self.state.read());

        Ok(Action::Done)
    }

    #[cmd]
    fn dbg(&mut self, args: &[String]) -> CommandResult {
        println!("{:#?}", self);

        Ok(Action::Done)
    }
}

#[derive(Debug)]
struct Network {
    qp2p: QuicP2p,
    peers: Vec<(Endpoint, SocketAddr)>,
}

#[derive(Debug)]
enum NetworkEvent {
    AddPeer(SocketAddr),
    Broadcast(Op),
}

impl Network {
    fn new() -> Self {
        Self {
            qp2p: qp2p(),

            peers: Default::default(),
        }
    }

    async fn apply(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::AddPeer(addr) => {
                let peer = self.qp2p.new_endpoint().unwrap();
                self.peers.push((peer, addr));
            }
            NetworkEvent::Broadcast(op) => {
                let msg = bincode::serialize(&op).unwrap();
                for (peer, addr) in self.peers.iter() {
                    let conn = peer.connect_to(&addr).await.unwrap();
                    let _ = conn.send(msg.clone().into()).await.unwrap();
                }
            }
        }
    }
}

#[tokio::main]
async fn listen_for_network_events(mut net_rx: mpsc::Receiver<NetworkEvent>) {
    let mut network = Network::new();
    while let Some(net_event) = net_rx.recv().await {
        println!("Applying {:?} to net", net_event);
        network.apply(net_event);
    }
}

fn main() {
    let state = SharedState::new();
    let (net_tx, mut net_rx) = mpsc::channel(100);
    std::thread::spawn(|| listen_for_network_events(net_rx));
    cmd_loop(&mut Repl::new(state.clone(), net_tx));
}

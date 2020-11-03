use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use cmdr::*; // cli repl

use qp2p::{self, Config, Endpoint, QuicP2p};
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
struct Repl {
    state: SharedState,
    network_tx: mpsc::Sender<NetworkCmd>,
}

#[cmdr]
impl Repl {
    fn new(state: SharedState, network_tx: mpsc::Sender<NetworkCmd>) -> Self {
        Self { state, network_tx }
    }

    #[cmd]
    fn peer(&mut self, args: &[String]) -> CommandResult {
        match args {
            [ip_port] => match ip_port.parse::<SocketAddr>() {
                Ok(addr) => {
                    println!("Parsed an addr {:?}", addr);
                    self.network_tx.try_send(NetworkCmd::AddPeer(addr)).unwrap();
                }
                Err(e) => println!("Bad peer spec {:?}", e),
            },
            _ => println!("Bad peer spec {:?}", args),
        };
        Ok(Action::Done)
    }

    #[cmd]
    fn add(&mut self, args: &[String]) -> CommandResult {
        match args {
            [arg] => match arg.parse::<u8>() {
                Ok(v) => {
                    self.network_tx
                        .try_send(NetworkCmd::Broadcast(Op::Add(v)))
                        .expect("Failed to broadcast Add");
                }
                Err(_) => println!("Failed to parse: '{}'", arg),
            },
            _ => println!("help: add <v>"),
        }
        Ok(Action::Done)
    }

    #[cmd]
    fn remove(&mut self, args: &[String]) -> CommandResult {
        match args {
            [arg] => match arg.parse::<u8>() {
                Ok(v) => {
                    self.network_tx
                        .try_send(NetworkCmd::Broadcast(Op::Remove(v)))
                        .expect("Failed to broadcast Remove");
                }
                Err(_) => println!("Failed to parse: '{}'", arg),
            },
            _ => println!("help: remove <v>"),
        }
        Ok(Action::Done)
    }

    #[cmd]
    fn read(&mut self, _args: &[String]) -> CommandResult {
        println!("{:?}", self.state.read());
        Ok(Action::Done)
    }

    #[cmd]
    fn dbg(&mut self, _args: &[String]) -> CommandResult {
        println!("{:#?}", self);
        Ok(Action::Done)
    }
}

#[derive(Debug)]
struct Network {
    state: SharedState,
    qp2p: QuicP2p,
    peers: Vec<(Endpoint, SocketAddr)>,
}

#[derive(Debug)]
enum NetworkCmd {
    AddPeer(SocketAddr),
    Broadcast(Op),
    Apply(Op),
}

impl Network {
    fn new(state: SharedState) -> Self {
        Self {
            state,
            qp2p: qp2p(),
            peers: Default::default(),
        }
    }

    fn new_endpoint(&self) -> Endpoint {
        self.qp2p.new_endpoint().expect("Failed to create endpoint")
    }

    async fn listen_for_cmds(mut self, mut net_rx: mpsc::Receiver<NetworkCmd>) {
        while let Some(net_cmd) = net_rx.recv().await {
            self.apply(net_cmd).await;
        }
    }

    async fn apply(&mut self, event: NetworkCmd) {
        println!("Applying {:?}", event);
        match event {
            NetworkCmd::AddPeer(addr) => {
                let peer = self.new_endpoint();
                self.peers.push((peer, addr));
            }
            NetworkCmd::Broadcast(op) => {
                let msg = bincode::serialize(&op).unwrap();
                for (peer, addr) in self.peers.iter() {
                    println!("Broadcasting to addr {:?}", addr);
                    let conn = peer.connect_to(&addr).await.unwrap();
                    println!("Connected to {:?}", addr);
                    let _ = conn.send_uni(msg.clone().into()).await.unwrap();
                    println!("Sent to {:?}", addr);
                    conn.close()
                }
            }
            NetworkCmd::Apply(op) => self.state.apply(op),
        }
    }
}

async fn listen_for_ops(endpoint: Endpoint, mut network_tx: mpsc::Sender<NetworkCmd>) {
    println!("listening on {:?}", endpoint.our_addr());

    network_tx
        .send(NetworkCmd::AddPeer(endpoint.our_addr().unwrap()))
        .await
        .expect("Failed to send command to add self as peer");

    match endpoint.listen() {
        Ok(mut conn) => {
            println!("Got conn");
            while let Some(mut msgs) = conn.next().await {
                println!("Got msgs");
                while let Some(msg) = msgs.next().await {
                    println!("Got msg");
                    let op: Op = bincode::deserialize(&msg.get_message_data()).unwrap();
                    network_tx
                        .send(NetworkCmd::Apply(op))
                        .await
                        .expect("Failed to send Apply network command");
                }
                println!("Finished msgs");
            }
        }
        Err(e) => println!("Failed to start listening: {:?}", e),
    }
}

#[tokio::main]
async fn main() {
    let state = SharedState::new();
    let network = Network::new(state.clone());

    let (net_tx, net_rx) = mpsc::channel(100);

    tokio::spawn(listen_for_ops(network.new_endpoint(), net_tx.clone()));
    tokio::spawn(network.listen_for_cmds(net_rx));
    cmd_loop(&mut Repl::new(state, net_tx)).expect("Failure in REPL");
}

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use cmdr::*; // cli repl

use qp2p::{self, Config, Endpoint, QuicP2p};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

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
    network_tx: mpsc::Sender<RouterCmd>,
}

#[cmdr]
impl Repl {
    fn new(state: SharedState, network_tx: mpsc::Sender<RouterCmd>) -> Self {
        Self { state, network_tx }
    }

    #[cmd]
    fn peer(&mut self, args: &[String]) -> CommandResult {
        match args {
            [ip_port] => match ip_port.parse::<SocketAddr>() {
                Ok(addr) => {
                    println!("Parsed an addr {:?}", addr);
                    self.network_tx.try_send(RouterCmd::AddPeer(addr)).unwrap();
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
                        .try_send(RouterCmd::Broadcast(Op::Add(v)))
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
                        .try_send(RouterCmd::Broadcast(Op::Remove(v)))
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
struct Router {
    state: SharedState,
    qp2p: QuicP2p,
    addr: SocketAddr,
    peers: Vec<(Endpoint, SocketAddr)>,
}

#[derive(Debug)]
enum RouterCmd {
    AddPeer(SocketAddr),
    Broadcast(Op),
    Apply(Op),
}


#[derive(Debug, Serialize, Deserialize)]
enum NetworkMsg {
    HelloMyNameIs(SocketAddr),
    Msg(Op),
}

impl Router {
    fn new(state: SharedState) -> (Self, Endpoint) {
        let qp2p = QuicP2p::with_config(
            Some(Config {
                port: Some(0),
                ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ..Default::default()
            }),
            Default::default(),
            true,
        )
        .expect("Error creating QuicP2p object");

        let endpoint = qp2p.new_endpoint().expect("Failed to create endpoint");
        let addr = endpoint
            .our_addr()
            .expect("Failed to read our addr from endpoint");

        let router = Self {
            state,
            qp2p,
            addr,
            peers: Default::default(),
        };

        (router, endpoint)
    }

    fn new_endpoint(&self) -> Endpoint {
        self.qp2p.new_endpoint().expect("Failed to create endpoint")
    }

    async fn listen_for_cmds(mut self, mut net_rx: mpsc::Receiver<RouterCmd>) {
        while let Some(net_cmd) = net_rx.recv().await {
            self.apply(net_cmd).await;
        }
    }

    async fn apply(&mut self, event: RouterCmd) {
        println!("Applying {:?}", event);
        match event {
            RouterCmd::AddPeer(addr) => {
                if self.peers.iter().find(|(_, a)| a == &addr).is_none() {
                    let peer = self.new_endpoint();
                    let conn = peer.connect_to(&addr).await.unwrap();
                    self.peers.push((peer, addr));
                    let msg = bincode::serialize(&NetworkMsg::HelloMyNameIs(self.addr)).unwrap();
                    let _ = conn.send_uni(msg.into()).await.unwrap();
                    conn.close();
                }
            }
            RouterCmd::Broadcast(op) => {
                let msg = bincode::serialize(&NetworkMsg::Msg(op)).unwrap();
                for (peer, addr) in self.peers.iter() {
                    println!("Broadcasting to addr {:?}", addr);
                    let conn = peer.connect_to(&addr).await.unwrap();
                    println!("Connected to {:?}", addr);
                    let _ = conn.send_uni(msg.clone().into()).await.unwrap();
                    println!("Sent to {:?}", addr);
                    conn.close()
                }
            }
            RouterCmd::Apply(op) => self.state.apply(op),
        }
    }
}

async fn listen_for_ops(endpoint: Endpoint, mut network_tx: mpsc::Sender<RouterCmd>) {
    println!("listening on {:?}", endpoint.our_addr());

    network_tx
        .send(RouterCmd::AddPeer(endpoint.our_addr().unwrap()))
        .await
        .expect("Failed to send command to add self as peer");

    match endpoint.listen() {
        Ok(mut conns) => {
            while let Some(mut msgs) = conns.next().await {
                while let Some(msg) = msgs.next().await {
                    let net_msg: NetworkMsg =
                        bincode::deserialize(&msg.get_message_data()).unwrap();
                    let cmd = match net_msg {
                        NetworkMsg::HelloMyNameIs(addr) => RouterCmd::AddPeer(addr),
                        NetworkMsg::Msg(op) => RouterCmd::Apply(op),
                    };
                    network_tx
                        .send(cmd)
                        .await
                        .expect("Failed to send Apply network command");
                }
            }
        }
        Err(e) => println!("Failed to start listening: {:?}", e),
    }
}

#[tokio::main]
async fn main() {
    let state = SharedState::new();
    let (network, endpoint) = Router::new(state.clone());

    let (net_tx, net_rx) = mpsc::channel(100);

    tokio::spawn(listen_for_ops(endpoint, net_tx.clone()));
    tokio::spawn(network.listen_for_cmds(net_rx));
    cmd_loop(&mut Repl::new(state, net_tx)).expect("Failure in REPL");
}

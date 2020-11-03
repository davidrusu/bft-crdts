use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use cmdr::*; // cli repl

use qp2p::{self, Config, Endpoint, QuicP2p};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub mod actor;
pub mod deterministic_secure_broadcast;
pub mod net;
pub mod orswot;
pub mod traits;

use actor::Actor;
use deterministic_secure_broadcast as dsb;
use traits::SecureBroadcastAlgorithm;

type Value = u64;
type State = orswot::BFTOrswot<Value>;
type DSB = dsb::SecureBroadcastProc<State>; // rename to SecureBroadcast
type Packet = dsb::Packet<<State as SecureBroadcastAlgorithm>::Op>;

#[derive(Debug, Clone)]
struct SharedDSB {
    dsb: Arc<Mutex<DSB>>,
}
impl SharedDSB {
    fn new() -> Self {
        Self {
            dsb: Arc::new(Mutex::new(DSB::new(Default::default()))),
        }
    }

    fn actor(&self) -> Actor {
        self.dsb.lock().unwrap().actor()
    }

    fn exec_algo_op(
        &self,
        f: impl FnOnce(&State) -> Option<<State as SecureBroadcastAlgorithm>::Op>,
    ) -> Vec<Packet> {
        self.dsb.lock().unwrap().exec_algo_op(f)
    }

    fn apply(&self, packet: Packet) -> Vec<Packet> {
        self.dsb.lock().unwrap().apply(packet)
    }

    fn read(&self) -> HashSet<Value> {
        self.dsb
            .lock()
            .unwrap()
            .read_state(|orswot| orswot.state().read().val)
    }
}

#[derive(Debug)]
struct Repl {
    state: SharedDSB,
    network_tx: mpsc::Sender<RouterCmd>,
}

#[cmdr]
impl Repl {
    fn new(state: SharedDSB, network_tx: mpsc::Sender<RouterCmd>) -> Self {
        Self { state, network_tx }
    }

    #[cmd]
    fn peer(&mut self, args: &[String]) -> CommandResult {
        match args {
            [ip_port] => match ip_port.parse::<SocketAddr>() {
                Ok(addr) => {
                    println!("Parsed an addr {:?}", addr);
                    self.network_tx.try_send(RouterCmd::SayHello(addr)).unwrap();
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
            [arg] => match arg.parse::<Value>() {
                Ok(v) => {
                    for packet in self.state.exec_algo_op(|orswot| Some(orswot.add(v))) {
                        self.network_tx
                            .try_send(RouterCmd::Deliver(packet))
                            .expect("Failed to queue packet");
                    }
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
            [arg] => match arg.parse::<Value>() {
                Ok(v) => {
                    for packet in self.state.exec_algo_op(|orswot| orswot.rm(v)) {
                        self.network_tx
                            .try_send(RouterCmd::Deliver(packet))
                            .expect("Failed to queue packet");
                    }
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
    state: SharedDSB,
    qp2p: QuicP2p,
    addr: SocketAddr,
    peers: HashMap<Actor, (Endpoint, SocketAddr)>,
}

#[derive(Debug)]
enum RouterCmd {
    SayHello(SocketAddr),
    AddPeer(Actor, SocketAddr),
    Deliver(Packet),
    Apply(Packet),
}

#[derive(Debug, Serialize, Deserialize)]
enum NetworkMsg {
    HelloMyNameIs(Actor, SocketAddr),
    Packet(Packet),
}

impl Router {
    fn new(state: SharedDSB) -> (Self, Endpoint) {
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

    async fn deliver_packet(&self, packet: Packet) {
        if let Some((peer, addr)) = self.peers.get(&packet.dest) {
            println!("Delivering to {:?} at addr {:?}", packet.dest, addr);
            let msg = bincode::serialize(&NetworkMsg::Packet(packet)).unwrap();
            let conn = peer.connect_to(&addr).await.unwrap();
            println!("Connected to {:?}", addr);
            let _ = conn.send_uni(msg.clone().into()).await.unwrap();
            println!("Sent to {:?}", addr);
            conn.close()
        } else {
            println!(
                "We don't have a peer matching the destination for packet {:?}",
                packet
            );
        }
    }

    async fn apply(&mut self, event: RouterCmd) {
        println!("Applying {:?}", event);
        match event {
            RouterCmd::SayHello(addr) => {
                let peer = self.new_endpoint();
                let conn = peer.connect_to(&addr).await.unwrap();
                // self.peers.insert(actor, (peer, addr));
                let msg =
                    bincode::serialize(&NetworkMsg::HelloMyNameIs(self.state.actor(), self.addr))
                        .unwrap();
                let _ = conn.send_uni(msg.into()).await.unwrap();
                conn.close();
            }
            RouterCmd::AddPeer(actor, addr) => {
                if !self.peers.contains_key(&actor) {
                    let peer = self.new_endpoint();
                    let conn = peer.connect_to(&addr).await.unwrap();
                    self.peers.insert(actor, (peer, addr));
                    let msg = bincode::serialize(&NetworkMsg::HelloMyNameIs(
                        self.state.actor(),
                        self.addr,
                    ))
                    .unwrap();
                    let _ = conn.send_uni(msg.into()).await.unwrap();
                    conn.close();
                }
            }
            RouterCmd::Deliver(packet) => {
                self.deliver_packet(packet).await;
            }
            RouterCmd::Apply(op_packet) => {
                for packet in self.state.apply(op_packet) {
                    self.deliver_packet(packet).await;
                }
            }
        }
    }
}

async fn listen_for_ops(endpoint: Endpoint, mut router_tx: mpsc::Sender<RouterCmd>) {
    println!("listening on {:?}", endpoint.our_addr());

    router_tx
        .send(RouterCmd::SayHello(endpoint.our_addr().unwrap()))
        .await
        .expect("Failed to send command to add self as peer");

    match endpoint.listen() {
        Ok(mut conns) => {
            while let Some(mut msgs) = conns.next().await {
                while let Some(msg) = msgs.next().await {
                    let net_msg: NetworkMsg =
                        bincode::deserialize(&msg.get_message_data()).unwrap();
                    let cmd = match net_msg {
                        NetworkMsg::HelloMyNameIs(actor, addr) => RouterCmd::AddPeer(actor, addr),
                        NetworkMsg::Packet(packet) => RouterCmd::Apply(packet),
                    };

                    router_tx
                        .send(cmd)
                        .await
                        .expect("Failed to send router command");
                }
            }
        }
        Err(e) => println!("Failed to start listening: {:?}", e),
    }
}

#[tokio::main]
async fn main() {
    let state = SharedDSB::new();
    let (router, endpoint) = Router::new(state.clone());
    let (router_tx, router_rx) = mpsc::channel(100);

    tokio::spawn(listen_for_ops(endpoint, router_tx.clone()));
    tokio::spawn(router.listen_for_cmds(router_rx));
    cmd_loop(&mut Repl::new(state, router_tx)).expect("Failure in REPL");
}

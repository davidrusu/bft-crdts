mod actor;
mod dynamic_secure_broadcast;
use std::fs::File;
use std::io::Write;

use actor::Actor;
use dynamic_secure_broadcast::{Net, Reconfig};

fn main() {
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2);
        for i in 0..nprocs {
            let i_actor = net.procs[i].id.actor();
            for j in 0..(nprocs * 2) {
                net.procs[j].trust(i_actor);
            }
        }

        let joining_members: Vec<Actor> =
            net.procs[nprocs..].iter().map(|p| p.id.actor()).collect();
        for i in 0..nprocs {
            let member = joining_members[i];
            let packets = net.procs[i].reconfig(Reconfig::Join(member)).unwrap();
            net.queue_packets(packets);
        }

        while !net.packets.is_empty() {
            println!("{:?}", net);
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].id.actor());
            }
        }

        let mut msc_file = File::create(format!("round_robin_split_vote_{}.msc", nprocs)).unwrap();
        msc_file.write_all(net.generate_msc().as_bytes()).unwrap();

        let expected_members = net.procs[0].members.clone();
        assert!(expected_members.len() > nprocs);

        for i in 0..nprocs {
            assert_eq!(net.procs[i].members, expected_members);
        }

        for member in expected_members.iter() {
            let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
            assert_eq!(p.members, expected_members);
        }
    }
}

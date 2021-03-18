#!/bin/bash
cargo build --release
sudo setcap cap_net_admin=eip target/release/ntcp
target/release/ntcp &
pid=$!
sudo ifconfig tun0 192.168.0.1/24 up
trap "kill $pid" INT TERM
wait $pid
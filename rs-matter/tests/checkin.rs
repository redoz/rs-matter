/*
 * Copyright (c) 2026 Project CHIP Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

//! Sessionless Check-In delivery and lifetime regression coverage.
#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use embassy_futures::select::select;
use rs_matter::crypto::{test_only_crypto, CanonAeadKeyRef};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::respond::Responder;
use rs_matter::sc::checkin::CheckIn;
use rs_matter::sc::{AsyncScHandler, OpCode, SecureChannel, PROTO_ID_SECURE_CHANNEL};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NetworkSend, NoNetwork};
use rs_matter::transport::packet::PacketHdr;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::WriteBuf;
use rs_matter::Matter;

const KEY: [u8; 16] = [0x11; 16];

struct NoReplies;
impl NetworkSend for NoReplies {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        panic!("Check-In must not elicit a reply: {data:02x?}");
    }
}

struct Recorder(async_channel::Sender<()>);
impl AsyncScHandler for Recorder {
    async fn check_in(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let mut payload = exchange.rx()?.payload().to_vec();
        let result =
            CheckIn::new(CanonAeadKeyRef::new(&KEY)).parse(&test_only_crypto(), &mut payload);
        if let Ok(parsed) = &result {
            assert_eq!(parsed.app_data, b"awake");
        }
        // Both successful and malformed messages release their exchange.
        if result.as_ref().is_ok_and(|parsed| parsed.counter % 3 == 0) {
            ().check_in(exchange).await?;
        } else {
            drop(exchange);
        }
        self.0.send(()).await.unwrap();
        result.map(|_| ())
    }
}

#[test]
fn sessionless_checkins_are_delivered_without_replies_or_session_leaks() {
    run_checkins(false);
}

#[test]
fn checkins_do_not_reuse_an_existing_plaintext_handshake_session() {
    run_checkins(true);
}

fn run_checkins(existing_session: bool) {
    common::init_env_logger();
    futures_lite::future::block_on(async {
        let crypto = test_only_crypto();
        let controller = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let (device_socket, controller_socket) = common::create_localhost_socket_pair();
        let controller_addr = controller_socket.get_ref().local_addr().unwrap();
        let handshake_session = existing_session.then(|| {
            controller.with_state(|state| {
                state
                    .sessions
                    .add(
                        1,
                        false,
                        Address::Udp(device_socket.get_ref().local_addr().unwrap()),
                        None,
                    )
                    .unwrap()
                    .id()
            })
        });
        let (completed, completion) = async_channel::bounded(1);
        let responder = Responder::new(
            "controller",
            SecureChannel::new_with_handler(&crypto, &(), Recorder(completed)),
            &controller,
            0,
        );
        let controller_fut = async {
            select(
                controller.run(&crypto, NoReplies, &controller_socket, NoNetwork),
                responder.run::<4>(),
            )
            .coalesce()
            .await
        };
        let device_fut = async {
            // More distinct identities than the session table can hold. Include
            // invalid payloads to exercise handler error cleanup as well.
            for counter in 1..=64u32 {
                let mut payload_buf = [0u8; 64];
                let payload = CheckIn::new(CanonAeadKeyRef::new(&KEY)).generate(
                    &crypto,
                    counter,
                    b"awake",
                    &mut payload_buf,
                )?;
                let payload = if counter % 2 == 0 {
                    &payload[..1]
                } else {
                    payload
                };
                let mut frame = [0u8; 256];
                let mut wb =
                    WriteBuf::new_with(&mut frame, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);
                wb.copy_from_slice(payload)?;
                let mut hdr = PacketHdr::new();
                hdr.plain.ctr = counter;
                hdr.plain.set_src_nodeid(Some(counter as u64));
                hdr.proto.proto_id = PROTO_ID_SECURE_CHANNEL;
                hdr.proto.proto_opcode = OpCode::CheckIn as u8;
                hdr.proto.exch_id = counter as u16;
                hdr.proto.set_initiator();
                hdr.proto.unset_reliable();
                hdr.encode(&crypto, None, 0, &mut wb)?;
                device_socket
                    .send_to(wb.as_slice(), controller_addr)
                    .await
                    .unwrap();
                completion.recv().await.unwrap();
                assert!(completion.try_recv().is_err(), "duplicate dispatch");
                controller.with_state(|state| {
                    assert_eq!(
                        state.sessions.iter().count(),
                        usize::from(existing_session),
                        "session leaked"
                    );
                    if let Some(id) = handshake_session {
                        assert_eq!(state.sessions.iter().next().unwrap().id(), id);
                    }
                });
            }
            Ok(())
        };
        common::run_device_controller(controller_fut, device_fut)
            .await
            .unwrap();
    });
}

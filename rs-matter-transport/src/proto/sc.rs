/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! The message types of the Secure Channel protocol. The protocol itself is in
//! `rs-matter-sc`, which re-exports them.
//!
//! They are here because the transport itself sends and parses Secure Channel
//! messages: standalone acknowledgements, and the `Busy` and `CloseSession` status
//! reports. `SessionParameters` configures a session. A `rs-matter-sc-core` crate,
//! which the transport and `rs-matter-sc` would depend on, would contain only these.

use core::borrow::Borrow;

use num_derive::FromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::exchange::MessageMeta;
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::storage::{ReadBuf, WriteBuf};

/* Secure Channel protocol ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x00;

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
    CheckIn = 0x50,
}

impl OpCode {
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_SECURE_CHANNEL,
            proto_opcode: *self as u8,
            // Check-In is a fire-and-forget notification sent without MRP, like
            // the standalone ack.
            reliable: !matches!(self, Self::MRPStandAloneAck | Self::CheckIn),
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(
            self,
            Self::MRPStandAloneAck
                | Self::StatusReport
                | Self::MsgCounterSyncReq
                | Self::MsgCounterSyncResp
                | Self::CheckIn
        )
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
}

impl SCStatusCodes {
    pub fn reliable(&self) -> bool {
        // CloseSession and Busy are sent without the R flag raised
        !matches!(self, SCStatusCodes::CloseSession | SCStatusCodes::Busy)
    }

    pub fn as_report<'a>(&self, payload: &'a [u8]) -> StatusReport<'a> {
        let general_code = match self {
            SCStatusCodes::SessionEstablishmentSuccess => GeneralCode::Success,
            SCStatusCodes::CloseSession => GeneralCode::Success,
            SCStatusCodes::Busy => GeneralCode::Busy,
            SCStatusCodes::InvalidParameter | SCStatusCodes::NoSharedTrustRoots => {
                GeneralCode::Failure
            }
        };

        StatusReport {
            general_code,
            proto_id: PROTO_ID_SECURE_CHANNEL as u32,
            proto_code: *self as u16,
            proto_data: payload,
        }
    }
}

pub fn sc_write(
    wb: &mut WriteBuf,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<Option<MessageMeta>, Error> {
    status_code.as_report(payload).write(wb)?;

    Ok(Some(
        OpCode::StatusReport.meta().reliable(status_code.reliable()),
    ))
}

#[allow(dead_code)]
#[derive(FromPrimitive, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

/// Represents the session parameters
/// that might present in a "PBKDFParamRequest"/"PBKDFParamResponse" or "CASE-Sigma1"/"CASE-Sigma2" message
#[derive(Default, Clone, FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
pub struct SessionParameters {
    /// Session Idle Interval
    pub sii: Option<u32>,
    /// Session Active Interval
    pub sai: Option<u32>,
    /// Session Active Threshold
    pub sat: Option<u16>,
    /// Data Model Revision
    pub dm_revision: Option<u16>,
    /// Interaction Model Revision
    pub im_revision: Option<u16>,
    /// Specification Version
    pub spec_version: Option<u32>,
    /// Maximum number of paths per invoke
    pub max_paths_per_invoke: Option<u16>,
}

/// Represents a Status Report message, as per "Appendix D: Status Report Messages" of the Matter Spec.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusReport<'a> {
    pub general_code: GeneralCode,
    pub proto_id: u32,
    pub proto_code: u16,
    pub proto_data: &'a [u8],
}

impl<'a> StatusReport<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self {
            general_code: num::FromPrimitive::from_u16(pb.le_u16()?)
                .ok_or(ErrorCode::InvalidOpcode)?,
            proto_id: pb.le_u32()?,
            proto_code: pb.le_u16()?,
            proto_data: pb.as_slice(),
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u16(self.general_code as u16)?;
        wb.le_u32(self.proto_id)?;
        wb.le_u16(self.proto_code)?;
        wb.copy_from_slice(self.proto_data)?;

        Ok(())
    }

    /// The error a session-establishment initiator fails with when the peer
    /// answers with this (non-success) status report.
    ///
    /// The two Secure Channel refusals a caller can act on are named:
    /// `NoSharedTrustRoots` (the responder holds no fabric matching our
    /// destination identifier - it does not, or no longer, trusts us) becomes
    /// `ErrorCode::NoSharedTrustRoots`, and `Busy` (the responder is out of
    /// resources for now and may be retried) becomes `ErrorCode::Busy`.
    /// Anything else stays the generic `ErrorCode::Invalid`.
    pub fn establishment_error(&self) -> Error {
        let secure_channel = self.proto_id == PROTO_ID_SECURE_CHANNEL as u32;

        if secure_channel && self.proto_code == SCStatusCodes::NoSharedTrustRoots as u16 {
            ErrorCode::NoSharedTrustRoots.into()
        } else if self.general_code == GeneralCode::Busy
            || (secure_channel && self.proto_code == SCStatusCodes::Busy as u16)
        {
            ErrorCode::Busy.into()
        } else {
            ErrorCode::Invalid.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GeneralCode, SCStatusCodes, StatusReport, PROTO_ID_SECURE_CHANNEL};
    use crate::error::ErrorCode;

    /// A refusal the initiator can act on is named; anything else stays
    /// `Invalid`.
    #[test]
    fn establishment_error_names_no_shared_trust_roots_and_busy() {
        let code = |status: StatusReport<'_>| status.establishment_error().code();

        assert_eq!(
            code(SCStatusCodes::NoSharedTrustRoots.as_report(&[])),
            ErrorCode::NoSharedTrustRoots
        );
        // `Busy` carries the minimum wait time as protocol data.
        assert_eq!(
            code(SCStatusCodes::Busy.as_report(&[0xe8, 0x03])),
            ErrorCode::Busy
        );
        assert_eq!(
            code(SCStatusCodes::InvalidParameter.as_report(&[])),
            ErrorCode::Invalid
        );
        assert_eq!(
            code(StatusReport {
                general_code: GeneralCode::Failure,
                proto_id: PROTO_ID_SECURE_CHANNEL as u32,
                proto_code: 0xffff,
                proto_data: &[],
            }),
            ErrorCode::Invalid
        );
        // Another protocol's code 1 is not a Secure Channel refusal.
        assert_eq!(
            code(StatusReport {
                general_code: GeneralCode::Failure,
                proto_id: 0x0001,
                proto_code: SCStatusCodes::NoSharedTrustRoots as u16,
                proto_data: &[],
            }),
            ErrorCode::Invalid
        );
    }
}

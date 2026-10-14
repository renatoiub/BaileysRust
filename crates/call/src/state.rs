//! Máquina de estados da chamada (port de `services/call/call-state.ts`).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    CallDirection, CallMediaType, CallState, EndCallReason, RelayData,
};

/// Erro de transição inválida.
#[derive(Debug, thiserror::Error)]
#[error("invalid transition '{attempted}' in state '{current_state}'")]
pub struct InvalidTransition {
    pub current_state: String,
    pub attempted: String,
}

/// Transição de estado.
#[derive(Debug, Clone)]
pub enum CallTransition {
    OfferSent,
    OfferReceived { silenced: bool },
    LocalAccepted,
    RemoteAccepted,
    LocalRejected { reason: EndCallReason },
    RemoteRejected { reason: EndCallReason },
    MediaConnected,
    Terminated { reason: EndCallReason },
    Hold,
    Resume,
    AudioMuteChanged { muted: bool },
    VideoStateChanged { off: bool },
}

/// Dados de estado.
#[derive(Debug, Clone)]
pub struct CallStateData {
    pub state: CallState,
    pub connected_at: Option<u64>,
    pub accepted_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub audio_muted: bool,
    pub video_off: bool,
    pub silenced: bool,
    pub end_reason: Option<EndCallReason>,
    pub duration_secs: Option<u64>,
}

impl Default for CallStateData {
    fn default() -> Self {
        Self {
            state: CallState::Initiating,
            connected_at: None,
            accepted_at: None,
            ended_at: None,
            audio_muted: false,
            video_off: true,
            silenced: false,
            end_reason: None,
            duration_secs: None,
        }
    }
}

/// Info de chamada.
#[derive(Debug, Clone)]
pub struct CallInfo {
    pub call_id: String,
    pub peer_jid: String,
    pub call_creator: String,
    pub direction: CallDirection,
    pub media_type: CallMediaType,
    pub state_data: CallStateData,
    pub created_at: u64,
    pub group_jid: Option<String>,
    pub is_offline: bool,
    pub caller_pn: Option<String>,
    pub encryption_key: Option<Vec<u8>>,
    pub relay_data: Option<RelayData>,
    pub elected_relay_idx: Option<usize>,
}

impl CallInfo {
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn new_outgoing(
        call_id: String,
        peer_jid: String,
        call_creator: String,
        media_type: CallMediaType,
    ) -> Self {
        Self {
            call_id,
            peer_jid,
            call_creator,
            direction: CallDirection::Outgoing,
            media_type,
            state_data: CallStateData {
                state: CallState::Initiating,
                video_off: media_type != CallMediaType::Video,
                ..Default::default()
            },
            created_at: Self::now(),
            group_jid: None,
            is_offline: false,
            caller_pn: None,
            encryption_key: None,
            relay_data: None,
            elected_relay_idx: None,
        }
    }

    pub fn new_incoming(
        call_id: String,
        peer_jid: String,
        call_creator: String,
        caller_pn: Option<String>,
        media_type: CallMediaType,
    ) -> Self {
        Self {
            call_id,
            peer_jid,
            call_creator,
            direction: CallDirection::Incoming,
            media_type,
            state_data: CallStateData {
                state: CallState::IncomingRinging,
                video_off: media_type != CallMediaType::Video,
                ..Default::default()
            },
            created_at: Self::now(),
            group_jid: None,
            is_offline: false,
            caller_pn,
            encryption_key: None,
            relay_data: None,
            elected_relay_idx: None,
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.direction == CallDirection::Outgoing
    }

    pub fn is_active(&self) -> bool {
        self.state_data.state == CallState::Active
    }

    pub fn is_ringing(&self) -> bool {
        self.state_data.state == CallState::Ringing
            || self.state_data.state == CallState::IncomingRinging
    }

    pub fn is_ended(&self) -> bool {
        self.state_data.state == CallState::Ended
    }

    pub fn can_accept(&self) -> bool {
        self.state_data.state == CallState::IncomingRinging
    }

    pub fn can_reject(&self) -> bool {
        self.state_data.state == CallState::IncomingRinging
            || self.state_data.state == CallState::Ringing
    }

    pub fn apply_transition(&mut self, transition: CallTransition) -> Result<(), InvalidTransition> {
        let s = &mut self.state_data;
        let err = |attempted: &str| InvalidTransition {
            current_state: s.state.as_str().to_string(),
            attempted: attempted.to_string(),
        };

        match transition {
            CallTransition::OfferSent => {
                if s.state != CallState::Initiating {
                    return Err(err("offer_sent"));
                }
                s.state = CallState::Ringing;
            }
            CallTransition::OfferReceived { silenced } => {
                if s.state != CallState::Initiating {
                    return Err(err("offer_received"));
                }
                s.state = CallState::IncomingRinging;
                s.silenced = silenced;
            }
            CallTransition::RemoteAccepted => {
                if s.state != CallState::Ringing {
                    return Err(err("remote_accepted"));
                }
                s.state = CallState::Connecting;
                s.accepted_at = Some(Self::now());
            }
            CallTransition::LocalAccepted => {
                if s.state != CallState::IncomingRinging {
                    return Err(err("local_accepted"));
                }
                s.state = CallState::Connecting;
                s.accepted_at = Some(Self::now());
            }
            CallTransition::RemoteRejected { reason } => {
                if s.state != CallState::Ringing {
                    return Err(err("remote_rejected"));
                }
                s.state = CallState::Ended;
                s.ended_at = Some(Self::now());
                s.end_reason = Some(reason);
            }
            CallTransition::LocalRejected { reason } => {
                if s.state != CallState::IncomingRinging {
                    return Err(err("local_rejected"));
                }
                s.state = CallState::Ended;
                s.ended_at = Some(Self::now());
                s.end_reason = Some(reason);
            }
            CallTransition::MediaConnected => {
                if s.state != CallState::Connecting {
                    return Err(err("media_connected"));
                }
                s.state = CallState::Active;
                s.connected_at = Some(Self::now());
                s.video_off = self.media_type != CallMediaType::Video;
            }
            CallTransition::Terminated { reason } => {
                if s.state == CallState::Ended {
                    return Err(err("terminated"));
                }
                if let Some(at) = s.connected_at {
                    s.duration_secs = Some(Self::now().saturating_sub(at));
                }
                s.state = CallState::Ended;
                s.ended_at = Some(Self::now());
                s.end_reason = Some(reason);
            }
            CallTransition::Hold => {
                if s.state != CallState::Active {
                    return Err(err("hold"));
                }
                s.state = CallState::OnHold;
            }
            CallTransition::Resume => {
                if s.state != CallState::OnHold {
                    return Err(err("resume"));
                }
                s.state = CallState::Active;
            }
            CallTransition::AudioMuteChanged { muted } => {
                if s.state != CallState::Active {
                    return Err(err("audio_mute_changed"));
                }
                s.audio_muted = muted;
            }
            CallTransition::VideoStateChanged { off } => {
                if s.state != CallState::Active {
                    return Err(err("video_state_changed"));
                }
                s.video_off = off;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_lifecycle() {
        let mut call = CallInfo::new_outgoing(
            "call-1".into(),
            "peer".into(),
            "me:0@s.whatsapp.net".into(),
            CallMediaType::Audio,
        );
        assert_eq!(call.state_data.state, CallState::Initiating);
        call.apply_transition(CallTransition::OfferSent).unwrap();
        assert_eq!(call.state_data.state, CallState::Ringing);
        call.apply_transition(CallTransition::RemoteAccepted).unwrap();
        assert_eq!(call.state_data.state, CallState::Connecting);
        call.apply_transition(CallTransition::MediaConnected).unwrap();
        assert_eq!(call.state_data.state, CallState::Active);
        call.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })
        .unwrap();
        assert_eq!(call.state_data.state, CallState::Ended);
        assert!(call.state_data.duration_secs.is_some());
    }

    #[test]
    fn invalid_transition_errors() {
        let mut call = CallInfo::new_incoming(
            "call-2".into(),
            "peer".into(),
            "peer:0@s.whatsapp.net".into(),
            None,
            CallMediaType::Audio,
        );
        assert!(call
            .apply_transition(CallTransition::OfferSent)
            .is_err());
        assert!(call.can_accept());
        assert!(call.can_reject());
    }
}

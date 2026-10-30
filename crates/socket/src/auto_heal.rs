//! Auto-heal de criptografia (paridade com `container/src/services/whatsapp/autoHeal.ts`).
//!
//! Dois padrões de falha, cada um com a sua cura:
//! - muitos usuários distintos pedindo retry no mesmo grupo → a nossa sender key
//!   do grupo está quebrada para eles → `GroupReset` (sender key nova);
//! - o mesmo device pedindo retry de várias mensagens diferentes, ou falhando
//!   seguidamente no decrypt 1:1 → sessão quebrada → `SessionReset`.
//!
//! Só detecta; quem executa a ação é o `Client`. Estado em memória, por conexão.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AutoHealConfig {
    pub enabled: bool,
    /// Percentual dos participantes que precisa pedir retry para trocar a sender key.
    pub group_pct: f64,
    pub group_min: usize,
    pub group_max: usize,
    /// Limite quando o tamanho do grupo não é conhecido.
    pub group_default: usize,
    pub group_window: Duration,
    pub group_cooldown: Duration,
    /// Mensagens distintas com retry do mesmo device para resetar a sessão.
    pub device_retries: usize,
    pub device_window: Duration,
    /// Falhas de decrypt 1:1 do mesmo device para resetar a sessão.
    pub decrypt_fails: usize,
    pub decrypt_window: Duration,
    pub device_cooldown: Duration,
}

impl Default for AutoHealConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            group_pct: 5.0,
            group_min: 3,
            group_max: 20,
            group_default: 5,
            group_window: Duration::from_secs(10 * 60),
            group_cooldown: Duration::from_secs(60 * 60),
            device_retries: 3,
            device_window: Duration::from_secs(30 * 60),
            decrypt_fails: 5,
            decrypt_window: Duration::from_secs(10 * 60),
            device_cooldown: Duration::from_secs(30 * 60),
        }
    }
}

impl AutoHealConfig {
    /// `clamp(ceil(pct% dos participantes), min, max)`; sem tamanho → `group_default`.
    pub fn group_threshold(&self, participants: usize) -> usize {
        if participants == 0 {
            return self.group_default;
        }
        let pct = ((participants as f64) * self.group_pct / 100.0).ceil() as usize;
        pct.max(self.group_min).min(self.group_max)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealAction {
    GroupReset { group: String, users: usize, threshold: usize },
    SessionReset { jid: String, reason: &'static str, count: usize },
}

#[derive(Default)]
struct State {
    group_retries: HashMap<String, HashMap<String, Instant>>,
    device_retries: HashMap<String, HashMap<String, Instant>>,
    decrypt_failures: HashMap<String, Vec<Instant>>,
    last_group_reset: HashMap<String, Instant>,
    last_device_reset: HashMap<String, Instant>,
}

/// Mapas por device crescem com contatos novos; acima disso, descarta os vazios.
const MAX_TRACKED: usize = 5000;

pub struct AutoHeal {
    cfg: AutoHealConfig,
    state: Mutex<State>,
}

fn cooled(last: Option<&Instant>, now: Instant, cooldown: Duration) -> bool {
    last.map_or(true, |at| now.duration_since(*at) >= cooldown)
}

fn prune(seen: &mut HashMap<String, Instant>, now: Instant, window: Duration) {
    seen.retain(|_, at| now.duration_since(*at) <= window);
}

fn is_group(jid: &str) -> bool {
    jid.ends_with("@g.us")
}

/// Usuário sem device/agent (`5511...:3@s.whatsapp.net` → `5511...@s.whatsapp.net`).
fn user_of(jid: &str) -> String {
    let (local, server) = jid.split_once('@').unwrap_or((jid, ""));
    let user = local.split(':').next().unwrap_or(local);
    let user = user.split('_').next().unwrap_or(user);
    format!("{user}@{server}")
}

/// Erros de sessão 1:1 que justificam recriar a sessão (não os de sender key).
pub fn is_session_decrypt_error(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    ["bad mac", "no matching sessions", "no session record", "no open session", "no sessions", "no session to encrypt"]
        .iter()
        .any(|needle| t.contains(needle))
}

impl AutoHeal {
    pub fn new(cfg: AutoHealConfig) -> Self {
        Self { cfg, state: Mutex::new(State::default()) }
    }

    pub fn config(&self) -> &AutoHealConfig {
        &self.cfg
    }

    fn device_reset(
        &self,
        st: &mut State,
        jid: &str,
        reason: &'static str,
        count: usize,
        now: Instant,
    ) -> Option<HealAction> {
        if !cooled(st.last_device_reset.get(jid), now, self.cfg.device_cooldown) {
            return None;
        }
        st.last_device_reset.insert(jid.to_string(), now);
        st.device_retries.remove(jid);
        st.decrypt_failures.remove(jid);
        Some(HealAction::SessionReset { jid: jid.to_string(), reason, count })
    }

    /// Retry receipt recebido. `group_participants` = tamanho do grupo (0 = desconhecido).
    pub fn note_retry(
        &self,
        from: &str,
        participant: Option<&str>,
        msg_id: &str,
        group_participants: usize,
        now: Instant,
    ) -> Vec<HealAction> {
        let mut actions = Vec::new();
        if !self.cfg.enabled || from.is_empty() || msg_id.is_empty() {
            return actions;
        }
        let mut st = self.state.lock().unwrap();
        let group = is_group(from);

        if let (true, Some(participant)) = (group, participant) {
            if cooled(st.last_group_reset.get(from), now, self.cfg.group_cooldown) {
                let seen = st.group_retries.entry(from.to_string()).or_default();
                seen.insert(user_of(participant), now);
                prune(seen, now, self.cfg.group_window);
                let threshold = self.cfg.group_threshold(group_participants);
                if seen.len() >= threshold {
                    let users = seen.len();
                    st.group_retries.remove(from);
                    st.last_group_reset.insert(from.to_string(), now);
                    actions.push(HealAction::GroupReset { group: from.to_string(), users, threshold });
                }
            }
        }

        let device = match participant {
            Some(p) => p,
            None if !group => from,
            None => return actions,
        };
        if st.device_retries.len() > MAX_TRACKED {
            st.device_retries.retain(|_, m| !m.is_empty());
        }
        let msgs = st.device_retries.entry(device.to_string()).or_default();
        msgs.insert(msg_id.to_string(), now);
        prune(msgs, now, self.cfg.device_window);
        let count = msgs.len();
        if count >= self.cfg.device_retries {
            if let Some(action) = self.device_reset(&mut st, device, "retry", count, now) {
                actions.push(action);
            }
        }
        actions
    }

    /// Falha de decrypt 1:1 vinda de `device`.
    pub fn note_decrypt_failure(&self, device: &str, now: Instant) -> Option<HealAction> {
        if !self.cfg.enabled || device.is_empty() || is_group(device) {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        if st.decrypt_failures.len() > MAX_TRACKED {
            let window = self.cfg.decrypt_window;
            st.decrypt_failures
                .retain(|_, v| v.last().is_some_and(|at| now.duration_since(*at) <= window));
        }
        let window = self.cfg.decrypt_window;
        let times = st.decrypt_failures.entry(device.to_string()).or_default();
        times.retain(|at| now.duration_since(*at) <= window);
        times.push(now);
        let count = times.len();
        if count >= self.cfg.decrypt_fails {
            return self.device_reset(&mut st, device, "decrypt", count, now);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "120363423566447832@g.us";

    #[test]
    fn group_threshold_is_proportional_and_clamped() {
        let cfg = AutoHealConfig::default();
        assert_eq!(cfg.group_threshold(0), 5);
        assert_eq!(cfg.group_threshold(10), 3);
        assert_eq!(cfg.group_threshold(200), 10);
        assert_eq!(cfg.group_threshold(1000), 20);
    }

    #[test]
    fn three_distinct_messages_from_same_device_reset_session() {
        let heal = AutoHeal::new(AutoHealConfig::default());
        let now = Instant::now();
        let dev = "74406818787529:3@lid";
        assert!(heal.note_retry(dev, None, "A", 0, now).is_empty());
        assert!(heal.note_retry(dev, None, "A", 0, now).is_empty());
        assert!(heal.note_retry(dev, None, "B", 0, now).is_empty());
        let actions = heal.note_retry(dev, None, "C", 0, now);
        assert_eq!(
            actions,
            vec![HealAction::SessionReset { jid: dev.to_string(), reason: "retry", count: 3 }]
        );
    }

    #[test]
    fn cooldown_blocks_second_session_reset() {
        let heal = AutoHeal::new(AutoHealConfig::default());
        let now = Instant::now();
        let dev = "5512991923706:6@s.whatsapp.net";
        let mut fired = 0;
        for _ in 0..12 {
            if heal.note_decrypt_failure(dev, now).is_some() {
                fired += 1;
            }
        }
        assert_eq!(fired, 1);
        let later = now + Duration::from_secs(31 * 60);
        let mut fired_later = 0;
        for _ in 0..5 {
            if heal.note_decrypt_failure(dev, later).is_some() {
                fired_later += 1;
            }
        }
        assert_eq!(fired_later, 1);
    }

    #[test]
    fn group_reset_counts_distinct_users_not_devices() {
        let heal = AutoHeal::new(AutoHealConfig::default());
        let now = Instant::now();
        // Grupo de 60 → limite 3. Dois devices do mesmo usuário contam como um.
        assert!(heal.note_retry(GROUP, Some("111:1@lid"), "M1", 60, now).iter().all(|a| !matches!(a, HealAction::GroupReset { .. })));
        assert!(heal.note_retry(GROUP, Some("111:2@lid"), "M1", 60, now).iter().all(|a| !matches!(a, HealAction::GroupReset { .. })));
        assert!(heal.note_retry(GROUP, Some("222@lid"), "M1", 60, now).iter().all(|a| !matches!(a, HealAction::GroupReset { .. })));
        let actions = heal.note_retry(GROUP, Some("333@lid"), "M1", 60, now);
        assert!(actions.contains(&HealAction::GroupReset { group: GROUP.to_string(), users: 3, threshold: 3 }));
        // Cooldown: outro pico logo depois não dispara de novo.
        for user in ["444@lid", "555@lid", "666@lid", "777@lid"] {
            let actions = heal.note_retry(GROUP, Some(user), "M2", 60, now);
            assert!(actions.iter().all(|a| !matches!(a, HealAction::GroupReset { .. })));
        }
    }

    #[test]
    fn group_errors_are_not_session_errors() {
        assert!(is_session_decrypt_error("bad MAC"));
        assert!(is_session_decrypt_error("no matching sessions found for message"));
        assert!(!is_session_decrypt_error("no SenderKeyRecord found for x"));
    }
}

//! Agent identity (Ed25519) and persistent state: pinned control-plane key and
//! the set of contract nonces already executed (replay protection).

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct State {
    dir: PathBuf,
    pub key: SigningKey,
    pub nonces: BTreeSet<String>,
}

impl State {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating state dir {}", dir.display()))?;
        let key_path = dir.join("identity.key");
        let key = if key_path.exists() {
            let raw = hex::decode(std::fs::read_to_string(&key_path)?.trim())?;
            let seed: [u8; 32] = raw.as_slice().try_into().context("identity.key must hold 32 bytes")?;
            SigningKey::from_bytes(&seed)
        } else {
            let k = SigningKey::generate(&mut rand::rngs::OsRng);
            std::fs::write(&key_path, hex::encode(k.to_bytes()))?;
            k
        };
        let nonces = std::fs::read_to_string(dir.join("nonces.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Ok(Self { dir, key, nonces })
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }

    /// Pin the control-plane key on first contact (TOFU over verified TLS), or
    /// enforce an operator-provided pin.
    pub fn pin_control_plane(&self, offered: &[u8], operator_pin: Option<&str>) -> Result<VerifyingKey> {
        let offered: [u8; 32] = offered.try_into().context("control-plane key must be 32 bytes")?;
        let path = self.dir.join("control_plane.pub");
        if let Some(pin) = operator_pin {
            if hex::decode(pin.trim())? != offered {
                bail!("control-plane key does not match the operator-provided pin");
            }
        } else if path.exists() {
            let pinned = hex::decode(std::fs::read_to_string(&path)?.trim())?;
            if pinned != offered {
                bail!("control-plane key changed since first contact (pinned {}); refusing", path.display());
            }
        }
        std::fs::write(&path, hex::encode(offered))?;
        Ok(VerifyingKey::from_bytes(&offered)?)
    }

    pub fn remember_nonce(&mut self, nonce: &str) -> Result<()> {
        self.nonces.insert(nonce.to_string());
        while self.nonces.len() > 10_000 {
            let first = self.nonces.iter().next().cloned().unwrap();
            self.nonces.remove(&first);
        }
        std::fs::write(self.dir.join("nonces.json"), serde_json::to_string(&self.nonces)?)?;
        Ok(())
    }
}

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs, path::PathBuf};

use iced::{
    clipboard,
    widget::{
        button, checkbox, column, container, horizontal_rule, pick_list, row, scrollable, text,
        text_input, Space,
    },
    Element, Length, Task, Theme,
};
use puzzle_slipstream_core::{
    envelope::{decrypt_manifest, envelope_from_json_bounded, envelope_from_transport},
    relay::{submit_private_transaction, RelayReceipt, RelayTarget},
    rpc::{
        check_destination_confirmations, test_mempool_accept, ConfirmationResult, CorePolicyResult,
        CoreRpcConfig,
    },
    validation::validate_manifest,
    EncryptedSweepEnvelope, SweepManifest,
};
use zeroize::{Zeroize, Zeroizing};

const MAINNET_SUBMIT_CONFIRMATION: &str = "SUBMIT TO MARA";
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn main() -> iced::Result {
    iced::application("PuzzleSlipstream Relay", RelayApp::update, RelayApp::view)
        .theme(|_| Theme::Dark)
        .run_with(|| (RelayApp::default(), Task::none()))
}

#[derive(Debug)]
struct RelayApp {
    envelope_path: String,
    transport_text: String,
    passphrase: String,
    envelope: Option<EncryptedSweepEnvelope>,
    manifest: Option<SweepManifest>,
    target: RelayTarget,
    client_code: String,
    relay_visibility_ack: bool,
    mainnet_confirmation: String,
    cookie_path: String,
    rpc_port: String,
    policy_result: Option<CorePolicyResult>,
    confirmation_result: Option<ConfirmationResult>,
    receipt: Option<RelayReceipt>,
    busy: bool,
    status: Status,
}

#[derive(Debug, Clone)]
enum Message {
    ChooseEnvelope,
    EnvelopePathChanged(String),
    LoadEnvelope,
    TransportChanged(String),
    ParseTransport,
    PassphraseChanged(String),
    DecryptAndVerify,
    TargetSelected(RelayTarget),
    ClientCodeChanged(String),
    RelayVisibilityAckChanged(bool),
    MainnetConfirmationChanged(String),
    ChooseCookie,
    CookiePathChanged(String),
    RpcPortChanged(String),
    RunPolicyCheck,
    PolicyFinished(Result<CorePolicyResult, String>),
    SubmitPrivately,
    SubmissionFinished(Result<RelayReceipt, String>),
    CheckConfirmations,
    ConfirmationsFinished(Result<ConfirmationResult, String>),
    CopyTransactionId,
    ClearSession,
}

#[derive(Debug, Clone)]
struct Status {
    kind: StatusKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusKind {
    Neutral,
    Success,
    Warning,
    Error,
}

impl Default for RelayApp {
    fn default() -> Self {
        Self {
            envelope_path: String::new(),
            transport_text: String::new(),
            passphrase: String::new(),
            envelope: None,
            manifest: None,
            target: RelayTarget::LoopbackMock,
            client_code: String::new(),
            relay_visibility_ack: false,
            mainnet_confirmation: String::new(),
            cookie_path: String::new(),
            rpc_port: "18443".to_owned(),
            policy_result: None,
            confirmation_result: None,
            receipt: None,
            busy: false,
            status: Status {
                kind: StatusKind::Neutral,
                message: "Load an encrypted .swe file or paste PSW1 transport text. This application never accepts a private key."
                    .to_owned(),
            },
        }
    }
}

impl Drop for RelayApp {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.transport_text.zeroize();
        self.mainnet_confirmation.zeroize();
        self.client_code.zeroize();
    }
}

impl RelayApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ChooseEnvelope => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("PuzzleSlipstream encrypted sweep", &["swe", "json"])
                    .pick_file()
                {
                    self.envelope_path = path.display().to_string();
                    self.load_envelope_file();
                }
            }
            Message::EnvelopePathChanged(value) => self.envelope_path = bounded(value, 4096),
            Message::LoadEnvelope => self.load_envelope_file(),
            Message::TransportChanged(value) => {
                self.transport_text = bounded(value, 16 * 1024 * 1024)
            }
            Message::ParseTransport => self.parse_transport(),
            Message::PassphraseChanged(value) => self.passphrase = bounded(value, 1024),
            Message::DecryptAndVerify => self.decrypt_and_verify(),
            Message::TargetSelected(value) => {
                self.target = value;
                self.receipt = None;
            }
            Message::ClientCodeChanged(value) => self.client_code = bounded(value, 200),
            Message::RelayVisibilityAckChanged(value) => self.relay_visibility_ack = value,
            Message::MainnetConfirmationChanged(value) => {
                self.mainnet_confirmation = bounded(value, 64)
            }
            Message::ChooseCookie => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.cookie_path = path.display().to_string();
                }
            }
            Message::CookiePathChanged(value) => self.cookie_path = bounded(value, 4096),
            Message::RpcPortChanged(value) => self.rpc_port = digits_only(value, 5),
            Message::RunPolicyCheck => return self.run_policy_check(),
            Message::PolicyFinished(result) => {
                self.busy = false;
                match result {
                    Ok(policy) => {
                        let allowed = policy.allowed;
                        let detail = if allowed {
                            "Your loopback Bitcoin Core node accepted the transaction under its current mempool policy. Nothing was broadcast."
                                .to_owned()
                        } else {
                            format!(
                                "Your loopback node rejected the transaction: {}",
                                policy
                                    .reject_reason
                                    .clone()
                                    .unwrap_or_else(|| "no reason returned".to_owned())
                            )
                        };
                        self.policy_result = Some(policy);
                        if allowed {
                            self.set_success(detail);
                        } else {
                            self.set_error(detail);
                        }
                    }
                    Err(error) => self.set_error(format!("Local policy check failed: {error}")),
                }
            }
            Message::SubmitPrivately => return self.submit_privately(),
            Message::SubmissionFinished(result) => {
                self.busy = false;
                self.mainnet_confirmation.zeroize();
                self.mainnet_confirmation.clear();
                match result {
                    Ok(receipt) => {
                        self.receipt = Some(receipt);
                        self.set_warning("Relay accepted the HTTP submission. This is not a Bitcoin confirmation. Track output zero with your own node.");
                    }
                    Err(error) => {
                        self.set_error(format!("Private submission stopped or failed: {error}"))
                    }
                }
            }
            Message::CheckConfirmations => return self.check_confirmations(),
            Message::ConfirmationsFinished(result) => {
                self.busy = false;
                match result {
                    Ok(confirmation) => {
                        let message = if confirmation.found_unspent_output {
                            if confirmation.confirmations > 0 {
                                format!(
                                    "Your node reports {} confirmation(s) for destination output zero.",
                                    confirmation.confirmations
                                )
                            } else {
                                "Your node sees destination output zero with zero confirmations."
                                    .to_owned()
                            }
                        } else {
                            "Your node did not return destination output zero. It may be unseen, already spent, pruned from the available view, or the RPC/node settings may be unsuitable."
                                .to_owned()
                        };
                        self.confirmation_result = Some(confirmation);
                        self.set_success(message);
                    }
                    Err(error) => {
                        self.set_error(format!("Confirmation check failed: {error}"))
                    }
                }
            }
            Message::CopyTransactionId => {
                if let Some(manifest) = &self.manifest {
                    let transaction_id = manifest.transaction_id.clone();
                    self.set_success("Transaction ID copied.");
                    return clipboard::write(transaction_id);
                }
            }
            Message::ClearSession => self.clear_session(),
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = column![
            text("PuzzleSlipstream Relay").size(36),
            text("Independent verification · optional loopback Bitcoin Core policy check · private relay submission")
                .size(16),
            container(
                text("Never enter a private key here. The signed P2PKH transaction contains its public key and will be visible to MARA and any downstream miner.")
                    .size(14),
            )
            .padding(14)
            .width(Length::Fill)
            .style(container::bordered_box),
        ]
        .spacing(8);

        let status = container(
            column![
                text(status_label(self.status.kind)).size(13),
                text(&self.status.message).size(15),
            ]
            .spacing(4),
        )
        .padding(14)
        .width(Length::Fill)
        .style(container::bordered_box);

        let import_card = container(
            column![
                text("1 · Import encrypted sweep").size(24),
                row![
                    text_input("Path to encrypted .swe", &self.envelope_path)
                        .on_input(Message::EnvelopePathChanged)
                        .padding(10)
                        .width(Length::Fill),
                    button(text("Choose…")).on_press(Message::ChooseEnvelope),
                    button(text("Load")).on_press(Message::LoadEnvelope),
                ]
                .spacing(8),
                text("Or paste encrypted PSW1 transport text").size(13),
                text_input("PSW1:…", &self.transport_text)
                    .on_input(Message::TransportChanged)
                    .padding(10),
                button(text("Parse transport text")).on_press(Message::ParseTransport),
                horizontal_rule(1),
                text("Transfer passphrase").size(13),
                text_input("Entered only to decrypt the signed envelope", &self.passphrase)
                    .on_input(Message::PassphraseChanged)
                    .secure(true)
                    .padding(12),
                button(text("Decrypt & independently verify").size(16))
                    .on_press(Message::DecryptAndVerify)
                    .padding(12),
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        let review_card: Element<'_, Message> = match &self.manifest {
            Some(manifest) => container(
                column![
                    text("2 · Verified transaction review").size(24),
                    summary_grid(manifest),
                    row![
                        button(text("Copy transaction ID"))
                            .on_press(Message::CopyTransactionId)
                            .padding(9),
                        button(text("Clear decrypted session"))
                            .on_press(Message::ClearSession)
                            .padding(9),
                    ]
                    .spacing(10),
                ]
                .spacing(12),
            )
            .padding(20)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into(),
            None => container(
                column![
                    text("2 · Verified transaction review").size(24),
                    text("No authenticated and independently verified sweep is loaded.").size(14),
                ]
                .spacing(10),
            )
            .padding(20)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into(),
        };

        let rpc_card = container(
            column![
                text("3 · Optional local Bitcoin Core checks").size(24),
                text("RPC is restricted to literal 127.0.0.1. testmempoolaccept validates policy without broadcasting.").size(14),
                row![
                    column![
                        text("Bitcoin Core cookie file").size(13),
                        row![
                            text_input("Path to .cookie", &self.cookie_path)
                                .on_input(Message::CookiePathChanged)
                                .padding(10)
                                .width(Length::Fill),
                            button(text("Choose…")).on_press(Message::ChooseCookie),
                        ]
                        .spacing(8),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(4)),
                    column![
                        text("RPC port").size(13),
                        text_input("18443", &self.rpc_port)
                            .on_input(Message::RpcPortChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                ]
                .spacing(12),
                row![
                    action_button("Run local policy check", Message::RunPolicyCheck, self.busy),
                    action_button("Check confirmations", Message::CheckConfirmations, self.busy),
                ]
                .spacing(10),
                policy_text(self.policy_result.as_ref()),
                confirmation_text(self.confirmation_result.as_ref()),
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        let submit_card = container(
            column![
                text("4 · Private relay submission").size(24),
                text("There is no public broadcast endpoint and no fallback. Production submission is mainnet-only and requires a mainnet-feature build.").size(14),
                row![
                    column![
                        text("Relay target").size(13),
                        pick_list(RelayTarget::ALL.to_vec(), Some(self.target), Message::TargetSelected)
                            .width(Length::Fill),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(2)),
                    column![
                        text("Optional MARA client code").size(13),
                        text_input("Leave blank when not issued", &self.client_code)
                            .on_input(Message::ClientCodeChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(2)),
                ]
                .spacing(12),
                checkbox(
                    "I understand the relay/miner receives the public key and raw signed transaction, and acceptance is not confirmation.",
                    self.relay_visibility_ack,
                )
                .on_toggle(Message::RelayVisibilityAckChanged),
                if self.target == RelayTarget::MaraProduction {
                    column![
                        text(format!("Type {MAINNET_SUBMIT_CONFIRMATION} to enable production submission")).size(13),
                        text_input(MAINNET_SUBMIT_CONFIRMATION, &self.mainnet_confirmation)
                            .on_input(Message::MainnetConfirmationChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                } else {
                    column![text("Loopback mock mode never leaves 127.0.0.1.").size(13)]
                },
                action_button("Submit privately", Message::SubmitPrivately, self.busy),
                receipt_text(self.receipt.as_ref()),
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        scrollable(
            container(
                column![
                    header,
                    Space::with_height(8),
                    status,
                    import_card,
                    review_card,
                    rpc_card,
                    submit_card,
                    text("Open-source alpha · not audited · authorized use only · no private key input exists in this application")
                        .size(12),
                    Space::with_height(20),
                ]
                .spacing(16),
            )
            .padding(24)
            .width(Length::Fill),
        )
        .into()
    }

    fn load_envelope_file(&mut self) {
        let path = PathBuf::from(self.envelope_path.trim());
        let result = (|| {
            let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
            if metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
                return Err("encrypted envelope must be between 1 byte and 8 MiB".to_owned());
            }
            let json = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            envelope_from_json_bounded(&json).map_err(|error| error.to_string())
        })();
        match result {
            Ok(envelope) => {
                self.envelope = Some(envelope);
                self.reset_verified_state();
                self.set_success("Encrypted envelope loaded. Enter its transfer passphrase to authenticate and verify it.");
            }
            Err(error) => {
                self.envelope = None;
                self.reset_verified_state();
                self.set_error(format!("Envelope was not loaded: {error}"));
            }
        }
    }

    fn parse_transport(&mut self) {
        match envelope_from_transport(&self.transport_text) {
            Ok(envelope) => {
                self.envelope = Some(envelope);
                self.reset_verified_state();
                self.set_success("Encrypted PSW1 transport parsed. Enter its passphrase to authenticate and verify it.");
            }
            Err(error) => {
                self.envelope = None;
                self.reset_verified_state();
                self.set_error(format!("Transport text was rejected: {error}"));
            }
        }
    }

    fn decrypt_and_verify(&mut self) {
        let passphrase = Zeroizing::new(std::mem::take(&mut self.passphrase));
        let result = self
            .envelope
            .as_ref()
            .ok_or_else(|| "load or parse an encrypted envelope first".to_owned())
            .and_then(|envelope| {
                decrypt_manifest(envelope, passphrase.as_str()).map_err(|error| error.to_string())
            })
            .and_then(|manifest| {
                validate_manifest(&manifest).map_err(|error| error.to_string())?;
                Ok(manifest)
            });

        self.reset_verified_state();
        match result {
            Ok(manifest) => {
                self.rpc_port = manifest.network.default_rpc_port().to_string();
                self.manifest = Some(manifest);
                self.set_success("Envelope authenticated. Transaction structure, destination, amounts, outpoints, public keys, SIGHASH_ALL signatures, and final sequences all verified.");
            }
            Err(error) => self.set_error(format!(
                "Decryption or verification stopped safely: {error}. The passphrase field was cleared."
            )),
        }
    }

    fn run_policy_check(&mut self) -> Task<Message> {
        if self.busy {
            return Task::none();
        }
        let Some(manifest) = self.manifest.clone() else {
            self.set_error("Decrypt and verify an envelope first.");
            return Task::none();
        };
        let config = match self.rpc_config() {
            Ok(config) => config,
            Err(error) => {
                self.set_error(error);
                return Task::none();
            }
        };
        self.busy = true;
        self.set_warning("Running testmempoolaccept against 127.0.0.1 only…");
        Task::perform(
            async move {
                test_mempool_accept(config, manifest)
                    .await
                    .map_err(|error| error.to_string())
            },
            Message::PolicyFinished,
        )
    }

    fn submit_privately(&mut self) -> Task<Message> {
        if self.busy {
            return Task::none();
        }
        let Some(manifest) = self.manifest.clone() else {
            self.set_error("Decrypt and verify an envelope first.");
            return Task::none();
        };
        if !self.relay_visibility_ack {
            self.set_error("Acknowledge relay/miner visibility and non-confirmation risk first.");
            return Task::none();
        }
        if self.target == RelayTarget::MaraProduction {
            if !manifest.network.is_mainnet() {
                self.set_error("MARA production submission requires a mainnet manifest.");
                return Task::none();
            }
            if self.mainnet_confirmation.trim() != MAINNET_SUBMIT_CONFIRMATION {
                self.set_error(format!("Type {MAINNET_SUBMIT_CONFIRMATION} exactly."));
                return Task::none();
            }
        }

        let target = self.target;
        let client_code = if self.client_code.trim().is_empty() {
            None
        } else {
            Some(self.client_code.trim().to_owned())
        };
        self.busy = true;
        self.receipt = None;
        self.set_warning("Submitting once to the selected private-relay preset. No fallback is enabled…");
        Task::perform(
            async move {
                submit_private_transaction(target, manifest, client_code)
                    .await
                    .map_err(|error| error.to_string())
            },
            Message::SubmissionFinished,
        )
    }

    fn check_confirmations(&mut self) -> Task<Message> {
        if self.busy {
            return Task::none();
        }
        let Some(manifest) = self.manifest.clone() else {
            self.set_error("Decrypt and verify an envelope first.");
            return Task::none();
        };
        let config = match self.rpc_config() {
            Ok(config) => config,
            Err(error) => {
                self.set_error(error);
                return Task::none();
            }
        };
        self.busy = true;
        self.set_warning("Checking destination output zero through 127.0.0.1 only…");
        Task::perform(
            async move {
                check_destination_confirmations(config, manifest)
                    .await
                    .map_err(|error| error.to_string())
            },
            Message::ConfirmationsFinished,
        )
    }

    fn rpc_config(&self) -> Result<CoreRpcConfig, String> {
        let port = self
            .rpc_port
            .parse::<u16>()
            .map_err(|_| "RPC port must be a whole number between 1 and 65535".to_owned())?;
        if port == 0 {
            return Err("RPC port must be between 1 and 65535".to_owned());
        }
        if self.cookie_path.trim().is_empty() {
            return Err("select a local Bitcoin Core .cookie file first".to_owned());
        }
        Ok(CoreRpcConfig {
            port,
            cookie_path: PathBuf::from(self.cookie_path.trim()),
        })
    }

    fn reset_verified_state(&mut self) {
        self.manifest = None;
        self.policy_result = None;
        self.confirmation_result = None;
        self.receipt = None;
        self.mainnet_confirmation.zeroize();
        self.mainnet_confirmation.clear();
    }

    fn clear_session(&mut self) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.transport_text.zeroize();
        self.transport_text.clear();
        self.envelope = None;
        self.reset_verified_state();
        self.client_code.zeroize();
        self.client_code.clear();
        self.relay_visibility_ack = false;
        self.set_success("Decrypted transaction state and sensitive session fields were cleared.");
    }

    fn set_success(&mut self, message: impl Into<String>) {
        self.status = Status {
            kind: StatusKind::Success,
            message: message.into(),
        };
    }

    fn set_warning(&mut self, message: impl Into<String>) {
        self.status = Status {
            kind: StatusKind::Warning,
            message: message.into(),
        };
    }

    fn set_error(&mut self, message: impl Into<String>) {
        self.status = Status {
            kind: StatusKind::Error,
            message: message.into(),
        };
    }
}

fn action_button<'a>(
    label: &'a str,
    message: Message,
    disabled: bool,
) -> Element<'a, Message> {
    let control = button(text(label)).padding(10);
    if disabled {
        control.into()
    } else {
        control.on_press(message).into()
    }
}

fn summary_grid(manifest: &SweepManifest) -> Element<'_, Message> {
    column![
        summary_row("Network", manifest.network.to_string()),
        summary_row(
            "Source",
            manifest
                .inputs
                .first()
                .map(|input| format!("{} ({})", input.source_address, input.pubkey_encoding))
                .unwrap_or_default(),
        ),
        summary_row("Inputs", manifest.inputs.len().to_string()),
        summary_row("Destination", manifest.destination_address.clone()),
        summary_row("Total input", format!("{} sats", grouped(manifest.total_input_sats))),
        summary_row("Destination output", format!("{} sats", grouped(manifest.output_sats))),
        summary_row("Fee", format!("{} sats", grouped(manifest.fee_sats))),
        summary_row("Actual fee rate", manifest.actual_fee_rate_display()),
        summary_row("Virtual size", format!("{} vB", manifest.actual_vsize)),
        summary_row("Transaction ID", manifest.transaction_id.clone()),
    ]
    .spacing(6)
    .into()
}

fn summary_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    row![
        text(label).size(13).width(Length::Fixed(170.0)),
        text(value).size(14).width(Length::Fill),
    ]
    .spacing(10)
    .into()
}

fn policy_text(policy: Option<&CorePolicyResult>) -> Element<'_, Message> {
    match policy {
        Some(policy) if policy.allowed => text(format!(
            "Local policy: ACCEPTED{}",
            policy
                .vsize
                .map(|vsize| format!(" · {vsize} vB"))
                .unwrap_or_default()
        ))
        .size(14)
        .into(),
        Some(policy) => text(format!(
            "Local policy: REJECTED · {}",
            policy
                .reject_reason
                .as_deref()
                .unwrap_or("no reason returned")
        ))
        .size(14)
        .into(),
        None => text("Local policy: not checked").size(14).into(),
    }
}

fn confirmation_text(confirmation: Option<&ConfirmationResult>) -> Element<'_, Message> {
    match confirmation {
        Some(value) if value.found_unspent_output => {
            text(format!("Node confirmations: {}", value.confirmations))
                .size(14)
                .into()
        }
        Some(_) => text("Node confirmations: destination output not returned")
            .size(14)
            .into(),
        None => text("Node confirmations: not checked").size(14).into(),
    }
}

fn receipt_text(receipt: Option<&RelayReceipt>) -> Element<'_, Message> {
    match receipt {
        Some(receipt) => column![
            text("RELAY ACCEPTED — NOT CONFIRMED").size(16),
            text(format!("Target: {}", receipt.target)).size(13),
            text(format!("HTTP status: {}", receipt.http_status)).size(13),
            text(format!(
                "Provider reference: {}",
                receipt.provider_reference.as_deref().unwrap_or("not returned")
            ))
            .size(13),
            text(format!("Bounded response: {}", receipt.response_preview)).size(12),
        ]
        .spacing(4)
        .into(),
        None => text("No private-relay submission receipt in this session.")
            .size(14)
            .into(),
    }
}

fn status_label(kind: StatusKind) -> &'static str {
    match kind {
        StatusKind::Neutral => "READY",
        StatusKind::Success => "VERIFIED",
        StatusKind::Warning => "NOT CONFIRMED",
        StatusKind::Error => "STOPPED SAFELY",
    }
}

fn bounded(mut value: String, maximum: usize) -> String {
    if value.len() > maximum {
        value.truncate(maximum);
    }
    value
}

fn digits_only(value: String, maximum: usize) -> String {
    bounded(
        value
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>(),
        maximum,
    )
}

fn grouped(value: u64) -> String {
    let text = value.to_string();
    let mut output = String::with_capacity(text.len() + text.len() / 3);
    for (index, character) in text.chars().enumerate() {
        if index > 0 && (text.len() - index) % 3 == 0 {
            output.push(',');
        }
        output.push(character);
    }
    output
}

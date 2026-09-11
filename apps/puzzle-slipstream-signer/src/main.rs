#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs, path::Path};

use iced::{
    clipboard,
    widget::{
        button, checkbox, column, container, horizontal_rule, pick_list, row, scrollable, text,
        text_input, Space,
    },
    Element, Length, Task, Theme,
};
use puzzle_slipstream_core::{
    envelope::{encrypt_manifest, envelope_to_pretty_json, envelope_to_transport},
    signing::build_signed_sweep,
    ChainNetwork, EncryptedSweepEnvelope, FeePolicy, SweepManifest, UtxoBundle,
};
use qrcode::QrCode;
use zeroize::{Zeroize, Zeroizing};

const MAINNET_CONFIRMATION: &str = "SWEEP MAINNET";
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn main() -> iced::Result {
    iced::application("PuzzleSlipstream Signer", SignerApp::update, SignerApp::view)
        .theme(|_| Theme::Dark)
        .run_with(|| (SignerApp::default(), Task::none()))
}

#[derive(Debug)]
struct SignerApp {
    network: ChainNetwork,
    bundle_path: String,
    bundle: Option<UtxoBundle>,
    private_key: String,
    destination: String,
    fee_rate: String,
    fee_cap: String,
    fee_bps_cap: String,
    transfer_passphrase: String,
    transfer_passphrase_confirm: String,
    authorized: bool,
    mainnet_confirmation: String,
    manifest: Option<SweepManifest>,
    envelope: Option<EncryptedSweepEnvelope>,
    transport: String,
    status: Status,
}

#[derive(Debug, Clone)]
enum Message {
    NetworkSelected(ChainNetwork),
    ChooseBundle,
    BundlePathChanged(String),
    LoadBundle,
    PrivateKeyChanged(String),
    DestinationChanged(String),
    FeeRateChanged(String),
    FeeCapChanged(String),
    FeeBpsCapChanged(String),
    PassphraseChanged(String),
    PassphraseConfirmChanged(String),
    AuthorizedChanged(bool),
    MainnetConfirmationChanged(String),
    BuildSignEncrypt,
    SaveEnvelope,
    SaveQr,
    CopyTransport,
    ClearSensitive,
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

impl Default for SignerApp {
    fn default() -> Self {
        Self {
            network: ChainNetwork::Regtest,
            bundle_path: String::new(),
            bundle: None,
            private_key: String::new(),
            destination: String::new(),
            fee_rate: "10".to_owned(),
            fee_cap: "250000".to_owned(),
            fee_bps_cap: "500".to_owned(),
            transfer_passphrase: String::new(),
            transfer_passphrase_confirm: String::new(),
            authorized: false,
            mainnet_confirmation: String::new(),
            manifest: None,
            envelope: None,
            transport: String::new(),
            status: Status {
                kind: StatusKind::Neutral,
                message: "Load a UTXO bundle to begin. No network code is present in this application."
                    .to_owned(),
            },
        }
    }
}

impl Drop for SignerApp {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.transfer_passphrase.zeroize();
        self.transfer_passphrase_confirm.zeroize();
        self.transport.zeroize();
    }
}

impl SignerApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NetworkSelected(network) => {
                self.network = network;
                self.bundle = None;
                self.manifest = None;
                self.envelope = None;
                self.transport.zeroize();
                self.transport.clear();
                self.set_warning("Network changed. Reload and revalidate the UTXO bundle.");
            }
            Message::ChooseBundle => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("PuzzleSlipstream UTXO bundle", &["json"])
                    .pick_file()
                {
                    self.bundle_path = path.display().to_string();
                    self.load_bundle();
                }
            }
            Message::BundlePathChanged(value) => self.bundle_path = value,
            Message::LoadBundle => self.load_bundle(),
            Message::PrivateKeyChanged(value) => self.private_key = bounded(value, 256),
            Message::DestinationChanged(value) => self.destination = bounded(value, 200),
            Message::FeeRateChanged(value) => self.fee_rate = digits_only(value, 12),
            Message::FeeCapChanged(value) => self.fee_cap = digits_only(value, 20),
            Message::FeeBpsCapChanged(value) => self.fee_bps_cap = digits_only(value, 5),
            Message::PassphraseChanged(value) => {
                self.transfer_passphrase = bounded(value, 1024)
            }
            Message::PassphraseConfirmChanged(value) => {
                self.transfer_passphrase_confirm = bounded(value, 1024)
            }
            Message::AuthorizedChanged(value) => self.authorized = value,
            Message::MainnetConfirmationChanged(value) => {
                self.mainnet_confirmation = bounded(value, 64)
            }
            Message::BuildSignEncrypt => self.build_sign_encrypt(),
            Message::SaveEnvelope => self.save_envelope(),
            Message::SaveQr => self.save_qr(),
            Message::CopyTransport => {
                if self.transport.is_empty() {
                    self.set_error("No encrypted transport text is available.");
                } else {
                    self.set_success(
                        "Encrypted PSW1 transport text copied. Treat it as pre-confirmation sensitive data.",
                    );
                    return clipboard::write(self.transport.clone());
                }
            }
            Message::ClearSensitive => {
                self.private_key.zeroize();
                self.private_key.clear();
                self.transfer_passphrase.zeroize();
                self.transfer_passphrase.clear();
                self.transfer_passphrase_confirm.zeroize();
                self.transfer_passphrase_confirm.clear();
                self.mainnet_confirmation.zeroize();
                self.mainnet_confirmation.clear();
                self.set_success("Sensitive input fields were cleared.");
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = column![
            text("PuzzleSlipstream Signer").size(36),
            text("Offline legacy P2PKH sweep construction · no HTTP, DNS, RPC, or broadcast code")
                .size(16),
            container(
                text("P2PKH spending reveals the public key in scriptSig. This application avoids a public broadcast path; it does not hide the transaction from the selected relay or miner.")
                    .size(14)
            )
            .padding(14)
            .width(Length::Fill)
            .style(container::bordered_box),
        ]
        .spacing(8);

        let network_options = available_networks();
        let source_card = container(
            column![
                text("1 · Source and authorization").size(24),
                text("Use complete previous transactions from your own Bitcoin Core node.").size(14),
                row![
                    column![
                        text("Network").size(13),
                        pick_list(network_options, Some(self.network), Message::NetworkSelected)
                            .width(Length::Fill),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                    column![
                        text("UTXO bundle JSON").size(13),
                        row![
                            text_input("Path to bundle.json", &self.bundle_path)
                                .on_input(Message::BundlePathChanged)
                                .padding(10)
                                .width(Length::Fill),
                            button(text("Choose…")).on_press(Message::ChooseBundle),
                            button(text("Load")).on_press(Message::LoadBundle),
                        ]
                        .spacing(8),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(3)),
                ]
                .spacing(14),
                text(bundle_description(self.bundle.as_ref())).size(14),
                text("Private key (WIF or 64 hexadecimal characters)").size(13),
                text_input("Entered only on this offline computer", &self.private_key)
                    .on_input(Message::PrivateKeyChanged)
                    .secure(true)
                    .padding(12),
                checkbox(
                    "I own or am explicitly authorized to spend every selected UTXO.",
                    self.authorized,
                )
                .on_toggle(Message::AuthorizedChanged),
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        let transaction_card = container(
            column![
                text("2 · Destination and fee guardrails").size(24),
                text("Destination address").size(13),
                text_input("Verified address controlled by you", &self.destination)
                    .on_input(Message::DestinationChanged)
                    .padding(12),
                row![
                    column![
                        text("Target fee rate (sat/vB)").size(13),
                        text_input("10", &self.fee_rate)
                            .on_input(Message::FeeRateChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                    column![
                        text("Absolute fee cap (sats)").size(13),
                        text_input("250000", &self.fee_cap)
                            .on_input(Message::FeeCapChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                    column![
                        text("Fee cap (basis points of input)").size(13),
                        text_input("500 = 5%", &self.fee_bps_cap)
                            .on_input(Message::FeeBpsCapChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                ]
                .spacing(12),
                if self.network.is_mainnet() {
                    column![
                        text(format!("Type {MAINNET_CONFIRMATION} to enable signing")).size(13),
                        text_input(MAINNET_CONFIRMATION, &self.mainnet_confirmation)
                            .on_input(Message::MainnetConfirmationChanged)
                            .padding(10),
                    ]
                    .spacing(5)
                } else {
                    column![text("Test-network mode: mainnet is not active.").size(13)]
                },
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        let transfer_card = container(
            column![
                text("3 · Encrypted offline transfer").size(24),
                text("Use a strong one-time passphrase of at least 12 UTF-8 bytes. It protects the .swe file while moving it to the Relay computer.").size(14),
                row![
                    column![
                        text("Transfer passphrase").size(13),
                        text_input("Minimum 12 bytes", &self.transfer_passphrase)
                            .on_input(Message::PassphraseChanged)
                            .secure(true)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                    column![
                        text("Confirm passphrase").size(13),
                        text_input("Repeat exactly", &self.transfer_passphrase_confirm)
                            .on_input(Message::PassphraseConfirmChanged)
                            .secure(true)
                            .padding(10),
                    ]
                    .spacing(5)
                    .width(Length::FillPortion(1)),
                ]
                .spacing(12),
                row![
                    button(text("Build, sign & verify").size(16))
                        .on_press(Message::BuildSignEncrypt)
                        .padding(12),
                    button(text("Clear sensitive fields"))
                        .on_press(Message::ClearSensitive)
                        .padding(12),
                ]
                .spacing(10),
            ]
            .spacing(12),
        )
        .padding(20)
        .width(Length::Fill)
        .style(container::rounded_box);

        let result_card: Element<'_, Message> = match &self.manifest {
            Some(manifest) => container(
                column![
                    text("4 · Signed sweep review").size(24),
                    summary_grid(manifest),
                    horizontal_rule(1),
                    text("The transaction has exactly one destination output and no change. Relay acceptance will still not mean confirmation.").size(14),
                    row![
                        button(text("Save encrypted .swe"))
                            .on_press(Message::SaveEnvelope)
                            .padding(10),
                        button(text("Save transport QR PNG"))
                            .on_press(Message::SaveQr)
                            .padding(10),
                        button(text("Copy encrypted PSW1 text"))
                            .on_press(Message::CopyTransport)
                            .padding(10),
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
                    text("4 · Signed sweep review").size(24),
                    text("No transaction has been signed in this session.").size(14),
                ]
                .spacing(10),
            )
            .padding(20)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into(),
        };

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

        scrollable(
            container(
                column![
                    header,
                    Space::with_height(8),
                    status,
                    source_card,
                    transaction_card,
                    transfer_card,
                    result_card,
                    text("Open-source alpha · not audited · authorized use only · never paste a real key into the online Relay")
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

    fn load_bundle(&mut self) {
        let path = Path::new(self.bundle_path.trim());
        let result = (|| {
            let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
            if metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
                return Err("bundle must be between 1 byte and 8 MiB".to_owned());
            }
            let json = fs::read_to_string(path).map_err(|error| error.to_string())?;
            let bundle = UtxoBundle::from_json_bounded(&json).map_err(|error| error.to_string())?;
            if bundle.network != self.network {
                return Err(format!(
                    "bundle network is {}, but the selected network is {}",
                    bundle.network, self.network
                ));
            }
            Ok(bundle)
        })();

        match result {
            Ok(bundle) => {
                let count = bundle.inputs.len();
                self.bundle = Some(bundle);
                self.manifest = None;
                self.envelope = None;
                self.transport.zeroize();
                self.transport.clear();
                self.set_success(format!(
                    "Loaded {count} previous-transaction input(s). They will be decoded and matched to the supplied key during signing."
                ));
            }
            Err(error) => {
                self.bundle = None;
                self.set_error(format!("UTXO bundle was not loaded: {error}"));
            }
        }
    }

    fn build_sign_encrypt(&mut self) {
        self.manifest = None;
        self.envelope = None;
        self.transport.zeroize();
        self.transport.clear();

        let key = Zeroizing::new(std::mem::take(&mut self.private_key));
        let passphrase = Zeroizing::new(std::mem::take(&mut self.transfer_passphrase));
        let passphrase_confirm =
            Zeroizing::new(std::mem::take(&mut self.transfer_passphrase_confirm));

        let result = (|| {
            if !self.authorized {
                return Err("authorization acknowledgement is required".to_owned());
            }
            if self.network.is_mainnet() && self.mainnet_confirmation.trim() != MAINNET_CONFIRMATION
            {
                return Err(format!("type {MAINNET_CONFIRMATION} exactly for mainnet"));
            }
            if passphrase.as_str() != passphrase_confirm.as_str() {
                return Err("transfer passphrases do not match".to_owned());
            }
            let bundle = self
                .bundle
                .as_ref()
                .ok_or_else(|| "load a valid UTXO bundle first".to_owned())?;
            let fee_policy = FeePolicy {
                target_sat_per_vbyte: parse_u64(&self.fee_rate, "target fee rate")?,
                max_absolute_fee_sats: parse_u64(&self.fee_cap, "absolute fee cap")?,
                max_fee_basis_points: parse_u16(&self.fee_bps_cap, "fee basis-point cap")?,
            };
            let manifest = build_signed_sweep(
                bundle,
                key.as_str(),
                self.destination.trim(),
                fee_policy,
            )
            .map_err(|error| error.to_string())?;
            let envelope = encrypt_manifest(&manifest, passphrase.as_str())
                .map_err(|error| error.to_string())?;
            let transport = envelope_to_transport(&envelope).map_err(|error| error.to_string())?;
            Ok((manifest, envelope, transport))
        })();

        self.mainnet_confirmation.zeroize();
        self.mainnet_confirmation.clear();

        match result {
            Ok((manifest, envelope, transport)) => {
                self.manifest = Some(manifest);
                self.envelope = Some(envelope);
                self.transport = transport;
                self.set_success("Transaction signed, independently verified, and encrypted. Private-key and passphrase fields were cleared.");
            }
            Err(error) => {
                self.set_error(format!(
                    "Signing stopped safely: {error}. Private-key and passphrase fields were cleared."
                ));
            }
        }
    }

    fn save_envelope(&mut self) {
        let Some(envelope) = self.envelope.as_ref() else {
            self.set_error("No encrypted envelope is available.");
            return;
        };
        let tx_prefix = self
            .manifest
            .as_ref()
            .map(|manifest| manifest.transaction_id.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "sweep".to_owned());
        let Some(path) = rfd::FileDialog::new()
            .add_filter("PuzzleSlipstream encrypted sweep", &["swe"])
            .set_file_name(format!("puzzleslipstream-{tx_prefix}.swe"))
            .save_file()
        else {
            self.set_warning("Save was cancelled.");
            return;
        };
        let result = envelope_to_pretty_json(envelope)
            .map_err(|error| error.to_string())
            .and_then(|json| fs::write(&path, format!("{json}\n")).map_err(|error| error.to_string()));
        match result {
            Ok(()) => self.set_success(format!(
                "Encrypted envelope saved to {}. Move only this file to the Relay computer.",
                path.display()
            )),
            Err(error) => self.set_error(format!("Envelope could not be saved: {error}")),
        }
    }

    fn save_qr(&mut self) {
        if self.transport.is_empty() {
            self.set_error("No encrypted transport text is available.");
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .add_filter("PNG image", &["png"])
            .set_file_name("puzzleslipstream-transport.png")
            .save_file()
        else {
            self.set_warning("QR export was cancelled.");
            return;
        };
        let result = (|| {
            let code = QrCode::new(self.transport.as_bytes())
                .map_err(|_| "encrypted envelope is too large for one QR code; use the .swe file".to_owned())?;
            let image = code
                .render::<image::Luma<u8>>()
                .quiet_zone(true)
                .min_dimensions(1200, 1200)
                .build();
            image.save(&path).map_err(|error| error.to_string())
        })();
        match result {
            Ok(()) => self.set_success(format!(
                "Encrypted transport QR saved to {}. It contains no private key, but remains pre-confirmation sensitive.",
                path.display()
            )),
            Err(error) => self.set_error(format!("QR could not be saved: {error}")),
        }
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

fn available_networks() -> Vec<ChainNetwork> {
    let mut networks = ChainNetwork::TEST_NETWORKS.to_vec();
    if cfg!(feature = "mainnet") {
        networks.push(ChainNetwork::Mainnet);
    }
    networks
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

fn status_label(kind: StatusKind) -> &'static str {
    match kind {
        StatusKind::Neutral => "READY",
        StatusKind::Success => "SUCCESS",
        StatusKind::Warning => "CHECK",
        StatusKind::Error => "STOPPED SAFELY",
    }
}

fn bundle_description(bundle: Option<&UtxoBundle>) -> String {
    match bundle {
        Some(bundle) => format!(
            "Bundle loaded: {} · {} input(s). Values and source scripts are intentionally not trusted until signing validation.",
            bundle.network,
            bundle.inputs.len()
        ),
        None => "No validated UTXO bundle is loaded.".to_owned(),
    }
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive whole number"))
}

fn parse_u16(value: &str, name: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{name} must be a whole number between 1 and 10,000"))
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

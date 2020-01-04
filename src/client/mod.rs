//! A simple, thread-safe, and async-friendly IRC client library.
//!
//! This API provides the ability to connect to an IRC server via the
//! [`Client`](struct.Client.html) type. The [`Client`](trait.Client.html) trait that
//! [`Client`](struct.Client.html) implements provides methods for communicating with the
//! server.
//!
//! # Examples
//!
//! Using these APIs, we can connect to a server and send a one-off message (in this case,
//! identifying with the server).
//!
//! ```no_run
//! # extern crate irc;
//! use irc::client::prelude::Client;
//!
//! # #[tokio::main]
//! # async fn main() -> irc::error::Result<()> {
//! let client = Client::new("config.toml").await?;
//! client.identify()?;
//! # Ok(())
//! # }
//! ```
//!
//! We can then use functions from [`Client`](trait.Client.html) to receive messages from the
//! server in a blocking fashion and perform any desired actions in response. The following code
//! performs a simple call-and-response when the bot's name is mentioned in a channel.
//!
//! ```no_run
//! use irc::client::prelude::*;
//! use futures::*;
//!
//! # #[tokio::main]
//! # async fn main() -> irc::error::Result<()> {
//! let mut client = Client::new("config.toml").await?;
//! let mut stream = client.stream()?;
//! client.identify()?;
//!
//! while let Some(message) = stream.next().await.transpose()? {
//!     if let Command::PRIVMSG(channel, message) = message.command {
//!         if message.contains(client.current_nickname()) {
//!             client.send_privmsg(&channel, "beep boop").unwrap();
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "ctcp")]
use chrono::prelude::*;
use futures_channel::mpsc;
use futures_util::{
    future::{FusedFuture, Future},
    ready,
    stream::{FusedStream, FuturesUnordered, Stream},
};
use futures_util::{
    sink::Sink as _,
    stream::{SplitSink, SplitStream, StreamExt as _},
};
use std::{
    collections::HashMap,
    fmt,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::RwLock;

use crate::{
    client::{
        conn::Connection,
        data::{Config, User},
    },
    error,
    proto::{
        mode::ModeType,
        CapSubCommand::{END, LS, REQ},
        Capability, ChannelMode, Command,
        Command::{
            ChannelMODE, AUTHENTICATE, CAP, INVITE, JOIN, KICK, KILL, NICK, NICKSERV, NOTICE, OPER,
            PART, PASS, PONG, PRIVMSG, QUIT, SAMODE, SANICK, TOPIC, USER,
        },
        Message, Mode, NegotiationVersion, Response,
    },
};

pub mod conn;
pub mod data;
mod mock;
pub mod prelude;
pub mod transport;

macro_rules! pub_state_base {
    () => {
    /// Changes the modes for the specified target.
    pub async fn send_mode<S, T>(&self, target: S, modes: &[Mode<T>]) -> error::Result<()>
    where
        S: fmt::Display,
        T: ModeType,
    {
        self.send(T::mode(&target.to_string(), modes)).await
    }

    /// Joins the specified channel or chanlist.
    pub async fn send_join<S>(&self, chanlist: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send(JOIN(chanlist.to_string(), None, None)).await
    }

    /// Joins the specified channel or chanlist using the specified key or keylist.
    pub async fn send_join_with_keys<S1, S2>(&self, chanlist: &str, keylist: &str) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send(JOIN(chanlist.to_string(), Some(keylist.to_string()), None)).await
    }

    /// Sends a notice to the specified target.
    pub async fn send_notice<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        let message = message.to_string();
        for line in message.split("\r\n") {
            self.send(NOTICE(target.to_string(), line.to_string())).await?
        }
        Ok(())
    }
    }
}

macro_rules! pub_sender_base {
    () => {
    /// Sends a request for a list of server capabilities for a specific IRCv3 version.
    pub async fn send_cap_ls(&self, version: NegotiationVersion) -> error::Result<()> {
        self.send(Command::CAP(
            None,
            LS,
            match version {
                NegotiationVersion::V301 => None,
                NegotiationVersion::V302 => Some("302".to_owned()),
            },
            None,
        )).await
    }

    /// Sends an IRCv3 capabilities request for the specified extensions.
    pub async fn send_cap_req(&self, extensions: &[Capability]) -> error::Result<()> {
        let append = |mut s: String, c| {
            s.push_str(c);
            s.push(' ');
            s
        };
        let mut exts = extensions
            .iter()
            .map(|c| c.as_ref())
            .fold(String::new(), append);
        let len = exts.len() - 1;
        exts.truncate(len);
        self.send(CAP(None, REQ, None, Some(exts))).await
    }

    /// Sends a SASL AUTHENTICATE message with the specified data.
    pub async fn send_sasl<S: fmt::Display>(&self, data: S) -> error::Result<()> {
        self.send(AUTHENTICATE(data.to_string())).await
    }

    /// Sends a SASL AUTHENTICATE request to use the PLAIN mechanism.
    pub async fn send_sasl_plain(&self) -> error::Result<()> {
        self.send_sasl("PLAIN").await
    }

    /// Sends a SASL AUTHENTICATE request to use the EXTERNAL mechanism.
    pub async fn send_sasl_external(&self) -> error::Result<()> {
        self.send_sasl("EXTERNAL").await
    }

    /// Sends a SASL AUTHENTICATE request to abort authentication.
    pub async fn send_sasl_abort(&self) -> error::Result<()> {
        self.send_sasl("*").await
    }

    /// Sends a PONG with the specified message.
    pub async fn send_pong<S>(&self, msg: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send(PONG(msg.to_string(), None)).await
    }

    /// Parts the specified channel or chanlist.
    pub async fn send_part<S>(&self, chanlist: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send(PART(chanlist.to_string(), None)).await
    }

    /// Attempts to oper up using the specified username and password.
    pub async fn send_oper<S1, S2>(&self, username: S1, password: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send(OPER(username.to_string(), password.to_string())).await
    }

    /// Sends a message to the specified target. If the message contains IRC newlines (`\r\n`), it
    /// will automatically be split and sent as multiple separate `PRIVMSG`s to the specified
    /// target. If you absolutely must avoid this behavior, you can do
    /// `client.send(PRIVMSG(target, message))` directly.
    pub async fn send_privmsg<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        let message = message.to_string();
        for line in message.split("\r\n") {
            self.send(PRIVMSG(target.to_string(), line.to_string())).await?
        }
        Ok(())
    }

    /// Sets the topic of a channel or requests the current one.
    /// If `topic` is an empty string, it won't be included in the message.
    pub async fn send_topic<S1, S2>(&self, channel: S1, topic: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        let topic = topic.to_string();
        self.send(TOPIC(
            channel.to_string(),
            if topic.is_empty() { None } else { Some(topic) },
        )).await
    }

    /// Kills the target with the provided message.
    pub async fn send_kill<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send(KILL(target.to_string(), message.to_string())).await
    }

    /// Kicks the listed nicknames from the listed channels with a comment.
    /// If `message` is an empty string, it won't be included in the message.
    pub async fn send_kick<S1, S2, S3>(
        &self,
        chanlist: S1,
        nicklist: S2,
        message: S3,
    ) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
        S3: fmt::Display,
    {
        let message = message.to_string();
        self.send(KICK(
            chanlist.to_string(),
            nicklist.to_string(),
            if message.is_empty() {
                None
            } else {
                Some(message)
            },
        )).await
    }

    /// Changes the mode of the target by force.
    /// If `modeparams` is an empty string, it won't be included in the message.
    pub async fn send_samode<S1, S2, S3>(&self, target: S1, mode: S2, modeparams: S3) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
        S3: fmt::Display,
    {
        let modeparams = modeparams.to_string();
        self.send(SAMODE(
            target.to_string(),
            mode.to_string(),
            if modeparams.is_empty() {
                None
            } else {
                Some(modeparams)
            },
        )).await
    }

    /// Forces a user to change from the old nickname to the new nickname.
    pub async fn send_sanick<S1, S2>(&self, old_nick: S1, new_nick: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send(SANICK(old_nick.to_string(), new_nick.to_string())).await
    }

    /// Invites a user to the specified channel.
    pub async fn send_invite<S1, S2>(&self, nick: S1, chan: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send(INVITE(nick.to_string(), chan.to_string())).await
    }

    /// Quits the server entirely with a message.
    /// This defaults to `Powered by Rust.` if none is specified.
    pub async fn send_quit<S>(&self, msg: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        let msg = msg.to_string();
        self.send(QUIT(Some(if msg.is_empty() {
            "Powered by Rust.".to_string()
        } else {
            msg
        }))).await
    }

    /// Sends a CTCP-escaped message to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_ctcp<S1, S2>(&self, target: S1, msg: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send_privmsg(target, &format!("\u{001}{}\u{001}", msg.to_string())[..]).await
    }

    /// Sends an action command to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_action<S1, S2>(&self, target: S1, msg: S2) -> error::Result<()>
    where
        S1: fmt::Display,
        S2: fmt::Display,
    {
        self.send_ctcp(target, &format!("ACTION {}", msg.to_string())[..]).await
    }

    /// Sends a finger request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_finger<S: fmt::Display>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send_ctcp(target, "FINGER").await
    }

    /// Sends a version request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_version<S>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send_ctcp(target, "VERSION").await
    }

    /// Sends a source request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_source<S>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send_ctcp(target, "SOURCE").await
    }

    /// Sends a user info request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_user_info<S>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send_ctcp(target, "USERINFO").await
    }

    /// Sends a finger request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_ctcp_ping<S>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        let time = Local::now();
        self.send_ctcp(target, &format!("PING {}", time.timestamp())[..]).await
    }

    /// Sends a time request to the specified target.
    /// This requires the CTCP feature to be enabled.
    #[cfg(feature = "ctcp")]
    pub async fn send_time<S>(&self, target: S) -> error::Result<()>
    where
        S: fmt::Display,
    {
        self.send_ctcp(target, "TIME").await
    }
    }
}

/// A stream of `Messages` received from an IRC server via an `Client`.
///
/// Interaction with this stream relies on the `futures` API, but is only expected for less
/// traditional use cases. To learn more, you can view the documentation for the
/// [`futures`](https://docs.rs/futures/) crate, or the tutorials for
/// [`tokio`](https://tokio.rs/docs/getting-started/futures/).
#[derive(Debug)]
pub struct ClientStream {
    state: Arc<ClientState>,
    stream: SplitStream<Connection>,
    stream_ended: bool,
    // In case the client stream also handles outgoing messages.
    outgoing: Option<Outgoing>,
    // Stream of messages being handled.
    handles: FuturesUnordered<Pin<Box<dyn Future<Output = error::Result<()>> + Send>>>,
}

impl ClientStream {
    /// collect stream and collect all messages available.
    pub async fn collect(mut self) -> error::Result<Vec<Message>> {
        let mut output = Vec::new();

        while let Some(message) = self.next().await {
            match message {
                Ok(message) => output.push(message),
                Err(e) => return Err(e),
            }
        }

        Ok(output)
    }
}

impl FusedStream for ClientStream {
    fn is_terminated(&self) -> bool {
        self.stream_ended && self.handles.is_empty()
    }
}

impl Stream for ClientStream {
    type Item = Result<Message, error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let mut all_pending = true;

            // NB: Processing handles blocks other progress.
            while !self.handles.is_empty() {
                if let Poll::Ready(result) = Pin::new(&mut self.handles).poll_next(cx) {
                    all_pending = false;

                    match result {
                        Some(result) => result?,
                        None => panic!("handle stream ended"),
                    }
                } else {
                    break;
                }
            }

            if let Some(outgoing) = self.outgoing.as_mut() {
                if let Poll::Ready(result) = Pin::new(outgoing).poll(cx) {
                    result?;
                    // NB: outgoing future completed for some reason.
                    self.outgoing = None;
                    all_pending = false;
                }
            }

            if !self.stream_ended {
                if let Poll::Ready(result) = Pin::new(&mut self.stream).poll_next(cx) {
                    let msg = match result {
                        Some(msg) => msg?,
                        None => {
                            self.stream_ended = true;
                            continue;
                        }
                    };

                    let state = self.state.clone();
                    let m = msg.clone();

                    self.handles.push(Box::pin(async move {
                        state.handle_message(&m).await?;
                        Ok(())
                    }));

                    cx.waker().wake_by_ref();
                    return Poll::Ready(Some(Ok(msg)));
                }
            }

            if all_pending {
                if self.stream_ended && self.handles.is_empty() {
                    return Poll::Ready(None);
                }

                return Poll::Pending;
            }
        }
    }
}

/// Thread-safe internal state for an IRC server connection.
#[derive(Debug)]
struct ClientState {
    sender: Sender,
    /// The configuration used with this connection.
    config: Config,
    /// A thread-safe map of channels to the list of users in them.
    chanlists: RwLock<HashMap<String, Vec<User>>>,
    /// A thread-safe index to track the current alternative nickname being used.
    alt_nick_index: RwLock<usize>,
    /// Default ghost sequence to send if one is required but none is configured.
    default_ghost_sequence: Vec<String>,
}

impl ClientState {
    fn new(sender: Sender, config: Config) -> ClientState {
        ClientState {
            sender,
            config,
            chanlists: RwLock::new(HashMap::new()),
            alt_nick_index: RwLock::new(0),
            default_ghost_sequence: vec![String::from("GHOST")],
        }
    }

    fn config(&self) -> &Config {
        &self.config
    }

    async fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        let msg = msg.into();
        self.handle_sent_message(&msg).await?;
        Ok(self.sender.send(msg).await?)
    }

    /// Gets the current nickname in use.
    async fn current_nickname(&self) -> &str {
        let alt_nicks = self.config().alternate_nicknames();
        let index = *self.alt_nick_index.read().await;

        match index {
            0 => self
                .config()
                .nickname()
                .expect("current_nickname should not be callable if nickname is not defined."),
            i => alt_nicks[i - 1].as_str(),
        }
    }

    /// Handles sent messages internally for basic client functionality.
    async fn handle_sent_message(&self, msg: &Message) -> error::Result<()> {
        log::trace!("[SENT] {}", msg.to_string());

        match msg.command {
            PART(ref chan, _) => {
                let _ = self.chanlists.write().await.remove(chan);
            }
            _ => (),
        }

        Ok(())
    }

    /// Handles received messages internally for basic client functionality.
    async fn handle_message(&self, msg: &Message) -> error::Result<()> {
        log::trace!("[RECV] {}", msg.to_string());
        match msg.command {
            JOIN(ref chan, _, _) => {
                self.handle_join(msg.source_nickname().unwrap_or(""), chan)
                    .await
            }
            PART(ref chan, _) => {
                self.handle_part(msg.source_nickname().unwrap_or(""), chan)
                    .await
            }
            KICK(ref chan, ref user, _) => self.handle_part(user, chan).await,
            QUIT(_) => self.handle_quit(msg.source_nickname().unwrap_or("")).await,
            NICK(ref new_nick) => {
                self.handle_nick_change(msg.source_nickname().unwrap_or(""), new_nick)
                    .await
            }
            ChannelMODE(ref chan, ref modes) => self.handle_mode(chan, modes).await,
            PRIVMSG(ref target, ref body) => {
                if body.starts_with('\u{001}') {
                    let tokens: Vec<_> = {
                        let end = if body.ends_with('\u{001}') && body.len() > 1 {
                            body.len() - 1
                        } else {
                            body.len()
                        };
                        body[1..end].split(' ').collect()
                    };
                    if target.starts_with('#') {
                        self.handle_ctcp(target, &tokens).await?
                    } else if let Some(user) = msg.source_nickname() {
                        self.handle_ctcp(user, &tokens).await?
                    }
                }
            }
            Command::Response(Response::RPL_NAMREPLY, ref args, ref suffix) => {
                self.handle_namreply(args, suffix).await
            }
            Command::Response(Response::RPL_ENDOFMOTD, _, _)
            | Command::Response(Response::ERR_NOMOTD, _, _) => {
                self.send_nick_password().await?;
                self.send_umodes().await?;

                let config_chans = self.config().channels();
                for chan in config_chans {
                    match self.config().channel_key(chan) {
                        Some(key) => self.send_join_with_keys::<&str, &str>(chan, key).await?,
                        None => self.send_join(chan).await?,
                    }
                }
                let joined_chans = self.chanlists.read().await;
                for chan in joined_chans
                    .keys()
                    .filter(|x| config_chans.iter().find(|c| c == x).is_none())
                {
                    self.send_join(chan).await?
                }
            }
            Command::Response(Response::ERR_NICKNAMEINUSE, _, _)
            | Command::Response(Response::ERR_ERRONEOUSNICKNAME, _, _) => {
                let alt_nicks = self.config().alternate_nicknames();
                let mut index = self.alt_nick_index.write().await;

                if *index >= alt_nicks.len() {
                    return Err(error::Error::NoUsableNick);
                } else {
                    self.send(NICK(alt_nicks[*index].to_owned())).await?;
                    *index += 1;
                }
            }
            _ => (),
        }
        Ok(())
    }

    async fn send_nick_password(&self) -> error::Result<()> {
        if self.config().nick_password().is_empty() {
            return Ok(());
        }

        let mut index = self.alt_nick_index.write().await;

        if self.config().should_ghost() && *index != 0 {
            let seq = match self.config().ghost_sequence() {
                Some(seq) => seq,
                None => &*self.default_ghost_sequence,
            };

            for s in seq {
                let nickserv = format!(
                    "{} {} {}",
                    s,
                    self.config().nickname()?,
                    self.config().nick_password()
                );
                self.send(NICKSERV(nickserv)).await?;
            }
            *index = 0;
            self.send(NICK(self.config().nickname()?.to_owned()))
                .await?
        }

        let nickserv = format!("IDENTIFY {}", self.config().nick_password());
        self.send(NICKSERV(nickserv)).await
    }

    async fn send_umodes(&self) -> error::Result<()> {
        if self.config().umodes().is_empty() {
            return Ok(());
        }

        let nick = self.current_nickname().await;

        self.send_mode(
            &nick,
            &Mode::as_user_modes(self.config().umodes()).map_err(|e| {
                error::Error::InvalidMessage {
                    string: format!("MODE {} {}", nick, self.config().umodes()),
                    cause: e,
                }
            })?,
        )
        .await
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_join(&self, _: &str, _: &str) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_join(&self, src: &str, chan: &str) {
        if let Some(vec) = self.chanlists.write().await.get_mut(&chan.to_owned()) {
            if !src.is_empty() {
                vec.push(User::new(src))
            }
        }
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_part(&self, _: &str, _: &str) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_part(&self, src: &str, chan: &str) {
        if let Some(vec) = self.chanlists.write().await.get_mut(&chan.to_owned()) {
            if !src.is_empty() {
                if let Some(n) = vec.iter().position(|x| x.get_nickname() == src) {
                    vec.swap_remove(n);
                }
            }
        }
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_quit(&self, _: &str) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_quit(&self, src: &str) {
        if src.is_empty() {
            return;
        }

        for vec in self.chanlists.write().await.values_mut() {
            if let Some(p) = vec.iter().position(|x| x.get_nickname() == src) {
                vec.swap_remove(p);
            }
        }
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_nick_change(&self, _: &str, _: &str) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_nick_change(&self, old_nick: &str, new_nick: &str) {
        if old_nick.is_empty() || new_nick.is_empty() {
            return;
        }

        for (_, vec) in self.chanlists.write().await.iter_mut() {
            if let Some(n) = vec.iter().position(|x| x.get_nickname() == old_nick) {
                let new_entry = User::new(new_nick);
                vec[n] = new_entry;
            }
        }
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_mode(&self, _: &str, _: &[Mode<ChannelMode>]) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_mode(&self, chan: &str, modes: &[Mode<ChannelMode>]) {
        for mode in modes {
            match *mode {
                Mode::Plus(_, Some(ref user)) | Mode::Minus(_, Some(ref user)) => {
                    if let Some(vec) = self.chanlists.write().await.get_mut(chan) {
                        if let Some(n) = vec.iter().position(|x| x.get_nickname() == user) {
                            vec[n].update_access_level(mode)
                        }
                    }
                }
                _ => (),
            }
        }
    }

    #[cfg(feature = "nochanlists")]
    async fn handle_namreply(&self, _: &[String], _: &Option<String>) {}

    #[cfg(not(feature = "nochanlists"))]
    async fn handle_namreply(&self, args: &[String], suffix: &Option<String>) {
        let mut chanlists = self.chanlists.write().await;

        if let Some(ref users) = *suffix {
            if args.len() == 3 {
                let chan = &args[2];
                for user in users.split(' ') {
                    chanlists
                        .entry(chan.clone())
                        .or_insert_with(Vec::new)
                        .push(User::new(user))
                }
            }
        }
    }

    #[cfg(feature = "ctcp")]
    async fn handle_ctcp(&self, resp: &str, tokens: &[&str]) -> error::Result<()> {
        if tokens.is_empty() {
            return Ok(());
        }
        if tokens[0].eq_ignore_ascii_case("FINGER") {
            let ctcp = format!(
                "FINGER :{} ({})",
                self.config().real_name(),
                self.config().username()
            );
            self.send_ctcp_internal(resp, &ctcp).await
        } else if tokens[0].eq_ignore_ascii_case("VERSION") {
            let ctcp = format!("VERSION {}", self.config().version());
            self.send_ctcp_internal(resp, &ctcp).await
        } else if tokens[0].eq_ignore_ascii_case("SOURCE") {
            let ctcp = format!("SOURCE {}", self.config().source());
            self.send_ctcp_internal(resp, &ctcp).await
        } else if tokens[0].eq_ignore_ascii_case("PING") && tokens.len() > 1 {
            let ctcp = format!("PING {}", tokens[1]);
            self.send_ctcp_internal(resp, &ctcp).await
        } else if tokens[0].eq_ignore_ascii_case("TIME") {
            let ctcp = format!("TIME :{}", Local::now().to_rfc2822());
            self.send_ctcp_internal(resp, &ctcp).await
        } else if tokens[0].eq_ignore_ascii_case("USERINFO") {
            let ctcp = format!("USERINFO :{}", self.config().user_info());
            self.send_ctcp_internal(resp, &ctcp).await
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "ctcp")]
    async fn send_ctcp_internal(&self, target: &str, msg: &str) -> error::Result<()> {
        let notice = format!("\u{001}{}\u{001}", msg);
        self.send_notice(target, &notice).await
    }

    #[cfg(not(feature = "ctcp"))]
    fn handle_ctcp(&self, _: &str, _: &[&str]) -> error::Result<()> {
        Ok(())
    }

    pub_state_base!();
}

/// Thread-safe sender that can be used with the client.
#[derive(Debug, Clone)]
pub struct Sender {
    tx_outgoing: mpsc::Sender<Message>,
}

impl Sender {
    /// Send a single message to the unbounded queue.
    pub async fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        use futures_util::sink::SinkExt as _;
        Ok(self.tx_outgoing.clone().send(msg.into()).await?)
    }

    pub_state_base!();
    pub_sender_base!();
}

/// Future to handle outgoing messages.
///
/// Note: this is essentially the same as a version of [SendAll](https://github.com/rust-lang-nursery/futures-rs/blob/master/futures-util/src/sink/send_all.rs) that owns it's sink and stream.
#[derive(Debug)]
pub struct Outgoing {
    sink: SplitSink<Connection, Message>,
    stream: mpsc::Receiver<Message>,
    buffered: Option<Message>,
}

impl Outgoing {
    fn try_start_send(
        &mut self,
        cx: &mut Context<'_>,
        message: Message,
    ) -> Poll<Result<(), error::Error>> {
        debug_assert!(self.buffered.is_none());

        match Pin::new(&mut self.sink).poll_ready(cx)? {
            Poll::Ready(()) => Poll::Ready(Pin::new(&mut self.sink).start_send(message)),
            Poll::Pending => {
                self.buffered = Some(message);
                Poll::Pending
            }
        }
    }
}

impl FusedFuture for Outgoing {
    fn is_terminated(&self) -> bool {
        // NB: outgoing stream never terminates.
        // TODO: should it terminate if rx_outgoing is terminated?
        false
    }
}

impl Future for Outgoing {
    type Output = error::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if let Some(message) = this.buffered.take() {
            ready!(this.try_start_send(cx, message))?
        }

        loop {
            match this.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(message)) => ready!(this.try_start_send(cx, message))?,
                Poll::Ready(None) => {
                    ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
                    return Poll::Pending;
                }
            }
        }
    }
}

/// The canonical implementation of a connection to an IRC server.
///
/// For a full example usage, see [`irc::client`](./index.html).
#[derive(Debug)]
pub struct Client {
    /// The internal, thread-safe server state.
    state: Arc<ClientState>,
    incoming: Option<SplitStream<Connection>>,
    outgoing: Option<Outgoing>,
    sender: Sender,
    #[cfg(test)]
    /// A view of the logs for a mock connection.
    view: Option<self::transport::LogView>,
}

impl Client {
    /// Creates a new `Client` from the configuration at the specified path, connecting
    /// immediately. This function is short-hand for loading the configuration and then calling
    /// `Client::from_config` and consequently inherits its behaviors.
    ///
    /// # Example
    /// ```no_run
    /// # use irc::client::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> irc::error::Result<()> {
    /// let client = Client::new("config.toml").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new<P: AsRef<Path>>(config: P) -> error::Result<Client> {
        Client::from_config(Config::load(config)?).await
    }

    /// Creates a `Future` of an `Client` from the specified configuration and on the event loop
    /// corresponding to the given handle. This can be used to set up a number of `Clients` on a
    /// single, shared event loop. It can also be used to take more control over execution and error
    /// handling. Connection will not occur until the event loop is run.
    pub async fn from_config(config: Config) -> error::Result<Client> {
        let (tx_outgoing, rx_outgoing) = mpsc::channel(1);
        let conn = Connection::new(&config, tx_outgoing.clone()).await?;

        #[cfg(test)]
        let view = conn.log_view();

        let (sink, incoming) = conn.split();

        let sender = Sender { tx_outgoing };

        Ok(Client {
            sender: sender.clone(),
            state: Arc::new(ClientState::new(sender, config)),
            incoming: Some(incoming),
            outgoing: Some(Outgoing {
                sink,
                stream: rx_outgoing,
                buffered: None,
            }),
            #[cfg(test)]
            view,
        })
    }

    /// Gets the log view from the internal transport. Only used for unit testing.
    #[cfg(test)]
    fn log_view(&self) -> &self::transport::LogView {
        self.view
            .as_ref()
            .expect("there should be a log during testing")
    }

    /// Take the outgoing future in order to drive it yourself.
    ///
    /// Must be called before `stream` if you intend to drive this future
    /// yourself.
    pub fn outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.take()
    }

    /// Get access to a thread-safe sender that can be used with the client.
    pub fn sender(&self) -> Sender {
        self.sender.clone()
    }

    /// Gets the configuration being used with this `Client`.
    fn config(&self) -> &Config {
        &self.state.config
    }

    /// Gets a stream of incoming messages from the `Client`'s connection. This is only necessary
    /// when trying to set up more complex clients, and requires use of the `futures` crate. Most
    /// IRC bots should be able to get by using only `for_each_incoming` to handle received
    /// messages. You can find some examples of more complex setups using `stream` in the
    /// [GitHub repository](https://github.com/aatxe/irc/tree/stable/examples).
    ///
    /// **Note**: The stream can only be returned once. Subsequent attempts will cause a panic.
    // FIXME: when impl traits stabilize, we should change this return type.
    pub fn stream(&mut self) -> error::Result<ClientStream> {
        let stream = self
            .incoming
            .take()
            .ok_or_else(|| error::Error::StreamAlreadyConfigured)?;

        Ok(ClientStream {
            state: Arc::clone(&self.state),
            stream,
            stream_ended: false,
            outgoing: self.outgoing.take(),
            handles: FuturesUnordered::new(),
        })
    }

    /// Gets a list of currently joined channels. This will be `None` if tracking is disabled
    /// altogether via the `nochanlists` feature.
    #[cfg(not(feature = "nochanlists"))]
    pub async fn list_channels(&self) -> Option<Vec<String>> {
        Some(
            self.state
                .chanlists
                .read()
                .await
                .keys()
                .map(|k| k.to_owned())
                .collect(),
        )
    }

    #[cfg(feature = "nochanlists")]
    pub async fn list_channels(&self) -> Option<Vec<String>> {
        None
    }

    /// Gets a list of [`Users`](./data/user/struct.User.html) in the specified channel. If the
    /// specified channel hasn't been joined or the `nochanlists` feature is enabled, this function
    /// will return `None`.
    ///
    /// For best results, be sure to request `multi-prefix` support from the server. This will allow
    /// for more accurate tracking of user rank (e.g. oper, half-op, etc.).
    /// # Requesting multi-prefix support
    /// ```no_run
    /// # use irc::client::prelude::*;
    /// use irc::proto::caps::Capability;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> irc::error::Result<()> {
    /// # let client = Client::new("config.toml").await?;
    /// client.send_cap_req(&[Capability::MultiPrefix])?;
    /// client.identify()?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(not(feature = "nochanlists"))]
    pub async fn list_users(&self, chan: &str) -> Option<Vec<User>> {
        self.state
            .chanlists
            .read()
            .await
            .get(&chan.to_owned())
            .cloned()
    }

    #[cfg(feature = "nochanlists")]
    pub async fn list_users(&self, _: &str) -> Option<Vec<User>> {
        None
    }

    /// Gets the current nickname in use. This may be the primary username set in the configuration,
    /// or it could be any of the alternative nicknames listed as well. As a result, this is the
    /// preferred way to refer to the client's nickname.
    pub async fn current_nickname(&self) -> &str {
        self.state.current_nickname().await
    }

    /// Sends a [`Command`](../proto/command/enum.Command.html) as this `Client`. This is the
    /// core primitive for sending messages to the server.
    ///
    /// # Example
    /// ```no_run
    /// # use irc::client::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let client = Client::new("config.toml").await.unwrap();
    /// client.send(Command::NICK("example".to_owned())).unwrap();
    /// client.send(Command::USER("user".to_owned(), "0".to_owned(), "name".to_owned())).unwrap();
    /// # }
    /// ```
    pub async fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        self.state.send(msg).await
    }

    /// Sends a CAP END, NICK and USER to identify.
    pub async fn identify(&self) -> error::Result<()> {
        // Send a CAP END to signify that we're IRCv3-compliant (and to end negotiations!).
        self.send(CAP(None, END, None, None)).await?;
        if self.config().password() != "" {
            self.send(PASS(self.config().password().to_owned())).await?;
        }
        self.send(NICK(self.config().nickname()?.to_owned()))
            .await?;
        self.send(USER(
            self.config().username().to_owned(),
            "0".to_owned(),
            self.config().real_name().to_owned(),
        ))
        .await?;
        Ok(())
    }

    pub_state_base!();
    pub_sender_base!();
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, default::Default, thread, time::Duration};

    use super::Client;
    #[cfg(not(feature = "nochanlists"))]
    use crate::client::data::User;
    use crate::{
        client::data::Config,
        error::Error,
        proto::{
            command::Command::{Raw, PRIVMSG},
            ChannelMode, IrcCodec, Mode,
        },
    };
    use anyhow::Result;
    use futures::prelude::*;

    pub fn test_config() -> Config {
        Config {
            owners: vec![format!("test")],
            nickname: Some(format!("test")),
            alt_nicks: vec![format!("test2")],
            server: Some(format!("irc.test.net")),
            channels: vec![format!("#test"), format!("#test2")],
            user_info: Some(format!("Testing.")),
            use_mock_connection: true,
            ..Default::default()
        }
    }

    pub fn get_client_value(client: Client) -> String {
        // We sleep here because of synchronization issues.
        // We can't guarantee that everything will have been sent by the time of this call.
        thread::sleep(Duration::from_millis(100));
        client
            .log_view()
            .sent()
            .unwrap()
            .iter()
            .fold(String::new(), |mut acc, msg| {
                // NOTE: we have to sanitize here because sanitization happens in IrcCodec after the
                // messages are converted into strings, but our transport logger catches messages before
                // they ever reach that point.
                acc.push_str(&IrcCodec::sanitize(msg.to_string()));
                acc
            })
    }

    #[tokio::test]
    async fn stream() -> Result<()> {
        let exp = "PRIVMSG test :Hi!\r\nPRIVMSG test :This is a test!\r\n\
                   :test!test@test JOIN #test\r\n";

        let mut client = Client::from_config(Config {
            mock_initial_value: Some(exp.to_owned()),
            ..test_config()
        })
        .await?;

        client.stream()?.collect().await?;
        // assert_eq!(&messages[..], exp);
        Ok(())
    }

    #[tokio::test]
    async fn handle_message() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "JOIN #test\r\nJOIN #test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_nick_password() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nick_password: Some(format!("password")),
            channels: vec![format!("#test"), format!("#test2")],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NICKSERV IDENTIFY password\r\nJOIN #test\r\n\
             JOIN #test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_chan_keys() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some(format!("test")),
            channels: vec![format!("#test"), format!("#test2")],
            channel_keys: {
                let mut map = HashMap::new();
                map.insert(format!("#test2"), format!("password"));
                map
            },
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "JOIN #test\r\nJOIN #test2 password\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_ghost() -> Result<()> {
        let value = ":irc.pdgn.co 433 * test :Nickname is already in use.\r\n\
                     :irc.test.net 376 test2 :End of /MOTD command.\r\n";

        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some(format!("test")),
            alt_nicks: vec![format!("test2")],
            nick_password: Some(format!("password")),
            channels: vec![format!("#test"), format!("#test2")],
            should_ghost: true,
            ..test_config()
        })
        .await?;

        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NICK :test2\r\nNICKSERV GHOST test password\r\n\
             NICK :test\r\nNICKSERV IDENTIFY password\r\nJOIN #test\r\nJOIN #test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_ghost_seq() -> Result<()> {
        let value = ":irc.pdgn.co 433 * test :Nickname is already in use.\r\n\
                     :irc.test.net 376 test2 :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some(format!("test")),
            alt_nicks: vec![format!("test2")],
            nick_password: Some(format!("password")),
            channels: vec![format!("#test"), format!("#test2")],
            should_ghost: true,
            ghost_sequence: Some(vec![format!("RECOVER"), format!("RELEASE")]),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NICK :test2\r\nNICKSERV RECOVER test password\
             \r\nNICKSERV RELEASE test password\r\nNICK :test\r\nNICKSERV IDENTIFY password\
             \r\nJOIN #test\r\nJOIN #test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_umodes() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some(format!("test")),
            umodes: Some(format!("+B")),
            channels: vec![format!("#test"), format!("#test2")],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "MODE test +B\r\nJOIN #test\r\nJOIN #test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn nickname_in_use() -> Result<()> {
        let value = ":irc.pdgn.co 433 * test :Nickname is already in use.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "NICK :test2\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn ran_out_of_nicknames() -> Result<()> {
        let value = ":irc.pdgn.co 433 * test :Nickname is already in use.\r\n\
                     :irc.pdgn.co 433 * test2 :Nickname is already in use.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        let res = client.stream()?.try_collect::<Vec<_>>().await;
        if let Err(Error::NoUsableNick) = res {
            ()
        } else {
            panic!("expected error when no valid nicks were specified")
        }
        Ok(())
    }

    #[tokio::test]
    async fn send() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(PRIVMSG(format!("#test"), format!("Hi there!")))
            .await
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG #test :Hi there!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_no_newline_injection() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(PRIVMSG(format!("#test"), format!("Hi there!\r\nJOIN #bad")))
            .await
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG #test :Hi there!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_raw_is_really_raw() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(Raw("PASS".to_owned(), vec!["password".to_owned()], None))
            .await
            .is_ok());
        assert!(client
            .send(Raw("NICK".to_owned(), vec!["test".to_owned()], None))
            .await
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PASS password\r\nNICK test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn channel_tracking_names() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_channels().await.unwrap(),
            vec!["#test".to_owned()]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn channel_tracking_names_part() -> Result<()> {
        use crate::proto::command::Command::PART;

        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;

        client.stream()?.collect().await?;

        assert_eq!(client.list_channels().await, Some(vec!["#test".to_owned()]));
        // we ignore the result, as soon as we queue an outgoing message we
        // update client state, regardless if the queue is available or not.
        let _ = client.send(PART(format!("#test"), None)).await;
        assert_eq!(client.list_channels().await, Some(vec![]));
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn user_tracking_names() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").await.unwrap(),
            vec![User::new("test"), User::new("~owner"), User::new("&admin")]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn user_tracking_names_join() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :test2!test@test JOIN #test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").await.unwrap(),
            vec![
                User::new("test"),
                User::new("~owner"),
                User::new("&admin"),
                User::new("test2"),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn user_tracking_names_kick() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :owner!test@test KICK #test test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").await.unwrap(),
            vec![User::new("&admin"), User::new("~owner"),]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn user_tracking_names_part() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :owner!test@test PART #test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").await.unwrap(),
            vec![User::new("test"), User::new("&admin")]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "nochanlists"))]
    async fn user_tracking_names_mode() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :+test ~owner &admin\r\n\
                     :test!test@test MODE #test +o test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").await.unwrap(),
            vec![User::new("@test"), User::new("~owner"), User::new("&admin")]
        );
        let mut exp = User::new("@test");
        exp.update_access_level(&Mode::Plus(ChannelMode::Voice, None));
        assert_eq!(
            client.list_users("#test").await.unwrap()[0].highest_access_level(),
            exp.highest_access_level()
        );
        // The following tests if the maintained user contains the same entries as what is expected
        // but ignores the ordering of these entries.
        let mut levels = client.list_users("#test").await.unwrap()[0].access_levels();
        levels.retain(|l| exp.access_levels().contains(l));
        assert_eq!(levels.len(), exp.access_levels().len());
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "nochanlists")]
    async fn no_user_tracking() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert!(client.list_users("#test").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn handle_single_soh() -> Result<()> {
        let value = ":test!test@test PRIVMSG #test :\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some(format!("test")),
            channels: vec![format!("#test"), format!("#test2")],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn finger_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}FINGER\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NOTICE test :\u{001}FINGER :test (test)\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn version_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}VERSION\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            &format!(
                "NOTICE test :\u{001}VERSION {}\u{001}\r\n",
                crate::VERSION_STR,
            )
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn source_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}SOURCE\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NOTICE test :\u{001}SOURCE https://github.com/aatxe/irc\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn ctcp_ping_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}PING test\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NOTICE test :\u{001}PING test\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn time_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}TIME\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        let val = get_client_value(client);
        assert!(val.starts_with("NOTICE test :\u{001}TIME :"));
        assert!(val.ends_with("\u{001}\r\n"));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn user_info_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}USERINFO\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NOTICE test :\u{001}USERINFO :Testing.\u{001}\
             \r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn ctcp_ping_no_timestamp() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}PING\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "");
        Ok(())
    }

    #[tokio::test]
    async fn identify() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.identify().await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "CAP END\r\nNICK :test\r\n\
             USER test 0 * :test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn identify_with_password() -> Result<()> {
        let mut client = Client::from_config(Config {
            nickname: Some(format!("test")),
            password: Some(format!("password")),
            ..test_config()
        })
        .await?;

        // TODO: add helpers to separately drive the outgoing stream.
        let mut stream = client.stream()?;

        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                println!("MESSAGE: {}", message.unwrap());
            }
        });

        client.identify().await?;

        assert_eq!(
            &get_client_value(client)[..],
            "CAP END\r\nPASS :password\r\nNICK :test\r\n\
             USER test 0 * :test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_pong() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_pong("irc.test.net").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "PONG :irc.test.net\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_join() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_join("#test,#test2,#test3").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "JOIN #test,#test2,#test3\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_part() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_part("#test").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "PART #test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_oper() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_oper("test", "test").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "OPER test :test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_privmsg() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_privmsg("#test", "Hi, everybody!").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG #test :Hi, everybody!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_notice() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_notice("#test", "Hi, everybody!").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "NOTICE #test :Hi, everybody!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_topic_no_topic() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_topic("#test", "").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "TOPIC #test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_topic() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_topic("#test", "Testing stuff.").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "TOPIC #test :Testing stuff.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_kill() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kill("test", "Testing kills.").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "KILL test :Testing kills.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_kick_no_message() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kick("#test", "test", "").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "KICK #test test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_kick() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kick("#test", "test", "Testing kicks.").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "KICK #test test :Testing kicks.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_mode_no_modeparams() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client
            .send_mode("#test", &[Mode::Plus(ChannelMode::InviteOnly, None)])
            .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "MODE #test +i\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_mode() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client
            .send_mode(
                "#test",
                &[Mode::Plus(ChannelMode::Oper, Some("test".to_owned()))],
            )
            .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "MODE #test +o test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_samode_no_modeparams() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_samode("#test", "+i", "").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "SAMODE #test +i\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_samode() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_samode("#test", "+o", "test").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "SAMODE #test +o test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_sanick() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_sanick("test", "test2").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "SANICK test test2\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_invite() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_invite("test", "#test").await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client)[..], "INVITE test #test\r\n");
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_ctcp() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_ctcp("test", "MESSAGE").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}MESSAGE\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_action() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_action("test", "tests.").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}ACTION tests.\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_finger() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_finger("test").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}FINGER\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_version() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_version("test").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}VERSION\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_source() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_source("test").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}SOURCE\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_user_info() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_user_info("test").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}USERINFO\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_ctcp_ping() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_ctcp_ping("test").await?;
        client.stream()?.collect().await?;
        let val = get_client_value(client);
        println!("{}", val);
        assert!(val.starts_with("PRIVMSG test :\u{001}PING "));
        assert!(val.ends_with("\u{001}\r\n"));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_time() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_time("test").await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client)[..],
            "PRIVMSG test :\u{001}TIME\u{001}\r\n"
        );
        Ok(())
    }
}

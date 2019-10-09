//! An IRC transport that wraps an IRC-framed stream to provide a number of features including
//! automatic PING replies, automatic sending of PINGs, and message rate-limiting. This can be used
//! as the basis for implementing a more full IRC client.
use std::{
    pin::Pin,
    sync::{Arc, RwLock, RwLockReadGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use chrono::prelude::*;
use futures_channel::mpsc::UnboundedSender;
use futures_util::{future::Future, ready, sink::Sink, stream::Stream};
use tokio::{
    codec::Framed,
    io::{AsyncRead, AsyncWrite},
    timer::{self, Delay, Interval},
};

use crate::{
    client::data::Config,
    error,
    proto::{Command, IrcCodec, Message},
};

/// Pinger-based futures helper.
struct Pinger {
    tx: UnboundedSender<Message>,
    /// The amount of time to wait before timing out from no ping response.
    ping_timeout: Duration,
    /// The instant that the last ping was sent to the server.
    ping_deadline: Option<Delay>,
    /// The interval at which to send pings.
    ping_interval: Interval,
}

impl Pinger {
    /// Construct a new pinger helper.
    pub fn new(tx: UnboundedSender<Message>, config: &Config) -> Pinger {
        let ping_timeout = Duration::from_secs(u64::from(config.ping_timeout()));

        Self {
            tx,
            ping_timeout,
            ping_deadline: None,
            ping_interval: Interval::new_interval(ping_timeout / 2),
        }
    }

    /// Handle an incoming message.
    fn handle_message(&mut self, message: &Message) -> error::Result<()> {
        match message.command {
            // On receiving a `PING` message from the server, we automatically respond with
            // the appropriate `PONG` message to keep the connection alive for transport.
            Command::PING(ref data, _) => {
                self.send_pong(data)?;
            }
            // Check `PONG` responses from the server. If it matches, we will update the
            // last instant that the pong was received. This will prevent timeout.
            Command::PONG(_, None) | Command::PONG(_, Some(_)) => {
                log::trace!("Received PONG");
                self.ping_deadline.take();
            }
            _ => (),
        }

        Ok(())
    }

    /// Send a pong.
    fn send_pong(&mut self, data: &str) -> error::Result<()> {
        self.tx
            .unbounded_send(Command::PONG(data.to_owned(), None).into())?;
        Ok(())
    }

    /// Sends a ping via the transport.
    fn send_ping(&mut self) -> error::Result<()> {
        log::trace!("Sending PING");

        // Creates new ping data using the local timestamp.
        let data = format!("{}", Local::now().timestamp());

        self.tx
            .unbounded_send(Command::PING(data.clone(), None).into())?;

        Ok(())
    }

    /// Set the ping deadline.
    fn set_deadline(&mut self) {
        if self.ping_deadline.is_none() {
            let ping_deadline = timer::delay(Instant::now() + self.ping_timeout);
            self.ping_deadline = Some(ping_deadline);
        }
    }
}

impl Future for Pinger {
    type Output = Result<(), error::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(ping_deadline) = self.as_mut().ping_deadline.as_mut() {
            match Pin::new(ping_deadline).poll(cx) {
                Poll::Ready(()) => return Poll::Ready(Err(error::Error::PingTimeout)),
                Poll::Pending => (),
            }
        }

        if let Poll::Ready(_) = Pin::new(&mut self.as_mut().ping_interval).poll_next(cx) {
            self.as_mut().send_ping()?;
            self.as_mut().set_deadline();
        }

        Poll::Pending
    }
}

/// An IRC transport that handles core functionality for the IRC protocol. This is used in the
/// implementation of `Connection` and ultimately `IrcServer`, and plays an important role in
/// handling connection timeouts, message throttling, and ping response.
pub struct Transport<T> {
    /// The inner connection framed with an `IrcCodec`.
    inner: Framed<T, IrcCodec>,
    /// Helper for handle pinging.
    pinger: Option<Pinger>,
}

impl<T> Unpin for Transport<T> where T: Unpin {}

impl<T> Transport<T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    /// Creates a new `Transport` from the given IRC stream.
    pub fn new(
        config: &Config,
        inner: Framed<T, IrcCodec>,
        tx: UnboundedSender<Message>,
    ) -> Transport<T> {
        let pinger = Some(Pinger::new(tx, config));

        Transport { inner, pinger }
    }

    /// Gets the inner stream underlying the `Transport`.
    pub fn into_inner(self) -> Framed<T, IrcCodec> {
        self.inner
    }
}

impl<T> Stream for Transport<T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    type Item = Result<Message, error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(pinger) = self.as_mut().pinger.as_mut() {
            match Pin::new(pinger).poll(cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => (),
            }
        }

        let result = ready!(Pin::new(&mut self.as_mut().inner).poll_next(cx));

        let message = match result {
            None => return Poll::Ready(None),
            Some(message) => message?,
        };

        if let Some(pinger) = self.as_mut().pinger.as_mut() {
            pinger.handle_message(&message)?;
        }

        Poll::Ready(Some(Ok(message)))
    }
}

impl<T> Sink<Message> for Transport<T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    type Error = error::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.as_mut().inner).poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        log::trace!("[SEND] {}", item);
        Pin::new(&mut self.as_mut().inner).start_send(item)?;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.as_mut().inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.as_mut().inner).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

/// A view of the logs from a particular `Logged` transport.
#[derive(Clone, Debug)]
pub struct LogView {
    sent: Arc<RwLock<Vec<Message>>>,
    received: Arc<RwLock<Vec<Message>>>,
}

impl LogView {
    /// Gets a read guard for all the messages sent on the transport.
    pub fn sent(&self) -> error::Result<RwLockReadGuard<Vec<Message>>> {
        self.sent.read().map_err(|_| error::Error::PoisonedLog)
    }

    /// Gets a read guard for all the messages received on the transport.
    pub fn received(&self) -> error::Result<RwLockReadGuard<Vec<Message>>> {
        self.received.read().map_err(|_| error::Error::PoisonedLog)
    }
}

/// A logged version of the `Transport` that records all sent and received messages.
/// Note: this will introduce some performance overhead by cloning all messages.
pub struct Logged<T> {
    inner: Transport<T>,
    view: LogView,
}

impl<T> Unpin for Logged<T> where T: Unpin {}

impl<T> Logged<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// Wraps the given `Transport` in logging.
    pub fn wrap(inner: Transport<T>) -> Logged<T> {
        Logged {
            inner,
            view: LogView {
                sent: Arc::new(RwLock::new(vec![])),
                received: Arc::new(RwLock::new(vec![])),
            },
        }
    }

    /// Gets a view of the logging for this transport.
    pub fn view(&self) -> LogView {
        self.view.clone()
    }
}

impl<T> Stream for Logged<T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    type Item = Result<Message, error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.as_mut().inner).poll_next(cx)) {
            Some(msg) => {
                let msg = msg?;

                self.view
                    .received
                    .write()
                    .map_err(|_| error::Error::PoisonedLog)?
                    .push(msg.clone());

                Poll::Ready(Some(Ok(msg)))
            }
            None => Poll::Ready(None),
        }
    }
}

impl<T> Sink<Message> for Logged<T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    type Error = error::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_ready(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_close(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.as_mut().inner).start_send(item.clone())?;

        self.view
            .sent
            .write()
            .map_err(|_| error::Error::PoisonedLog)?
            .push(item);

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_flush(cx)
    }
}

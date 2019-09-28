extern crate irc;

use futures::prelude::*;
use irc::{client::prelude::*, error};

#[tokio::main]
async fn main() -> irc::error::Result<()> {
    env_logger::init();

    let cfg1 = Config {
        nickname: Some("pickles".to_owned()),
        server: Some("irc.mozilla.org".to_owned()),
        channels: Some(vec!["#rust-spam".to_owned()]),
        ..Default::default()
    };

    let cfg2 = Config {
        nickname: Some("bananas".to_owned()),
        server: Some("irc.mozilla.org".to_owned()),
        channels: Some(vec!["#rust-spam".to_owned()]),
        ..Default::default()
    };

    let configs = vec![cfg1, cfg2];
    let mut senders = Vec::new();
    let mut streams = Vec::new();

    for config in configs {
        // Immediate errors like failure to resolve the server's domain or to establish any connection will
        // manifest here in the result of prepare_client_and_connect.
        let mut client = Client::from_config(config).await?;
        client.identify()?;

        senders.push(client.sender());
        streams.push(client.stream()?);
    }

    loop {
        let (message, index, _) =
            futures::future::select_all(streams.iter_mut().map(|s| s.select_next_some())).await;
        let message = message?;
        let sender = &senders[index];
        process_msg(sender, message)?;
    }
}

fn process_msg(sender: &Sender, message: Message) -> error::Result<()> {
    // print!("{}", message);

    match message.command {
        Command::PRIVMSG(ref target, ref msg) => {
            if msg.contains("pickles") {
                sender.send_privmsg(target, "Hi!")?;
            }
        }
        _ => (),
    }

    Ok(())
}

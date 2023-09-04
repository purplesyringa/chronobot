use anyhow::{bail, Context, Result};
use grammers_client::{
    types::{Channel, Chat, Group, InputMessage, Message, PackedChat},
    Client, Update,
};
use grammers_session::Session;
use grammers_tl_types::{
    enums::{
        self, messages::Messages, ChatInvite, InputChannel, InputMedia, InputUser, MessageEntity,
        MessageFwdHeader, MessageMedia, MessageReplies, MessageReplyHeader, Peer, Updates, User,
    },
    functions::{
        channels::{GetChannels, GetMessages},
        messages::{CheckChatInvite, SendMedia, SendMessage, SendMultiMedia},
        users::GetUsers,
    },
    types::{
        self, Document, InputChannelFromMessage, InputDocument, InputMediaDocument,
        InputMediaPhoto, InputMessageId, InputPhoto, InputSingleMedia, InputUserFromMessage,
        MessageEntityTextUrl, MessageEntityUrl, MessageMediaDocument, MessageMediaPhoto,
        PeerChannel, Photo,
    },
};
use serde::Deserialize;
use std::collections::{hash_map::Entry, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use text_io::read;

#[derive(Deserialize)]
struct Config {
    login: ConfigLogin,
    access: ConfigAccess,
    #[serde(default)]
    forward: ConfigForward,
}

#[derive(Deserialize)]
struct ConfigLogin {
    api_id: i32,
    api_hash: String,
    phone: String,
}

#[derive(Deserialize)]
struct ConfigAccess {
    channel_username: String,
    public_discussion_joinlink_hash: String,
    private_discussion_joinlink_hash: String,
}

#[derive(Default, Deserialize)]
struct ConfigForward {
    public_discussion: Option<String>,
    private_discussion: Option<String>,
    forwarded_from_channel: Option<String>,
    forwarded_from_user: Option<String>,
    posted_by: Option<String>,
}

async fn create_client(config: &Config) -> Result<Client> {
    let client = Client::connect(grammers_client::Config {
        session: Session::load_file_or_create("aldan.session")?,
        api_id: config.login.api_id,
        api_hash: config.login.api_hash.clone(),
        params: Default::default(),
    })
    .await?;

    if !client.is_authorized().await? {
        let token = client
            .request_login_code(
                &config.login.phone,
                config.login.api_id,
                &config.login.api_hash,
            )
            .await?;
        print!("Enter the login code: ");
        let code: String = read!("{}\n");
        client.sign_in(&token, &code).await?;
        if let Err(e) = client.session().save_to_file("aldan.session") {
            client.sign_out().await?;
            return Err(e.into());
        }
    }

    Ok(client)
}

fn is_public_discussion_post(message: &Message, public_discussion: &Group) -> bool {
    if message.action().is_some() {
        return false;
    }
    let Chat::Group(group) = message.chat() else {
        return false;
    };
    if group.id() != public_discussion.id() {
        return false;
    }
    let Some(MessageFwdHeader::Header(header)) = message.forward_header() else {
        return false;
    };
    header.saved_from_peer.is_some()
}

fn tl_len(s: &str) -> i32 {
    s.encode_utf16().count() as i32
}

async fn get_message(
    client: &Client,
    orig_peer: PackedChat,
    orig_msg_id: i32,
    channel_id: i64,
    id: i32,
) -> Result<types::Message> {
    let message = client
        .invoke(&GetMessages {
            channel: InputChannel::FromMessage(InputChannelFromMessage {
                peer: orig_peer.to_input_peer(),
                msg_id: orig_msg_id,
                channel_id,
            }),
            id: vec![enums::InputMessage::Id(InputMessageId { id })],
        })
        .await?;
    let message = match message {
        Messages::ChannelMessages(mut messages) => messages.messages.pop(),
        _ => bail!("Unexpected result from GetMessages"),
    };
    let Some(enums::Message::Message(message)) = message else {
        bail!("Unexpected result from GetMessages");
    };
    Ok(message)
}

async fn get_reply_post(
    client: &Client,
    message: &types::Message,
    channel: &Channel,
) -> Result<Option<types::Message>> {
    let Some(MessageReplyHeader::Header(ref header)) = message.reply_to else {
        return Ok(None);
    };

    Ok(Some(
        get_message(
            client,
            channel.pack(),
            message.id,
            channel.id(),
            header.reply_to_msg_id,
        )
        .await?,
    ))
}

async fn get_private_forwarded_post_id(
    client: &Client,
    message: &types::Message,
    public_discussion: &Group,
    private_discussion: &Group,
) -> Result<Option<i32>> {
    let Some(MessageReplies::Replies(types::MessageReplies {
        max_id: Some(last_public_reply_id),
        ..
    })) = message.replies
    else {
        return Ok(None);
    };

    let Some(ref last_public_reply) = client
        .get_messages_by_id(public_discussion, &[last_public_reply_id])
        .await?[0]
    else {
        return Ok(None);
    };

    if !last_public_reply.outgoing() {
        return Ok(None);
    }

    let Some(entities) = last_public_reply.fmt_entities() else {
        return Ok(None);
    };
    if entities.len() != 1 {
        return Ok(None);
    }

    let MessageEntity::TextUrl(MessageEntityTextUrl {
        offset: 0, ref url, ..
    }) = entities[0]
    else {
        return Ok(None);
    };

    let prefix = format!("https://t.me/c/{}/", private_discussion.id());
    let Some(msg_id_str) = url.strip_prefix(&prefix) else {
        return Ok(None);
    };
    Ok(msg_id_str.parse::<i32>().ok())
}

fn get_url_from_forward_header(header: &types::MessageFwdHeader) -> Option<String> {
    match header.from_id.as_ref()? {
        Peer::User(user) => Some(format!("tg://user?id={}", user.user_id)),
        Peer::Channel(channel) => {
            let channel_link = format!("https://t.me/c/{}", channel.channel_id);
            Some(match header.channel_post {
                Some(channel_post) => format!("{channel_link}/{channel_post}"),
                None => channel_link,
            })
        }
        _ => None,
    }
}

async fn get_forward_signature(
    config: &Config,
    client: &Client,
    message: &types::Message,
    offset: i32,
    channel: &Channel,
) -> Result<Option<(String, Option<MessageEntity>)>> {
    let Some(MessageFwdHeader::Header(header)) = message.fwd_from.as_ref() else {
        return Ok(None);
    };

    let name;
    let pattern;
    if let Some(ref from_name) = header.from_name {
        name = from_name.clone();
        pattern = &config.forward.forwarded_from_user;
    } else if let Some(ref from) = header.from_id {
        match from {
            Peer::User(user) => {
                let user = client
                    .invoke(&GetUsers {
                        id: vec![InputUser::FromMessage(InputUserFromMessage {
                            peer: channel.pack().to_input_peer(),
                            msg_id: message.id,
                            user_id: user.user_id,
                        })],
                    })
                    .await?
                    .pop()
                    .unwrap();
                name = match user {
                    User::Empty(_) => bail!("Empty user"),
                    User::User(user) => match (user.first_name, user.last_name) {
                        (Some(x), Some(y)) => format!("{x} {y}"),
                        (Some(x), None) | (None, Some(x)) => x,
                        (None, None) => bail!("User without name"),
                    },
                };
                pattern = &config.forward.forwarded_from_user;
            }
            Peer::Chat(_) => bail!("Forward from chat"),
            Peer::Channel(from_channel) => {
                let from_channel = client
                    .invoke(&GetChannels {
                        id: vec![InputChannel::FromMessage(InputChannelFromMessage {
                            peer: channel.pack().to_input_peer(),
                            msg_id: message.id,
                            channel_id: from_channel.channel_id,
                        })],
                    })
                    .await?
                    .chats()
                    .pop()
                    .unwrap();
                name = match from_channel {
                    enums::Chat::Channel(from_channel) => from_channel.title,
                    _ => bail!("Unexpected return from GetChannels"),
                };
                pattern = &config.forward.forwarded_from_channel;
            }
        }
    } else {
        return Ok(None);
    }

    let Some(ref pattern) = pattern else {
        return Ok(None);
    };

    if let Some((prefix, suffix)) = pattern.split_once("{}") {
        let text = format!("{prefix}{name}{suffix}");
        let entity = get_url_from_forward_header(header).map(|url| {
            MessageEntity::TextUrl(MessageEntityTextUrl {
                offset: offset + tl_len(prefix),
                length: tl_len(&name),
                url,
            })
        });
        Ok(Some((text, entity)))
    } else {
        Ok(Some((pattern.to_string(), None)))
    }
}

fn get_author_signature(config: &Config, message: &types::Message) -> Option<String> {
    let post_author = message.post_author.as_ref()?;
    Some(
        config
            .forward
            .posted_by
            .as_ref()?
            .replace("{}", post_author),
    )
}

async fn forward_post(
    config: &Config,
    client: &Client,
    public_discussion_messages: &[Message],
    public_discussion: &Group,
    private_discussion: &Group,
    channel: &Channel,
) -> Result<String> {
    let MessageFwdHeader::Header(header) = public_discussion_messages[0].forward_header().unwrap();

    let Peer::Channel(PeerChannel { channel_id }) = header.saved_from_peer.unwrap() else {
        bail!("Unexpected message in public discussion");
    };

    let message = get_message(
        client,
        public_discussion.pack(),
        public_discussion_messages[0].id(),
        channel_id,
        header.saved_from_msg_id.unwrap(),
    )
    .await?;
    let mut new_entities = message.entities.clone().unwrap_or_else(Vec::new);

    let additional_text;
    let link_offset;
    let link_length;
    let pattern = config.forward.private_discussion.as_deref().unwrap_or("");
    if let Some((prefix, rest)) = pattern.split_once("[[") {
        let (mid, suffix) = rest
            .split_once("]]")
            .expect("Invalid forward.private_discussion");
        additional_text = format!("{prefix}{mid}{suffix}");
        link_offset = tl_len(prefix);
        link_length = tl_len(mid);
    } else {
        additional_text = pattern.to_string();
        link_offset = -1;
        link_length = -1;
    }

    let old_text = message.message.trim();
    let new_text_untrimmed = format!("{old_text}{additional_text}");
    let mut new_text = new_text_untrimmed.trim_start().to_string();
    let whitespace_trimmed = &new_text_untrimmed[..new_text_untrimmed.len() - new_text.len()];
    if link_offset != -1 {
        new_entities.push(MessageEntity::TextUrl(MessageEntityTextUrl {
            offset: tl_len(old_text) + link_offset - tl_len(whitespace_trimmed),
            length: link_length,
            url: format!(
                "https://t.me/{}/{}",
                config.access.channel_username, message.id
            ),
        }));
    }

    if let Some((text, entity)) =
        get_forward_signature(config, client, &message, tl_len(&new_text), channel).await?
    {
        new_text += &text;
        new_entities.extend(entity);
    } else if let Some(text) = get_author_signature(config, &message) {
        new_text += &text;
    }

    // If a link takes the entirety of the original message, show preview
    let link_preview = message.entities.as_ref().is_some_and(|entities| {
        matches!(
            entities[..],
            [MessageEntity::Url(MessageEntityUrl { offset: 0, length })
                | MessageEntity::TextUrl(MessageEntityTextUrl {
                    offset: 0,
                    length,
                    ..
                })] if length == tl_len(&message.message),
        )
    });

    let mut reply_to = None;
    if let Some(reply_to_in_channel) = get_reply_post(client, &message, channel).await? {
        reply_to = get_private_forwarded_post_id(
            client,
            &reply_to_in_channel,
            public_discussion,
            private_discussion,
        )
        .await?;
    }

    let mut input_media = Vec::new();

    for public_discussion_message in public_discussion_messages {
        let MessageFwdHeader::Header(header) = public_discussion_message.forward_header().unwrap();
        let message = get_message(
            client,
            public_discussion.pack(),
            public_discussion_message.id(),
            channel_id,
            header.saved_from_msg_id.unwrap(),
        )
        .await?;
        match message.media {
            Some(MessageMedia::Photo(MessageMediaPhoto {
                photo: Some(photo),
                ttl_seconds,
                spoiler,
            })) => input_media.push(InputMedia::Photo(InputMediaPhoto {
                id: match photo {
                    enums::Photo::Empty(_) => enums::InputPhoto::Empty,
                    enums::Photo::Photo(Photo {
                        id,
                        access_hash,
                        file_reference,
                        ..
                    }) => enums::InputPhoto::Photo(InputPhoto {
                        id,
                        access_hash,
                        file_reference,
                    }),
                },
                ttl_seconds,
                spoiler,
            })),
            Some(MessageMedia::Document(MessageMediaDocument {
                nopremium: _,
                spoiler,
                document: Some(document),
                ttl_seconds,
            })) => input_media.push(InputMedia::Document(InputMediaDocument {
                spoiler,
                id: match document {
                    enums::Document::Empty(_) => enums::InputDocument::Empty,
                    enums::Document::Document(Document {
                        id,
                        access_hash,
                        file_reference,
                        ..
                    }) => enums::InputDocument::Document(InputDocument {
                        id,
                        access_hash,
                        file_reference,
                    }),
                },
                ttl_seconds,
                query: None,
            })),
            _ => {}
        }
    }

    let mut new_entities = if new_entities.is_empty() {
        None
    } else {
        Some(new_entities)
    };
    let first_random_id = rand::random();

    let updates;
    if input_media.is_empty() {
        updates = client
            .invoke(&SendMessage {
                no_webpage: !link_preview,
                silent: message.silent,
                background: false,
                clear_draft: false,
                noforwards: false,
                update_stickersets_order: false,
                peer: private_discussion.pack().to_input_peer(),
                reply_to_msg_id: reply_to,
                top_msg_id: None,
                message: new_text,
                random_id: first_random_id,
                reply_markup: None,
                entities: new_entities,
                schedule_date: None,
                send_as: None,
            })
            .await?;
    } else if input_media.len() == 1 {
        updates = client
            .invoke(&SendMedia {
                silent: message.silent,
                background: false,
                clear_draft: false,
                noforwards: false,
                update_stickersets_order: false,
                peer: private_discussion.pack().to_input_peer(),
                reply_to_msg_id: reply_to,
                top_msg_id: None,
                media: input_media.pop().unwrap(),
                message: new_text,
                random_id: first_random_id,
                reply_markup: None,
                entities: new_entities,
                schedule_date: None,
                send_as: None,
            })
            .await?;
    } else {
        let mut random_id = Some(first_random_id);
        let mut new_text = Some(new_text);
        updates = client
            .invoke(&SendMultiMedia {
                silent: message.silent,
                background: false,
                clear_draft: false,
                noforwards: false,
                update_stickersets_order: false,
                peer: private_discussion.pack().to_input_peer(),
                reply_to_msg_id: reply_to,
                top_msg_id: None,
                multi_media: input_media
                    .into_iter()
                    .map(|media| {
                        enums::InputSingleMedia::Media(InputSingleMedia {
                            media,
                            random_id: random_id.take().unwrap_or_else(rand::random),
                            message: new_text.take().unwrap_or_default(),
                            entities: new_entities.take(),
                        })
                    })
                    .collect(),
                schedule_date: None,
                send_as: None,
            })
            .await?;
    }

    let Updates::Updates(updates) = updates else {
        bail!("Unexpected return value from SendMessage {updates:?}")
    };

    let id = updates
        .updates
        .iter()
        .find_map(|update| match update {
            enums::Update::MessageId(update) if update.random_id == first_random_id => {
                Some(update.id)
            }
            _ => None,
        })
        .context("MessageId update missing")?;

    Ok(format!("https://t.me/c/{}/{}", private_discussion.id(), id))
}

async fn add_discussion_link(
    config: &Config,
    message: &Message,
    private_link: String,
) -> Result<()> {
    let Some(ref pattern) = config.forward.public_discussion else {
        return Ok(());
    };

    let reply = if let Some((prefix, rest)) = pattern.split_once("[[") {
        let Some((mid, suffix)) = rest.split_once("]]") else {
            bail!("Invalid forward.public_discussion");
        };
        InputMessage::text(format!("{prefix}{mid}{suffix}")).fmt_entities(vec![
            MessageEntity::TextUrl(MessageEntityTextUrl {
                offset: tl_len(prefix),
                length: tl_len(mid),
                url: private_link,
            }),
        ])
    } else {
        InputMessage::text(pattern.clone())
    };

    message.reply(reply).await?;
    Ok(())
}

async fn handle_post(
    config: &Config,
    client: &Client,
    messages: &[Message],
    public_discussion: &Group,
    private_discussion: &Group,
    channel: &Channel,
) -> Result<()> {
    let private_link = forward_post(
        config,
        client,
        messages,
        public_discussion,
        private_discussion,
        channel,
    )
    .await?;
    add_discussion_link(config, &messages[0], private_link).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = std::fs::read_to_string("config.toml").context("Failed to read config.toml")?;
    let config = Arc::new(toml::from_str(&config).context("Failed to parse config")?);

    let client = Arc::new(create_client(&config).await?);

    let public_discussion = match client
        .invoke(&CheckChatInvite {
            hash: config.access.public_discussion_joinlink_hash.clone(),
        })
        .await?
    {
        ChatInvite::Already(already) => Arc::new(Group::from_raw(already.chat)),
        _ => panic!("Invalid public discussion join link"),
    };

    let private_discussion = match client
        .invoke(&CheckChatInvite {
            hash: config.access.private_discussion_joinlink_hash.clone(),
        })
        .await?
    {
        ChatInvite::Already(already) => Arc::new(Group::from_raw(already.chat)),
        _ => panic!("Invalid private discussion join link"),
    };

    let channel = match client
        .resolve_username(&config.access.channel_username)
        .await?
    {
        Some(Chat::Channel(channel)) => Arc::new(channel),
        _ => panic!("Invalid channel username"),
    };

    let messages_by_grouped_id = Arc::new(Mutex::new(HashMap::new()));

    while let Some(update) = client.next_update().await? {
        let Update::NewMessage(message) = update else {
            continue;
        };
        if !is_public_discussion_post(&message, &public_discussion) {
            continue;
        }

        if let Some(grouped_id) = message.grouped_id() {
            let was_vacant;
            {
                let mut lock = messages_by_grouped_id.lock().unwrap();
                let entry = lock.entry(grouped_id);
                was_vacant = matches!(entry, Entry::Vacant(_));
                entry.or_insert_with(Vec::new).push(message);
            }
            if was_vacant {
                let config = Arc::clone(&config);
                let client = Arc::clone(&client);
                let public_discussion = Arc::clone(&public_discussion);
                let private_discussion = Arc::clone(&private_discussion);
                let channel = Arc::clone(&channel);
                let messages_by_grouped_id = Arc::clone(&messages_by_grouped_id);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let messages;
                    {
                        let mut lock = messages_by_grouped_id.lock().unwrap();
                        messages = lock
                            .remove(&grouped_id)
                            .expect("grouped_id is missing from the hashmap");
                    }
                    handle_post(
                        &config,
                        &client,
                        &messages,
                        &public_discussion,
                        &private_discussion,
                        &channel,
                    )
                    .await
                    .expect("Failed to handle multimedia post");
                });
            }
        } else {
            handle_post(
                &config,
                &client,
                &[message],
                &public_discussion,
                &private_discussion,
                &channel,
            )
            .await?;
        }
    }

    Ok(())
}

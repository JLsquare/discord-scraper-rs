use reqwest::{Client, Response, header};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::fs::OpenOptions;
use std::time::Duration;
use std::io::Write;

#[derive(Deserialize)]
struct Config {
    base_url: String,
    max_messages_per_channel: usize,
    token: String,
    guilds: Vec<GuildConfig>,
}

#[derive(Deserialize)]
struct GuildConfig {
    id: String,
    all: bool,
    channels: Vec<String>,
    blacklist: Vec<String>,
}

fn load_config() -> Config {
    let data = fs::read_to_string("config.json").expect("Unable to read config.json");
    serde_json::from_str(&data).expect("Failed to parse config.json")
}

#[tokio::main]
async fn main() {
    let config = load_config();
    for guild_config in &config.guilds {
        match process_guild(&config, guild_config).await {
            Ok(_) => {},
            Err(e) => eprintln!("Error processing guild: {}", e),
        }
    }
}

async fn process_guild(
    config: &Config,
    guild_config: &GuildConfig
) -> Result<(), reqwest::Error> {
    let guild_id = &guild_config.id;
    let guild_name = get_guild_name(&config.base_url, guild_id, &config.token).await?;
    println!("Guild name: {}", guild_name);

    let mut channels = guild_config.channels.clone();
    if guild_config.all {
        channels = get_channels_from_guild(&config.base_url, guild_id, &config.token).await.unwrap_or(Vec::new());
    }

    let filtered_channels: Vec<_> = channels
        .iter()
        .filter(|channel| !guild_config.blacklist.contains(channel))
        .cloned()
        .collect();

    for channel_config in filtered_channels {
        process_channel(config, guild_config, &channel_config, &guild_name).await?;
    }

    Ok(())
}

async fn process_channel(
    config: &Config,
    guild_config: &GuildConfig,
    channel_id: &str,
    guild_name: &str
) -> Result<(), reqwest::Error> {
    if is_channel_forbidden(&config.base_url, channel_id, &config.token).await? {
        println!("Channel access forbidden");
        return Ok(());
    }
    let channel_name = get_channel_name(&config.base_url, channel_id, &config.token).await?;
    println!("Channel name: {}", channel_name);
    if does_channel_file_exist(guild_name, &channel_name) {
        println!("Channel file already exists");
        return Ok(());
    }

    let total_messages = get_channel_length(&config.base_url, &guild_config.id, channel_id, &config.token).await.unwrap_or(0);
    let mut messages: Vec<Value> = Vec::new();
    let mut count = 0;
    let url = format!("{}/channels/{}/messages?limit=100", &config.base_url, channel_id);

    let json = fetch_data(&url, &config.base_url, "", channel_id, &config.token).await?;
    for message in &json {
        messages.push(extract_message_author_and_bot(message));
    }
    count += 100;
    if !json.is_empty() {
        get_message_before(&mut messages, json[json.len() - 1]["id"].as_str().unwrap(), &mut count, total_messages, config.max_messages_per_channel, &config.base_url, channel_id, guild_name, &channel_name, &config.token).await;
    }
    save_messages_to_file(guild_name, &channel_name, &messages);

    Ok(())
}

async fn get_guild_name(
    base_url: &str,
    guild_id: &str,
    token: &str
) -> Result<String, reqwest::Error> {
    let url = format!("{}/guilds/{}", base_url, guild_id);
    let resp = send_request(&url, base_url, guild_id, "", token).await?;
    let json: Value = resp.json().await?;
    let guild_name = match json["name"].as_str() {
        Some(name) => name.to_string(),
        None => guild_id.to_string(),
    };

    Ok(guild_name)
}

async fn get_channels_from_guild(
    base_url: &str,
    guild_id: &str,
    token: &str
) -> Result<Vec<String>, reqwest::Error> {
    let url = format!("{}/guilds/{}/channels?limit=100", base_url, guild_id);
    let resp = send_request(&url, base_url, guild_id, "", token).await?;
    let json: Value = resp.json().await?;
    let empty: Vec<Value> = Vec::new();
    let channels_json = json.as_array().unwrap_or(&empty);

    let mut channels: Vec<String> = Vec::new();
    for (index, channel) in channels_json.iter().enumerate() {
        channels.push(channel["id"].as_str().unwrap_or(&index.to_string()).to_string());
    }
    Ok(channels)
}

async fn is_channel_forbidden(
    base_url: &str,
    channel_id: &str,
    token: &str
) -> Result<bool, reqwest::Error> {
    let url = format!("{}/channels/{}", base_url, channel_id);
    let resp = send_request(&url, base_url, "", channel_id, token).await?;
    Ok(resp.status() == 403)
}

async fn get_channel_name(
    base_url: &str,
    channel_id: &str,
    token: &str
) -> Result<String, reqwest::Error> {
    let url = format!("{}/channels/{}", base_url, channel_id);
    let resp = send_request(&url, base_url, "", channel_id, token).await?;
    let json: Value = resp.json().await?;
    let channel_name = json["name"].as_str().unwrap_or(channel_id).to_string();
    Ok(channel_name)
}

async fn get_channel_length(
    base_url: &str,
    guild_id: &str,
    channel_id: &str,
    token: &str
) -> Result<usize, reqwest::Error> {
    let url = format!("{}/guilds/{}/messages/search?channel_id={}&include_nsfw=true", base_url, guild_id, channel_id);
    let resp = send_request(&url, base_url, guild_id, channel_id, token).await?;
    let json: Value = resp.json().await?;
    let total_messages = json["total_results"].as_u64().unwrap_or(0) as usize;
    Ok(total_messages)
}

async fn get_message_before(
    messages: &mut Vec<Value>,
    before_id: &str,
    count: &mut usize,
    total_messages: usize,
    max: usize,
    base_url: &str,
    channel_id: &str,
    guild_name: &str,
    channel_name: &str,
    token: &str
) {
    let mut current_before_id = before_id.to_string();
    loop {
        let url = format!("{}/channels/{}/messages?before={}&limit=100", base_url, channel_id, &current_before_id);

        match fetch_data(&url, base_url, "", channel_id, token).await {
            Ok(json) => {
                for message in &json {
                    messages.push(extract_message_author_and_bot(message));
                }
                if !json.is_empty() {
                    *count += 100;
                    let total = std::cmp::min(max, total_messages);
                    println!("Progress: {}/{} - {:.2}%", messages.len(), total, (messages.len() as f64 / total as f64) * 100.0);

                    if *count >= max {
                        save_messages_to_file(guild_name, channel_name, messages);
                        break;
                    }
                    current_before_id = match json[json.len() - 1]["id"].as_str() {
                        Some(id) => id.to_string(),
                        None => {
                            eprintln!("Error fetching message before ID: {}", current_before_id);
                            save_messages_to_file(guild_name, channel_name, messages);
                            break
                        },
                    }
                } else {
                    break;
                }
            },
            Err(e) => {
                eprintln!("Error fetching message before ID: {}", e);
                save_messages_to_file(guild_name, channel_name, messages);
                break;
            }
        }
    }
}

fn extract_message_author_and_bot(msg: &Value) -> Value {
    json!({
        "content": msg["content"].as_str().unwrap_or_default(),
        "username": msg["author"]["username"].as_str().unwrap_or_default(),
        "bot": msg["author"]["bot"].as_bool().unwrap_or_default(),
    })
}

fn sanitize_filename(filename: &str) -> String {
    filename.chars().map(|c| match c {
        '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '-',
        _ => c,
    }).collect()
}

fn save_messages_to_file(guild_name: &str, channel_name: &str, messages: &Vec<Value>) {
    let mut messages = messages.clone();
    messages.reverse();

    let path_str = format!(
        "guilds/{}/{}.json",
        sanitize_filename(guild_name),
        sanitize_filename(channel_name)
    );
    let path = std::path::Path::new(&path_str);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("Error creating directory: {}", e);
                return;
            }
        }
    }

    let mut file = match OpenOptions::new().write(true).create(true).truncate(true).open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            return;
        }
    };

    let serialized_data = serde_json::to_string_pretty(&json!({"messages": messages})).unwrap_or_else(|_| "Error".to_string());

    if let Err(e) = file.write_all(serialized_data.as_bytes()) {
        eprintln!("Error saving messages to file: {}", e);
        return;
    }

    if let Err(e) = file.sync_all() {
        eprintln!("Error syncing file: {}", e);
        return;
    }

    if path.exists() {
        println!("Messages saved to {}", path_str);
    } else {
        eprintln!("Error saving messages to file: {}", path_str);
    }
}

fn does_channel_file_exist(guild_name: &str, channel_name: &str) -> bool {
    let path_str = format!(
        "guilds/{}/{}.json",
        sanitize_filename(guild_name),
        sanitize_filename(channel_name)
    );
    let path = std::path::Path::new(&path_str);
    path.exists()
}

async fn fetch_data(
    url: &str,
    base_url: &str,
    guild_id: &str,
    channel_id: &str,
    token: &str
) -> Result<Vec<Value>, reqwest::Error> {
    let resp = send_request(url, base_url, guild_id, channel_id, token).await?;
    resp.json().await
}

async fn send_request(
    url: &str,
    base_url: &str,
    guild_id: &str,
    channel_id: &str,
    token: &str
) -> Result<Response, reqwest::Error> {
    let client = Client::new();
    let mut retries = 5;

    loop {
        let resp = client.get(url)
            .header(header::USER_AGENT, "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0")
            .header(header::AUTHORIZATION, token)
            .header(header::REFERER, format!("{}/channels/{}/{}", base_url, guild_id, channel_id))
            .send()
            .await;

        match resp {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Ok(response);
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            },
            Err(_) => {
                if retries == 0 {
                    return resp;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }

        retries -= 1;
    }
}

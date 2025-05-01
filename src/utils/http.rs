// src/utils/http.rs
use std::time::Duration;
use anyhow::{Result, Context};
use reqwest::{Client, Response, header};
use serde::Serialize;
use tracing::{debug, warn};

/// HTTP client for making requests
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    user_agent: String,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(user_agent: Option<String>, timeout_secs: Option<u64>) -> Result<Self> {
        let user_agent = user_agent.unwrap_or_else(|| format!("bbhunt/{}", env!("CARGO_PKG_VERSION")));
        let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
        
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&user_agent)
            .build()
            .context("Failed to create HTTP client")?;
        
        Ok(Self { client, user_agent })
    }
    
    /// Make a GET request
    pub async fn get(&self, url: &str) -> Result<Response> {
        debug!("GET {}", url);
        
        self.client
            .get(url)
            .send()
            .await
            .context(format!("Failed to GET {}", url))
    }
    
    /// Make a POST request with JSON body
    pub async fn post_json<T: Serialize>(&self, url: &str, data: &T) -> Result<Response> {
        debug!("POST {}", url);
        
        self.client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(data)
            .send()
            .await
            .context(format!("Failed to POST to {}", url))
    }
    
    /// Check if a URL is reachable
    pub async fn is_url_live(&self, url: &str) -> bool {
        match self.get(url).await {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                warn!("Failed to check URL {}: {}", url, e);
                false
            }
        }
    }
    
    /// Download content from a URL
    pub async fn download(&self, url: &str) -> Result<Vec<u8>> {
        debug!("Downloading {}", url);
        
        let response = self.get(url).await?;
        let bytes = response.bytes().await?;
        
        Ok(bytes.to_vec())
    }
    
    /// Get the user agent
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }
}
//! `hypr pull` command - Pull an image from a registry

use crate::client::HyprClient;
use anyhow::Result;

/// Pull an image from a registry
pub async fn pull(image: &str) -> Result<()> {
    println!("Pulling image: {}", image);

    let mut client = HyprClient::connect().await?;

    // Parse image name and tag
    let (image_name, image_tag) =
        if let Some((name, tag)) = image.split_once(':') { (name, tag) } else { (image, "latest") };

    // This will auto-pull if the image doesn't exist locally
    let image_info = client.get_image(image_name, image_tag).await?;

    println!("Image pulled successfully:");
    println!("  ID:   {}", &image_info.id[..12.min(image_info.id.len())]);
    println!("  Name: {}:{}", image_info.name, image_info.tag);
    println!("  Size: {:.2} MB", image_info.size_bytes as f64 / 1024.0 / 1024.0);

    Ok(())
}

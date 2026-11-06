//! `POST /api/import_channel_attachment` — fork(letscubo)专属:渠道附件导入。
//!
//! MyClaw 平台把 Telegram / WhatsApp 收到的附件暂存进自己的**私有** R2 桶,签一个
//! 300 秒有效的预签名 URL,再让实例把字节落到本地磁盘;最终写进提示词的是本地
//! **绝对路径**,不是链接 —— 下载地址(带签名)既不进模型上下文,也不进聊天历史。
//!
//! 一次调用 = 下载 → 校验(长度 + sha256)→ 原子落盘 → 返回 `{path, size}`。
//! 平台侧(`web/src/lib/channels/channel-media.ts`)会对 path 做严格校验(绝对路径、
//! 无控制字符、无空段/`.`/`..`),并要求 `size` 与入参字节数完全相等。所以这里
//! **只在校验全部通过之后**才返回路径,任何不一致都报错,绝不返回"看起来像成功"的值。
//!
//! 落盘位置沿用上游 `upload_attachment` 的约定:
//! `<uploads_root>/<session>/<object>/<name>` —— 与网页上传的附件同根,agent 用
//! `file://` 直接读。同一 job 重试时 `objectId` 不变,于是重放会覆盖同一路径(幂等),
//! 不会堆出 `name (1).zip`。
//!
//! ## 鉴权 / 信任边界
//!
//! 与所有 `/api/*` 一样过 `web::auth::require_token`。请求里的 `sessionId` /
//! `name` 最终来自聊天软件用户输入,一律在本地重新消毒(不假设平台已经处理);
//! 下载 URL 只交给 reqwest,不进错误信息(`without_url`),避免签名链接漏进日志。

use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::app_error::AppCommandError;
use crate::paths::codeg_uploads_root;
use crate::web::handlers::files::{
    ensure_path_inside, sanitize_session_bucket, sanitize_upload_filename,
};
use crate::web::handlers::upload_jail;

/// 与平台侧 `CHANNEL_MEDIA_MAX_BYTES` 对齐(10 MiB)。请求里的 `size` 不可信,
/// 下载本身也按这个上限截断 —— 超了立刻停,不落盘。
const MAX_BYTES: u64 = 10 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 平台侧等 75 秒,这里留出余量,超时由 codeg 先报。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub url: String,
    pub session_id: String,
    pub object_id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub path: String,
    pub size: u64,
}

pub async fn import_channel_attachment(
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, AppCommandError> {
    import_into(&codeg_uploads_root(), req).await.map(Json)
}

/// `root` 显式传入,测试才能用临时目录而不是真实的 `~/.codeg/uploads`。
async fn import_into(root: &Path, req: ImportRequest) -> Result<ImportResult, AppCommandError> {
    validate(&req)?;
    let expected_sha = req.sha256.trim().to_ascii_lowercase();

    let dir = root
        .join(sanitize_session_bucket(&req.session_id))
        .join(sanitize_session_bucket(&req.object_id));
    let name = sanitize_upload_filename(&req.name);

    let tmp_dir = root.join(".tmp");
    tokio::fs::create_dir_all(&tmp_dir).await.map_err(|e| {
        AppCommandError::io_error("Failed to create uploads tmp directory")
            .with_detail(e.to_string())
    })?;
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        AppCommandError::io_error("Failed to create channel attachment directory")
            .with_detail(e.to_string())
    })?;
    // `create_dir_all` 对已存在的符号链接是 no-op,所以两个目录都要在落盘前
    // 确认解析后仍在 uploads root 内(与 files.rs 的校验同源)。
    ensure_path_inside(&tmp_dir, root).await?;
    ensure_path_inside(&dir, root).await?;

    let staging = format!("{}.part", uuid::Uuid::new_v4().simple());
    let mut file = upload_jail::create_staging_file(&tmp_dir, &staging)
        .await
        .map_err(|e| {
            AppCommandError::io_error("Failed to create channel attachment staging file")
                .with_detail(e.to_string())
        })?;

    let (written, actual_sha) = match write_download(&req.url, &mut file).await {
        Ok(v) => v,
        Err(e) => {
            drop(file);
            upload_jail::remove_staging_best_effort(&tmp_dir, &staging).await;
            return Err(e);
        }
    };
    drop(file);

    let mismatch = if written != req.size {
        Some(format!(
            "size mismatch: declared {} bytes, received {written}",
            req.size
        ))
    } else if actual_sha != expected_sha {
        Some("sha256 mismatch".to_string())
    } else {
        None
    };
    if let Some(detail) = mismatch {
        upload_jail::remove_staging_best_effort(&tmp_dir, &staging).await;
        return Err(
            AppCommandError::invalid_input("Channel attachment verification failed")
                .with_detail(detail),
        );
    }

    match upload_jail::finalize_into_bucket(&tmp_dir, &staging, &dir, &name).await {
        Ok(()) => {}
        // 同一个 job 重放:objectId 相同 → 目标已存在。覆盖即可。
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            tokio::fs::remove_file(dir.join(&name)).await.map_err(|e| {
                AppCommandError::io_error("Failed to replace previous channel attachment")
                    .with_detail(e.to_string())
            })?;
            upload_jail::finalize_into_bucket(&tmp_dir, &staging, &dir, &name)
                .await
                .map_err(|e| {
                    AppCommandError::io_error("Failed to store channel attachment")
                        .with_detail(e.to_string())
                })?;
        }
        Err(e) => {
            upload_jail::remove_staging_best_effort(&tmp_dir, &staging).await;
            return Err(
                AppCommandError::io_error("Failed to store channel attachment")
                    .with_detail(e.to_string()),
            );
        }
    }
    upload_jail::remove_staging_best_effort(&tmp_dir, &staging).await;

    // 防御性复核:返回给平台的路径必须是解析后仍在 root 内的绝对路径。
    let path = ensure_path_inside(&dir.join(&name), root).await?;
    Ok(ImportResult {
        path: path.to_string_lossy().into_owned(),
        size: written,
    })
}

fn validate(req: &ImportRequest) -> Result<(), AppCommandError> {
    let url = reqwest::Url::parse(&req.url)
        .map_err(|_| AppCommandError::invalid_input("url is not a valid URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(AppCommandError::invalid_input(
            "url must be an absolute http(s) URL",
        ));
    }
    if req.object_id.trim().is_empty() {
        return Err(AppCommandError::invalid_input("objectId must not be empty"));
    }
    if req.size == 0 || req.size > MAX_BYTES {
        return Err(AppCommandError::invalid_input(
            "size must be between 1 byte and the attachment limit",
        ));
    }
    let sha = req.sha256.trim();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppCommandError::invalid_input(
            "sha256 must be 64 hexadecimal characters",
        ));
    }
    Ok(())
}

/// 流式下载并边写边算 sha256,返回 `(已写字节数, 小写十六进制摘要)`。
async fn write_download(
    url: &str,
    file: &mut tokio::fs::File,
) -> Result<(u64, String), AppCommandError> {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|e| {
            AppCommandError::io_error("Failed to build HTTP client")
                .with_detail(e.without_url().to_string())
        })?;
    let mut response = client.get(url).send().await.map_err(|e| {
        AppCommandError::network("Channel attachment download failed")
            .with_detail(e.without_url().to_string())
    })?;
    if !response.status().is_success() {
        return Err(
            AppCommandError::network("Channel attachment download failed")
                .with_detail(format!("status {}", response.status().as_u16())),
        );
    }
    if response.content_length().is_some_and(|len| len > MAX_BYTES) {
        return Err(AppCommandError::invalid_input(
            "Channel attachment exceeds the size limit",
        ));
    }

    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        AppCommandError::network("Channel attachment download failed")
            .with_detail(e.without_url().to_string())
    })? {
        written = written.saturating_add(chunk.len() as u64);
        if written > MAX_BYTES {
            return Err(AppCommandError::invalid_input(
                "Channel attachment exceeds the size limit",
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| {
            AppCommandError::io_error("Failed to write channel attachment")
                .with_detail(e.to_string())
        })?;
    }
    file.flush().await.map_err(|e| {
        AppCommandError::io_error("Failed to write channel attachment").with_detail(e.to_string())
    })?;
    Ok((written, format!("{:x}", hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use serde_json::json;

    const OBJECT_ID: &str = "0123456789abcdef0123456789abcdef";

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// 一个只回固定字节的本地 HTTP 服务,替代 R2 预签名 URL。
    async fn serve(bytes: &'static [u8]) -> String {
        let app = axum::Router::new().route("/object", get(move || async move { bytes }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}/object")
    }

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "codeg-channel-media-{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    fn request(url: String, body: &[u8], name: &str) -> ImportRequest {
        ImportRequest {
            url,
            session_id: "job-1".into(),
            object_id: OBJECT_ID.into(),
            name: name.into(),
            size: body.len() as u64,
            sha256: sha256_hex(body),
        }
    }

    #[test]
    fn request_accepts_the_platforms_camel_case_payload() {
        let req: ImportRequest = serde_json::from_value(json!({
            "url": "https://example.test/object",
            "sessionId": "job-1",
            "objectId": OBJECT_ID,
            "name": "archive.zip",
            "mimeType": "application/zip",
            "size": 3,
            "sha256": sha256_hex(b"abc"),
        }))
        .unwrap();
        assert_eq!(req.session_id, "job-1");
        assert_eq!(req.object_id, OBJECT_ID);
        assert_eq!(req.size, 3);
    }

    #[tokio::test]
    async fn imports_verified_bytes_under_the_uploads_root() {
        let url = serve(b"hello channel").await;
        let root = temp_root();
        let res = import_into(&root, request(url, b"hello channel", "archive.zip"))
            .await
            .unwrap();

        let canon_root = tokio::fs::canonicalize(&root).await.unwrap();
        assert_eq!(
            Path::new(&res.path),
            canon_root.join("job-1").join(OBJECT_ID).join("archive.zip")
        );
        assert_eq!(res.size, 13);
        assert_eq!(tokio::fs::read(&res.path).await.unwrap(), b"hello channel");
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn replayed_import_overwrites_the_same_path() {
        let root = temp_root();
        let first = import_into(
            &root,
            request(serve(b"first").await, b"first", "archive.zip"),
        )
        .await
        .unwrap();
        let second = import_into(
            &root,
            request(serve(b"second").await, b"second", "archive.zip"),
        )
        .await
        .unwrap();

        assert_eq!(first.path, second.path);
        assert_eq!(second.size, 6);
        assert_eq!(tokio::fs::read(&second.path).await.unwrap(), b"second");
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn rejects_sha_mismatch_and_leaves_nothing_behind() {
        let root = temp_root();
        let mut req = request(
            serve(b"hello channel").await,
            b"hello channel",
            "archive.zip",
        );
        req.sha256 = "0".repeat(64);
        let err = import_into(&root, req).await.unwrap_err();
        assert!(err.message.contains("verification failed"));

        let dir = root.join("job-1").join(OBJECT_ID);
        assert!(!dir.join("archive.zip").exists());
        let mut staging = tokio::fs::read_dir(root.join(".tmp")).await.unwrap();
        assert!(staging.next_entry().await.unwrap().is_none());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn rejects_size_mismatch() {
        let root = temp_root();
        let mut req = request(
            serve(b"hello channel").await,
            b"hello channel",
            "archive.zip",
        );
        req.size = 999;
        assert!(import_into(&root, req).await.is_err());
        assert!(!root
            .join("job-1")
            .join(OBJECT_ID)
            .join("archive.zip")
            .exists());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn traversal_in_the_name_stays_inside_the_object_directory() {
        let root = temp_root();
        let res = import_into(
            &root,
            request(serve(b"safe").await, b"safe", "../../etc/passwd"),
        )
        .await
        .unwrap();

        let canon_root = tokio::fs::canonicalize(&root).await.unwrap();
        assert_eq!(
            Path::new(&res.path),
            canon_root.join("job-1").join(OBJECT_ID).join("passwd")
        );
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn rejects_non_http_urls() {
        let req = request("file:///etc/passwd".into(), b"x", "a.txt");
        assert!(import_into(&temp_root(), req).await.is_err());
    }
}

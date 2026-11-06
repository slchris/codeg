//! fork(letscubo)专属 handler 命名空间 —— 上游 xintaofei/codeg 无此模块。
//!
//! 这里集中放 MyClaw 平台对接所需、不属于上游功能面的接口。独立成目录是为了
//! 在跟随上游 rebase / merge 时一眼分清「fork 自有」与「上游原生」,把冲突面
//! 收敛到接线点(handlers/mod.rs 的 `pub mod myclaw;` 与 router.rs 的路由注册)。
//!
//! 路由前缀统一 `/api/myclaw/*`,与上游的扁平命令名(如 `/api/acp_prompt`)区隔。

pub mod activity;
pub mod backup;
pub mod channel_media;
pub mod download;
pub mod exec;
pub mod file_ticket;
pub mod mcp;
pub mod memory;
pub mod metrics;
pub mod runner;
pub mod task;

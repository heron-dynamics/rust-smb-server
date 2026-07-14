//! QUERY_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::ServerState;

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

// FS attribute flags (MS-FSCC §2.5.1)
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
const FILE_FILE_COMPRESSION: u32 = 0x0000_0010;
const FILE_SUPPORTS_HARD_LINKS: u32 = 0x0040_0000;
const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x0080_0000;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match req.info_type_enum() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    // Pull the file index (we use FileId.volatile as the unique handle id).
    let (file_index, info_res) = {
        let open = open_arc.read().await;
        let fid = open.file_id;
        match open.handle.as_ref() {
            Some(h) => (fid.volatile, h.stat().await),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };

    let buf: Vec<u8> = match info_type {
        InfoType::File => {
            let info = match info_res {
                Ok(i) => i,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            match req.file_information_class {
                ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
                ic::FILE_STANDARD_INFORMATION => ic::encode_file_standard_information(&info),
                ic::FILE_INTERNAL_INFORMATION => ic::encode_file_internal_information(file_index),
                ic::FILE_EA_INFORMATION => ic::encode_file_ea_information(),
                ic::FILE_FULL_EA_INFORMATION => {
                    return HandlerResponse::err(ntstatus::STATUS_NO_EAS_ON_FILE);
                }
                ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(0x001F_01FF),
                ic::FILE_POSITION_INFORMATION => ic::encode_file_position_information(),
                ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(0),
                ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
                ic::FILE_NAME_INFORMATION => ic::encode_file_name_information(&info.name),
                ic::FILE_ALL_INFORMATION => {
                    ic::encode_file_all_information(&info, file_index, 0x001F_01FF)
                }
                ic::FILE_NETWORK_OPEN_INFORMATION => {
                    ic::encode_file_network_open_information(&info)
                }
                ic::FILE_STREAM_INFORMATION => ic::encode_file_stream_information(&info),
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::FileSystem => {
            // For FS info we use the open's tree's backend for context.
            let creation_time = info_res.as_ref().map(|i| i.creation_time).unwrap_or(0);
            match req.file_information_class {
                ic::FS_VOLUME_INFORMATION => {
                    ic::encode_fs_volume_information(creation_time, 0xCAFE_BABE, "smb-server")
                }
                ic::FS_SIZE_INFORMATION => {
                    // 1 PiB free pseudo-volume, 4 KiB cluster.
                    ic::encode_fs_size_information(
                        1u64 << 40, // total
                        1u64 << 39, // free
                        1,          // sectors per cluster
                        4096,       // bytes per sector
                    )
                }
                ic::FS_DEVICE_INFORMATION => {
                    ic::encode_fs_device_information(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE)
                }
                ic::FS_ATTRIBUTE_INFORMATION => {
                    // `FILE_NAMED_STREAMS` is advertised only when the
                    // backend actually honours `SmbPath::stream_name()` —
                    // claiming it otherwise would make macOS attempt
                    // stream-backed xattr writes against a backend that
                    // silently drops them onto the primary data stream
                    // (docs/SMB_DEFECTS.md S2/S10 in the prosopon consumer).
                    let backend = {
                        let tree = tree_arc.read().await;
                        tree.share.backend.clone()
                    };
                    let mut attrs = FILE_CASE_SENSITIVE_SEARCH
                        | FILE_CASE_PRESERVED_NAMES
                        | FILE_UNICODE_ON_DISK
                        | FILE_PERSISTENT_ACLS
                        | FILE_FILE_COMPRESSION
                        | FILE_SUPPORTS_HARD_LINKS
                        | FILE_SUPPORTS_EXTENDED_ATTRIBUTES;
                    if backend.capabilities().supports_named_streams {
                        attrs |= FILE_NAMED_STREAMS;
                    }
                    ic::encode_fs_attribute_information(attrs, 255, "NTFS")
                }
                ic::FS_FULL_SIZE_INFORMATION => {
                    ic::encode_fs_full_size_information(1u64 << 40, 1u64 << 39, 1u64 << 39, 1, 4096)
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::Security => ic::encode_minimal_security_descriptor(),
        InfoType::Quota => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    if buf.len() as u32 > req.output_buffer_length {
        return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }

    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out)
        .expect("QUERY_INFO response encodes");
    HandlerResponse::ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::{Connection, Session, TreeConnect};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{HeaderTail, Smb2Header};
    use crate::proto::messages::{CreateRequest, CreateResponse, FileId};
    use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn test_server() -> Arc<ServerState> {
        let cfg = ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_string(),
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: Uuid::nil(),
        };
        let users = ServerUsers {
            table: tokio::sync::RwLock::new(HashMap::new()),
        };
        Arc::new(ServerState::new(cfg, users, vec![]))
    }

    async fn test_conn_with_tree(backend: MemFsBackend) -> (Arc<Connection>, u64, u32) {
        let conn = Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024));
        let session = Session::new(1, Identity::Anonymous, [0; 16], [0; 16], false, None);
        let session = Arc::new(tokio::sync::RwLock::new(session));
        let share = ShareBindings::new(
            "share".to_string(),
            Arc::new(backend),
            ShareMode::Public,
            HashMap::new(),
            false,
        );
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            1,
            share,
            crate::builder::Access::ReadWrite,
        )));
        {
            let sess = session.read().await;
            sess.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1)
    }

    fn header(
        session_id: u64,
        tree_id: u32,
        message_id: u64,
        command: crate::proto::header::Command,
    ) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    /// Opens the share root via a real CREATE and returns the `FileId` from
    /// the response — QUERY_INFO needs a live `Open` to attach to.
    async fn open_root(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
    ) -> FileId {
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0008_0000,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1,       // FILE_OPEN
            create_options: 0x0000_0001, // FILE_DIRECTORY_FILE
            name_offset: 0x78,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: vec![],
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        let hdr = header(
            session_id,
            tree_id,
            1,
            crate::proto::header::Command::Create,
        );
        let resp = crate::handlers::create::handle(server, conn, &hdr, &body).await;
        assert_eq!(
            resp.status,
            ntstatus::STATUS_SUCCESS,
            "setup: open the share root"
        );
        CreateResponse::parse(&resp.body).unwrap().file_id
    }

    fn fs_attribute_query(file_id: FileId) -> Vec<u8> {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::FileSystem as u8,
            file_information_class: ic::FS_ATTRIBUTE_INFORMATION,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        body
    }

    #[tokio::test]
    async fn fs_attribute_information_advertises_named_streams_when_the_backend_supports_them() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;
        let hdr = header(
            session_id,
            tree_id,
            2,
            crate::proto::header::Command::QueryInfo,
        );

        let resp = handle(&server, &conn, &hdr, &fs_attribute_query(file_id)).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let qresp = QueryInfoResponse::parse(&resp.body).unwrap();
        let attrs = u32::from_le_bytes(qresp.buffer[0..4].try_into().unwrap());
        assert_ne!(
            attrs & FILE_NAMED_STREAMS,
            0,
            "MemFsBackend implements streams — FILE_NAMED_STREAMS must be advertised"
        );
    }
}

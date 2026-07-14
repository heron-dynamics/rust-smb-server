//! CREATE handler — open or create a file/directory and allocate a FileId.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CreateRequest, CreateResponse};
use tracing::{debug, warn};

use crate::backend::{OpenIntent, OpenOptions};
use crate::builder::Access;
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

// MS-SMB2 §2.2.13 access mask flags
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAX_ALLOWED: u32 = 0x0200_0000;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 §2.2.14)
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CreateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let tree = tree_arc.read().await;
    let granted = tree.granted_access;
    let backend = tree.share.backend.clone();
    drop(tree);

    // Decode path.
    let units = match utf16le_to_units(&req.name) {
        Some(u) => u,
        None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let path = match SmbPath::from_utf16(&units) {
        Ok(p) => p,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };

    // Translate disposition.
    let intent = match req.create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        FILE_OPEN => OpenIntent::Open,
        FILE_CREATE => OpenIntent::Create,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    // Translate desired access into read/write hints.
    let want_read = req.desired_access
        & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_ALL | MAX_ALLOWED)
        != 0;
    let want_write = req.desired_access
        & (FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | GENERIC_WRITE
            | GENERIC_ALL
            | MAX_ALLOWED)
        != 0;

    // Reject writes on a read-only tree.
    if want_write && !granted.allows_write() {
        warn!(path = %path, "write open on read-only tree");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    // Disposition that creates: requires write permission.
    if !granted.allows_write()
        && matches!(
            intent,
            OpenIntent::Create
                | OpenIntent::OpenOrCreate
                | OpenIntent::OverwriteOrCreate
                | OpenIntent::Truncate
        )
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let directory = req.create_options & FILE_DIRECTORY_FILE != 0;
    let non_directory = req.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if directory && non_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // MS-SMB2 §2.2.13: FILE_DIRECTORY_FILE is valid only paired with
    // FILE_CREATE, FILE_OPEN_IF, or FILE_OPEN — never with a disposition
    // that overwrites or truncates. Validated here, in the fork's own
    // handler, before any backend is called; `smb.rs`'s adapter does not
    // duplicate this check (`docs/PLAN_smb_round_two.md` Step 2, Stage 1).
    if directory && matches!(intent, OpenIntent::OverwriteOrCreate | OpenIntent::Truncate) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let delete_on_close = req.create_options & FILE_DELETE_ON_CLOSE != 0;

    let opts = OpenOptions {
        read: want_read || !want_write,
        write: want_write,
        intent,
        directory,
        non_directory,
        delete_on_close,
    };

    let handle = match backend.open(&path, opts).await {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Stat for the response.
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Allocate FileId, register Open.
    let tree = tree_arc.write().await;
    let file_id = tree.alloc_file_id();
    let path_for_trace = path.display_backslash();
    let open = Open::new(
        file_id,
        handle,
        if want_write { granted } else { Access::Read },
        path,
        info.is_directory,
        delete_on_close,
    );
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens.write().await.insert(file_id, open_arc);
    drop(tree);

    if server.trace_sink.is_some() {
        let contexts = crate::proto::messages::CreateContext::parse_chain(&req.create_contexts)
            .map(|chain| {
                chain
                    .into_iter()
                    .map(|c| crate::trace::CreateContextInfo {
                        name: c.name,
                        data_len: c.data.len() as u32,
                    })
                    .collect()
            })
            .unwrap_or_default();
        crate::trace::record(
            &server.trace_sink,
            crate::trace::current_trace_key(),
            crate::trace::TraceEvent::Create {
                path: path_for_trace,
                create_options: req.create_options,
                directory,
                non_directory,
                create_disposition: req.create_disposition,
                desired_access: req.desired_access,
                file_id: [
                    file_id.persistent.to_le_bytes(),
                    file_id.volatile.to_le_bytes(),
                ]
                .concat()
                .try_into()
                .expect("FileId is 16 bytes"),
                contexts,
            },
        );
    }

    let create_action = match intent {
        OpenIntent::Create => FILE_CREATED,
        OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate => FILE_OPENED,
        OpenIntent::Open | OpenIntent::Truncate => FILE_OPENED,
    };
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: vec![],
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

// ---------------------------------------------------------------------------
// Stage 1 handler tests (`docs/PLAN_smb_round_two.md` Step 2)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::{Session, TreeConnect};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::HeaderTail;
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

    /// A connection with one anonymous session and one tree bound to a
    /// fresh `MemFsBackend`. Returns `(conn, session_id, tree_id)`.
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
            Access::ReadWrite,
        )));
        {
            let sess = session.read().await;
            sess.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1)
    }

    fn create_request_bytes(name: &str, create_options: u32, create_disposition: u32) -> Vec<u8> {
        let name_u16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition,
            create_options,
            name_offset: 0x78,
            name_length: name_u16.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: name_u16,
            create_contexts: vec![],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        buf
    }

    fn create_header(session_id: u64, tree_id: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: crate::proto::header::Command::Create,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 1,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    #[tokio::test]
    async fn both_directory_constraint_flags_set_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let body = create_request_bytes(
            "x",
            FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE,
            FILE_OPEN,
        );

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn directory_flag_with_overwrite_if_disposition_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        // FILE_SUPERSEDE (0) and FILE_OVERWRITE_IF (5) both fold to
        // `OpenIntent::OverwriteOrCreate` — both must be rejected paired
        // with FILE_DIRECTORY_FILE.
        for disposition in [FILE_SUPERSEDE, FILE_OVERWRITE_IF] {
            let body = create_request_bytes("x", FILE_DIRECTORY_FILE, disposition);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(
                resp.status,
                ntstatus::STATUS_INVALID_PARAMETER,
                "disposition {disposition:#x}"
            );
        }
    }

    #[tokio::test]
    async fn directory_flag_with_overwrite_disposition_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let body = create_request_bytes("x", FILE_DIRECTORY_FILE, FILE_OVERWRITE);

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn directory_flag_with_creating_dispositions_survives_stage1() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        // FILE_CREATE, FILE_OPEN_IF are two of the three dispositions
        // Stage 1 permits paired with FILE_DIRECTORY_FILE — each must
        // reach the backend (a fresh MemFsBackend has no "newdir", so both
        // creating dispositions succeed by creating it).
        for (disposition, name) in [
            (FILE_CREATE, "newdir_create"),
            (FILE_OPEN_IF, "newdir_openif"),
        ] {
            let body = create_request_bytes(name, FILE_DIRECTORY_FILE, disposition);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(
                resp.status,
                ntstatus::STATUS_SUCCESS,
                "disposition {disposition:#x} must survive Stage 1 and reach the backend"
            );
        }
    }

    #[tokio::test]
    async fn directory_flag_with_open_disposition_survives_stage1() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        // FILE_OPEN is the third disposition Stage 1 permits paired with
        // FILE_DIRECTORY_FILE — but FILE_OPEN requires the target to
        // already exist, so create it first (via FILE_CREATE) and only
        // then exercise FILE_OPEN against it.
        let create_body = create_request_bytes("existing_dir", FILE_DIRECTORY_FILE, FILE_CREATE);
        let create_resp = handle(&server, &conn, &hdr, &create_body).await;
        assert_eq!(
            create_resp.status,
            ntstatus::STATUS_SUCCESS,
            "setup: create the directory"
        );

        let open_body = create_request_bytes("existing_dir", FILE_DIRECTORY_FILE, FILE_OPEN);
        let open_resp = handle(&server, &conn, &hdr, &open_body).await;
        assert_eq!(
            open_resp.status,
            ntstatus::STATUS_SUCCESS,
            "FILE_DIRECTORY_FILE + FILE_OPEN must survive Stage 1 and reach the backend"
        );
    }
}

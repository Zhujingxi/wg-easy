//! Small audited Win32 operations that cannot be expressed by the safe daemon.

use std::{
    ffi::OsStr,
    io,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, RevertToSelf, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    System::{
        Pipes::ImpersonateNamedPipeClient,
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: Token owns this OpenThreadToken handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Impersonation;
impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: this guard never leaves the synchronous impersonating thread.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing privileged work under the client's identity is unsafe.
            std::process::abort();
        }
    }
}

/// The pipe server must set PIPE_REJECT_REMOTE_CLIENTS when creating its pipe.
/// Call after reading a request so Win32 has a client security context.
pub fn pipe_owner(pipe: &impl AsRawHandle) -> io::Result<String> {
    // SAFETY: the caller retains the pipe for this synchronous operation.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle() as HANDLE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Impersonation;
    let mut handle = ptr::null_mut();
    // SAFETY: handle points to writable storage, and the current thread is impersonating.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(handle);
    let mut needed = 0;
    // SAFETY: a null buffer with size zero asks Windows for the required length.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Err(io::Error::other("Invalid client token size"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is aligned for TOKEN_USER and large enough for needed bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query initializes TOKEN_USER at the buffer start.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = ptr::null_mut();
    // SAFETY: the SID lives in buffer through this call; Windows allocates the output.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        // SAFETY: successful conversion returns a null-terminated SID string.
        let mut length = 0;
        while *sid.add(length) != 0 {
            length += 1;
        }
        let result =
            String::from_utf16(std::slice::from_raw_parts(sid, length)).map_err(io::Error::other);
        LocalFree(sid.cast());
        result
    }
}

/// Atomically publishes a file in the same volume and waits for the rename to persist.
pub fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide(source.as_os_str());
    let destination = wide(destination.as_os_str());
    // SAFETY: both inputs are null-terminated UTF-16 paths, valid for this call.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ))
    } else {
        Ok(())
    }
}

/// Creates a local-only service pipe. The client verifies its server PID with SCM.
pub fn create_pipe(first: bool) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    };
    let sddl = wide(OsStr::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"));
    let mut descriptor = ptr::null_mut();
    // SAFETY: Windows allocates the descriptor; the UTF-16 input remains alive.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: the descriptor and attributes are valid until pipe creation returns.
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                r"\\.\pipe\wireguardeasy",
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    // SAFETY: ConvertStringSecurityDescriptor allocates this buffer with LocalAlloc.
    unsafe {
        LocalFree(descriptor);
    }
    result
}

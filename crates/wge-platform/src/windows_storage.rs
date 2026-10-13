//! Private service directories, including when the installer has not created them.

use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        },
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsWellKnownSid, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
    },
};

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: both descriptor constructors below allocate with LocalAlloc.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: Handle owns the successful CreateFileW result.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Service storage must be a private directory owned by SYSTEM or Administrators",
    )
}

fn descriptor(sddl: &str) -> io::Result<Descriptor> {
    let sddl: Vec<u16> = OsStr::new(sddl).encode_wide().chain(Some(0)).collect();
    let mut result = ptr::null_mut();
    // SAFETY: the input is terminated UTF-16; the output receives an owned descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut result,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Descriptor(result))
}

fn validate(descriptor: &Descriptor) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: Descriptor contains a Windows-validated security descriptor for this call.
    unsafe {
        if GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) == 0
            || owner.is_null()
            || (IsWellKnownSid(owner, WinLocalSystemSid) == 0
                && IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0)
            || GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) == 0
            || control & SE_DACL_PROTECTED == 0
            || GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) == 0
            || present == 0
            || acl.is_null()
            || (*acl).AceCount != 2
        {
            return Err(denied());
        }
        let mut system = false;
        let mut administrators = false;
        for index in 0..2 {
            let mut ace = ptr::null_mut();
            if GetAce(acl, index, &mut ace) == 0 {
                return Err(denied());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            // ACCESS_ALLOWED_ACE_TYPE is zero; object and callback ACEs are rejected.
            if header.AceType != 0
                || header.AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(denied());
            }
            let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            if ace.Mask != FILE_ALL_ACCESS {
                return Err(denied());
            }
            let sid = ptr::addr_of!(ace.SidStart).cast_mut().cast();
            if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                system = true;
            } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                administrators = true;
            } else {
                return Err(denied());
            }
        }
        if !system || !administrators {
            return Err(denied());
        }
    }
    Ok(())
}

/// Creates one directory with a protected DACL, then verifies it through a native handle.
/// The parent must already exist and be protected from replacement by ordinary users.
pub fn private_directory(path: &Path) -> io::Result<()> {
    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid storage path",
        ));
    }
    path.push(0);
    let security = descriptor("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    // SAFETY: the descriptor and terminated path stay alive through creation.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    // SAFETY: native path and flags are valid; OPEN_REPARSE_POINT avoids following a final link.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = Handle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the directory handle remains open and info is writable.
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let mut descriptor = ptr::null_mut();
    // SAFETY: valid open handle; Windows allocates a descriptor freed by Descriptor.
    let error = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    validate(&Descriptor(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_protected_service_permissions() {
        for owner in ["SY", "BA"] {
            let sddl = format!("O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            assert!(validate(&descriptor(&sddl).unwrap()).is_ok());
        }
        for sddl in [
            "O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)",
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;SY)",
            "O:WDD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        ] {
            assert!(validate(&descriptor(sddl).unwrap()).is_err(), "{sddl}");
        }
    }
}

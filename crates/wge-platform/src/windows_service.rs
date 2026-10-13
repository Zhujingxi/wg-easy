//! SCM's unsafe entry point is confined to the native platform crate.

use std::{
    ffi::OsString,
    io,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::oneshot::{self, Receiver};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

use crate::Error;

const SERVICE_NAME: &str = "wireguardeasy";
static RUN: OnceLock<fn(Receiver<()>)> = OnceLock::new();
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();
static FAILURE: Mutex<Option<String>> = Mutex::new(None);

/// Run on the process's main thread; the callback owns cleanup before it returns.
pub fn run_service(run: fn(Receiver<()>)) -> Result<(), Error> {
    RUN.set(run)
        .map_err(|_| io::Error::other("The Windows service dispatcher was already started"))?;
    service_dispatcher::start(SERVICE_NAME, service_main_ffi)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(error) = FAILURE
        .lock()
        .map_err(|_| io::Error::other("Windows service failure lock was poisoned"))?
        .take()
    {
        return Err(io::Error::other(error).into());
    }
    Ok(())
}

define_windows_service!(service_main_ffi, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = dispatch() {
        if let Some(handle) = STATUS.get() {
            let _ = handle.set_service_status(status(ServiceState::Stopped, 1));
        }
        if let Ok(mut failure) = FAILURE.lock() {
            *failure = Some(error.to_string());
        }
    }
}

fn dispatch() -> Result<(), Error> {
    let (stop, stopped) = oneshot::channel();
    let mut stop = Some(stop);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(handle) = STATUS.get() {
                let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
            }
            if let Some(stop) = stop.take() {
                let _ = stop.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|error| io::Error::other(error.to_string()))?;
    STATUS.set(handle).map_err(|_| {
        io::Error::other("The Windows service status handle was already registered")
    })?;
    handle
        .set_service_status(status(ServiceState::Running, 0))
        .map_err(|error| io::Error::other(error.to_string()))?;
    let run = RUN
        .get()
        .ok_or_else(|| io::Error::other("The Windows service callback was not initialized"))?;
    // The callback consumes the receiver; no channel state is reused after a panic.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(stopped)))
        .map_err(|_| io::Error::other("The Windows service stopped unexpectedly"))?;
    handle
        .set_service_status(status(ServiceState::Stopped, 0))
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

fn status(state: ServiceState, exit_code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: u32::from(state == ServiceState::StopPending),
        wait_hint: if state == ServiceState::StopPending {
            Duration::from_secs(30)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_accepted_only_while_running() {
        assert!(
            status(ServiceState::Running, 0)
                .controls_accepted
                .contains(ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)
        );
        assert!(
            status(ServiceState::StopPending, 0)
                .controls_accepted
                .is_empty()
        );
        assert_eq!(
            status(ServiceState::Stopped, 1).exit_code,
            ServiceExitCode::Win32(1)
        );
    }
}

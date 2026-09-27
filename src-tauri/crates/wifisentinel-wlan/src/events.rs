// wifisentinel-wlan/src/events.rs
// WLAN notification subscription for real-time AP/connection events.

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use windows::{
    Win32::NetworkManagement::WiFi::{
        WlanCloseHandle, WlanOpenHandle, WlanRegisterNotification,
        L2_NOTIFICATION_DATA, WLAN_NOTIFICATION_SOURCES,
        WLAN_NOTIFICATION_SOURCE_ACM, WLAN_NOTIFICATION_SOURCE_MSM,
        wlan_notification_acm_scan_complete,
        wlan_notification_acm_scan_fail,
        wlan_notification_acm_network_available,
        wlan_notification_acm_disconnected,
        wlan_notification_acm_connection_complete,
    },
    Win32::Foundation::HANDLE,
};

use wifisentinel_core::Error;

/// Events emitted by the WLAN notification subsystem.
#[derive(Debug, Clone)]
pub enum WlanEvent {
    ScanComplete,
    ScanFailed,
    NetworkAvailable { ssid: Option<String> },
    Disconnected { ssid: Option<String> },
    ConnectionComplete { ssid: Option<String> },
    Other { code: u32 },
}

/// Subscribes to Windows WLAN notifications and forwards them as events.
pub struct WlanEventStream {
    sender: Arc<broadcast::Sender<WlanEvent>>,
    _handle: Arc<HandleGuard>,
}

impl WlanEventStream {
    /// Initialize the event stream and register WLAN notifications.
    pub fn start() -> Result<(Self, broadcast::Receiver<WlanEvent>), Error> {
        let (tx, rx) = broadcast::channel(256);
        let tx = Arc::new(tx);

        unsafe {
            let mut client_handle = HANDLE::default();
            let mut negotiated_version: u32 = 0;

            let err = WlanOpenHandle(2, None, &mut negotiated_version, &mut client_handle);
            if err != 0 {
                return Err(Error::WlanApi {
                    message: "WlanOpenHandle for events failed".into(),
                    code: err,
                });
            }

            // Box the sender to pass as context pointer.
            let tx_clone = Arc::clone(&tx);
            let ctx = Box::into_raw(Box::new(tx_clone)) as *mut std::ffi::c_void;

            let err = WlanRegisterNotification(
                client_handle,
                WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM,
                true,
                Some(notification_callback),
                Some(ctx),
                None,
                None,
            );

            if err != 0 {
                warn!("WlanRegisterNotification failed: {}", err);
                // Non-fatal; continue without events.
            } else {
                info!("WLAN notification subscription active");
            }

            let guard = Arc::new(HandleGuard(client_handle, ctx));

            Ok((Self { sender: tx, _handle: guard }, rx))
        }
    }

    pub fn subscriber(&self) -> broadcast::Receiver<WlanEvent> {
        self.sender.subscribe()
    }
}

unsafe extern "system" fn notification_callback(
    data: *mut L2_NOTIFICATION_DATA,
    context: *mut std::ffi::c_void,
) {
    if data.is_null() || context.is_null() {
        return;
    }

    let notification = &*data;
    let tx = &*(context as *const Arc<broadcast::Sender<WlanEvent>>);

    let event = match notification.NotificationCode {
        x if x == wlan_notification_acm_scan_complete.0 as u32 => WlanEvent::ScanComplete,
        x if x == wlan_notification_acm_scan_fail.0 as u32 => WlanEvent::ScanFailed,
        x if x == wlan_notification_acm_network_available.0 as u32 => {
            WlanEvent::NetworkAvailable { ssid: None }
        }
        x if x == wlan_notification_acm_disconnected.0 as u32 => {
            WlanEvent::Disconnected { ssid: None }
        }
        x if x == wlan_notification_acm_connection_complete.0 as u32 => {
            WlanEvent::ConnectionComplete { ssid: None }
        }
        other => WlanEvent::Other { code: other },
    };

    debug!("WLAN event: {:?}", event);

    // Ignore send errors (no subscribers active).
    let _ = tx.send(event);
}

struct HandleGuard(HANDLE, *mut std::ffi::c_void);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                // Deregister notification before closing handle.
                let _ = WlanRegisterNotification(
                    self.0,
                    WLAN_NOTIFICATION_SOURCES(0), // WLAN_NOTIFICATION_SOURCE_NONE
                    false,
                    None,
                    None,
                    None,
                    None,
                );
                WlanCloseHandle(self.0, None);
            }
            // Drop the context Box.
            if !self.1.is_null() {
                let _ = Box::from_raw(self.1 as *mut Arc<broadcast::Sender<WlanEvent>>);
            }
        }
    }
}

// Safety: the HANDLE and context pointer are only accessed from the callback
// which Windows guarantees happens before the handle is closed.
unsafe impl Send for HandleGuard {}
unsafe impl Sync for HandleGuard {}

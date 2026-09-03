//! Optional libcurl URL redirect for the local LunaGC dispatch.
//!
//! Some 7.0 client requests do not pass through the Unity HTTP or WinHTTP
//! hooks.  When libcurl is exposed as a loaded DLL, redirect only the dispatch
//! URLs passed to CURLOPT_URL to the local HTTP listener.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;

use anyhow::Result;
use ilhook::x64::Registers;
use lazy_static::lazy_static;
use windows::{
    core::{s, PCSTR},
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

use super::{MhyContext, MhyModule, ModuleType};

const CURL_URL: u32 = 10002;
const DISPATCH_HOSTS: [&str; 2] = [
    "dispatchcnglobal.yuanshen.com",
    "dispatchosglobal.yuanshen.com",
];
const LOCAL_BASE: &str = "http://127.0.0.1:8088";

lazy_static! {
    // curl_easy_setopt copies CURLOPT_URL strings during the call, but the hook
    // needs the temporary CString to stay alive until the original function
    // resumes. Keep a bounded per-handle store for that short-lived data.
    static ref URL_STORAGE: Mutex<HashMap<usize, Vec<CString>>> = Mutex::new(HashMap::new());
}

pub struct Curl;

impl MhyModule for MhyContext<Curl> {
    unsafe fn init(&mut self) -> Result<()> {
        // Do not load a new curl DLL here. We only hook one that the game has
        // already loaded; otherwise we could accidentally hook an unrelated
        // library that the process never uses.
        const CANDIDATES: [&PCSTR; 4] = [
            &s!("libcurl.dll"),
            &s!("libcurl-x64.dll"),
            &s!("libcurl-4.dll"),
            &s!("curl.dll"),
        ];

        for name in CANDIDATES {
            let Ok(module) = GetModuleHandleA(*name) else {
                continue;
            };

            let Some(addr) = GetProcAddress(module, s!("curl_easy_setopt")) else {
                continue;
            };

            crate::plog!("curl_easy_setopt: {:x} ({})", addr as usize, cstr_name(*name));
            self.interceptor.attach(addr as usize, on_curl_easy_setopt)?;
            return Ok(());
        }

        crate::plog!("curl_easy_setopt: no loaded libcurl export found; curl redirect disabled");
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> ModuleType {
        ModuleType::Curl
    }
}

fn cstr_name(name: PCSTR) -> String {
    unsafe { CStr::from_ptr(name.0 as *const i8).to_string_lossy().into_owned() }
}

fn redirect_url(url: &str) -> Option<String> {
    let without_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return None;
    };

    let (authority, path) = without_scheme
        .split_once('/')
        .map_or((without_scheme, ""), |(a, p)| (a, p));

    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .split(':')
        .next()
        .unwrap_or(authority);

    if !DISPATCH_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h)) {
        return None;
    }

    Some(if path.is_empty() {
        LOCAL_BASE.to_owned()
    } else {
        format!("{LOCAL_BASE}/{path}")
    })
}

/// curl_easy_setopt(easy, option, value, ...)
///
/// On Windows x64 the first three arguments are RCX/RDX/R8 even for the
/// variadic function. For CURLOPT_URL, rewrite only the value pointer and let
/// libcurl continue through its normal implementation.
unsafe extern "win64" fn on_curl_easy_setopt(reg: *mut Registers, _: usize) {
    let option = (*reg).rdx as u32;
    if option != CURL_URL {
        return;
    }

    let ptr = (*reg).r8 as *const i8;
    if ptr.is_null() {
        return;
    }

    let Ok(original) = CStr::from_ptr(ptr).to_str() else {
        return;
    };

    let Some(rewritten) = redirect_url(original) else {
        return;
    };

    let Ok(c_url) = CString::new(rewritten.clone()) else {
        return;
    };

    let easy = (*reg).rcx as usize;
    let replacement_ptr = c_url.as_ptr() as u64;

    if let Ok(mut storage) = URL_STORAGE.lock() {
        let entry = storage.entry(easy).or_default();
        entry.push(c_url);
        if entry.len() > 32 {
            entry.drain(..entry.len() - 32);
        }
    } else {
        return;
    }

    crate::plog!("[curl] Redirect: {original} -> {rewritten}");
    (*reg).r8 = replacement_ptr;
}

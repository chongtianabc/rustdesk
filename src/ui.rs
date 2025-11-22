use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
        *cm::HIDE_CM.lock().unwrap() = crate::ipc::get_config("hide_cm")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "true";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    let hide_cm = *cm::HIDE_CM.lock().unwrap();
    if !args.is_empty() && args[0] == "--cm" && hide_cm {
        // run_app calls expand(show) + run_loop, we use collapse(hide) + run_loop instead to create a hidden window
        frame.collapse(true);
        frame.run_loop();
        return;
    }
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn is_incoming_only(&self) -> bool {
        hbb_common::config::is_incoming_only()
    }

    pub fn is_outgoing_only(&self) -> bool {
        hbb_common::config::is_outgoing_only()
    }

    pub fn is_custom_client(&self) -> bool {
        crate::common::is_custom_client()
    }

    pub fn is_disable_settings(&self) -> bool {
        hbb_common::config::is_disable_settings()
    }

    pub fn is_disable_account(&self) -> bool {
        hbb_common::config::is_disable_account()
    }

    pub fn is_disable_installation(&self) -> bool {
        hbb_common::config::is_disable_installation()
    }

    pub fn is_disable_ab(&self) -> bool {
        hbb_common::config::is_disable_ab()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn verify_login(&self, raw: String, id: String) -> bool {
        crate::verify_login(&raw, &id)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }

    fn is_option_fixed(&self, key: String) -> bool {
        crate::ui_interface::is_option_fixed(&key)
    }

    fn get_builtin_option(&self, key: String) -> String {
        crate::ui_interface::get_builtin_option(&key)
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn is_custom_client();
        fn is_outgoing_only();
        fn is_incoming_only();
        fn is_disable_settings();
        fn is_disable_account();
        fn is_disable_installation();
        fn is_disable_ab();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
        fn verify_login(String, String);
        fn is_option_fixed(String);
        fn get_builtin_option(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}

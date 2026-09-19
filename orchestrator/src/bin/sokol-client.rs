use aya::{
    maps::{lpm_trie::Key, Array, LpmTrie},
    programs::{xdp::XdpLinkId, Xdp, XdpFlags},
    Bpf, Pod,
};
use axum::{
    extract::{Json, State},
    response::sse::Event,
    response::{Html, Sse},
    routing::{get, post},
    Router,
};
use futures_util::stream::{self, Stream};
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

#[repr(transparent)]
#[derive(Copy, Clone)]
struct BpfPacketStats(common::PacketStats);

unsafe impl Pod for BpfPacketStats {}

#[derive(Clone, Serialize, Deserialize)]
struct ClientData {
    name: String,
    token: String,
    protection_active: bool,
    packets_inspected: u64,
    attacks_blocked: u64,
    bandwidth_mbps: f64,
    threat_level: String,
    whitelist: Vec<String>,
    blacklist: Vec<String>,
}

struct EbpfManager {
    ebpf: Bpf,
    xdp_link: Option<XdpLinkId>,
    iface: String,
}

#[derive(Clone)]
struct AppState {
    client: Arc<Mutex<ClientData>>,
    ebpf_mgr: Arc<Mutex<EbpfManager>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("[*] Запуск SOKOL-CLIENT Kernel Cabinet на http://127.0.0.1:3001");

    let iface = std::env::var("SOKOL_IFACE").unwrap_or_else(|_| "eth0".into());

    #[cfg(debug_assertions)]
    let mut ebpf = Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/debug/ebpf-probe"
    )))?;

    #[cfg(not(debug_assertions))]
    let mut ebpf = Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/ebpf-probe"
    )))?;

    let program: &mut Xdp = ebpf.program_mut("sentinel_vfr_filter").unwrap().try_into()?;
    program.load()?;
    let link_id = program.attach(&iface, XdpFlags::default())?;

    let client_data = ClientData {
        name: format!("Client Node [{}]", iface),
        token: "sokol-secure-token-01".to_string(),
        protection_active: true,
        packets_inspected: 0,
        attacks_blocked: 0,
        bandwidth_mbps: 128.4,
        threat_level: "LOW".to_string(),
        whitelist: vec![],
        blacklist: vec![],
    };

    let state = AppState {
        client: Arc::new(Mutex::new(client_data)),
        ebpf_mgr: Arc::new(Mutex::new(EbpfManager {
            ebpf,
            xdp_link: Some(link_id),
            iface,
        })),
    };

    let app = Router::new()
        .route("/", get(client_dashboard_handler))
        .route("/metrics/stream", get(client_metrics_stream))
        .route("/api/client/data", post(client_get_data))
        .route("/api/client/toggle", post(client_toggle_protection))
        .route("/api/client/list/update", post(client_update_list))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn client_dashboard_handler() -> Html<&'static str> {
    Html(CLIENT_HTML)
}

#[derive(Deserialize)]
struct ClientAuthReq {
    token: String,
}

async fn client_get_data(
    State(state): State<AppState>,
    Json(req): Json<ClientAuthReq>,
) -> Json<serde_json::Value> {
    let client = state.client.lock().await;
    if client.token == req.token {
        Json(serde_json::json!({ "success": true, "client": *client, "logs": [] }))
    } else {
        Json(serde_json::json!({ "success": false, "error": "Unauthorized" }))
    }
}

async fn client_toggle_protection(
    State(state): State<AppState>,
    Json(req): Json<ClientAuthReq>,
) -> Json<serde_json::Value> {
    let mut client = state.client.lock().await;
    if client.token != req.token {
        return Json(serde_json::json!({ "success": false, "error": "Unauthorized" }));
    }

    let mut mgr = state.ebpf_mgr.lock().await;
    client.protection_active = !client.protection_active;

    let iface = mgr.iface.clone();

    if client.protection_active {
        if let Some(prog) = mgr.ebpf.program_mut("sentinel_vfr_filter") {
            if let Ok(xdp_prog) = TryInto::<&mut Xdp>::try_into(prog) {
                if let Ok(id) = xdp_prog.attach(&iface, XdpFlags::default()) {
                    mgr.xdp_link = Some(id);
                }
            }
        }
    } else if let Some(link_id) = mgr.xdp_link.take() {
        if let Some(prog) = mgr.ebpf.program_mut("sentinel_vfr_filter") {
            if let Ok(xdp_prog) = TryInto::<&mut Xdp>::try_into(prog) {
                let _ = xdp_prog.detach(link_id);
            }
        }
    }

    Json(serde_json::json!({ "success": true, "protection_active": client.protection_active }))
}

#[derive(Deserialize)]
struct ListUpdateReq {
    token: String,
    list_type: String,
    ip: String,
    action: String,
}

async fn client_update_list(
    State(state): State<AppState>,
    Json(req): Json<ListUpdateReq>,
) -> Json<serde_json::Value> {
    let mut client = state.client.lock().await;
    if client.token != req.token {
        return Json(serde_json::json!({ "success": false, "error": "Unauthorized" }));
    }

    let mut mgr = state.ebpf_mgr.lock().await;
    let map_name = if req.list_type == "whitelist" { "WHITELIST_V4" } else { "BLOCKLIST_V4" };

    if let Ok(addr) = req.ip.parse::<Ipv4Addr>() {
        let key = Key::new(32, addr.octets());

        if let Some(map_data) = mgr.ebpf.map_mut(map_name) {
            if let Ok(mut trie) = LpmTrie::<_, [u8; 4], u32>::try_from(map_data) {
                if req.action == "add" {
                    let _ = trie.insert(&key, 1, 0);
                } else {
                    let _ = trie.remove(&key);
                }
            }
        }

        if req.action == "add" {
            if req.list_type == "whitelist" {
                if !client.whitelist.contains(&req.ip) {
                    client.whitelist.push(req.ip.clone());
                }
            } else if !client.blacklist.contains(&req.ip) {
                client.blacklist.push(req.ip.clone());
            }
        } else if req.list_type == "whitelist" {
            client.whitelist.retain(|x| x != &req.ip);
        } else {
            client.blacklist.retain(|x| x != &req.ip);
        }
    }

    Json(serde_json::json!({
        "success": true,
        "whitelist": client.whitelist,
        "blacklist": client.blacklist
    }))
}

async fn client_metrics_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let initial_state = (state, 0u64);

    let stream = stream::unfold(initial_state, |(state, last_total)| async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;

        let mut total_pps = 0;
        let mut current_total = last_total;
        let mut total_dropped = 0;

        {
            let mut mgr = state.ebpf_mgr.lock().await;
            if let Some(map_data) = mgr.ebpf.map_mut("STATS") {
                if let Ok(stats_map) = Array::<_, BpfPacketStats>::try_from(map_data) {
                    if let Ok(stats) = stats_map.get(&0u32, 0) {
                        current_total = stats.0.rx_packets;
                        total_pps = current_total.saturating_sub(last_total);
                        total_dropped = stats.0.dropped_packets;
                    }
                }
            }
        }

        {
            let mut client = state.client.lock().await;
            client.packets_inspected = current_total;
            client.attacks_blocked = total_dropped;
        }

        let payload = format!(
            r#"{{"packets_per_sec": {}, "packets_inspected": {}, "attacks_blocked": {}, "time": "{}"}}"#,
            total_pps,
            current_total,
            total_dropped,
            chrono::Utc::now().format("%H:%M:%S")
        );

        Some((Ok(Event::default().data(payload)), (state, current_total)))
    });

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

const CLIENT_HTML: &str = r###"
<!DOCTYPE html>
<html lang="uk" class="dark">
<head>
    <meta charset="UTF-8">
    <title>Sokol-Core // Клієнтський Кабінет</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-zinc-950 text-zinc-100 font-mono antialiased min-h-screen p-6 flex flex-col items-center">
    <div id="client-login" class="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-xl p-8 text-center shadow-2xl mt-20">
        <h2 class="text-lg font-bold text-cyan-400 mb-1">ЯДРО КАБІНЕТУ КЛІЄНТА</h2>
        <p class="text-xs text-zinc-500 mb-6">Введіть токен доступу (за замовчуванням: sokol-secure-token-01)</p>
        <input type="text" id="client-token-input" class="w-full bg-zinc-950 border border-zinc-700 rounded p-2 text-sm text-zinc-300 mb-4 text-center focus:border-cyan-500 outline-none" value="sokol-secure-token-01">
        <button onclick="clientLogin()" class="w-full bg-cyan-600/20 border border-cyan-500/50 text-cyan-400 font-bold py-2 rounded text-sm hover:bg-cyan-600/30 transition">ПІДКЛЮЧИТИСЬ ДО XDP</button>
    </div>

    <div id="client-dashboard" class="hidden w-full max-w-5xl space-y-6">
        <div class="flex justify-between items-center bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div>
                <h1 id="client-title" class="text-base font-bold text-cyan-400">СЕРВІС</h1>
                <p class="text-xs text-zinc-500">Керування правилами фільтрації eBPF в реальному часі</p>
            </div>
            <div class="flex items-center gap-4">
                <div class="text-xs bg-zinc-950 border border-zinc-800 px-3 py-1.5 rounded">XDP PPS: <span id="live-pps" class="text-emerald-400 font-bold">0</span></div>
                <button onclick="toggleProtection()" id="prot-btn" class="text-xs px-3 py-1.5 rounded border transition bg-emerald-950/40 text-emerald-400 border-emerald-800">ЗАХИСТ: ВКЛ</button>
                <button onclick="logoutClient()" class="text-xs text-zinc-400 border border-zinc-700 px-3 py-1.5 rounded hover:bg-zinc-800 transition">ВИЙТИ</button>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                <div class="text-xs text-zinc-500 mb-1">Оброблено пакетів</div>
                <div id="m-packets" class="text-lg font-bold text-zinc-100">0</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                <div class="text-xs text-zinc-500 mb-1">Заблоковано атак</div>
                <div id="m-attacks" class="text-lg font-bold text-red-400">0</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                <div class="text-xs text-zinc-500 mb-1">Швидкість (Mbps)</div>
                <div id="m-bandwidth" class="text-lg font-bold text-cyan-400">128.4</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                <div class="text-xs text-zinc-500 mb-1">Статус ядра</div>
                <div id="m-threat" class="text-lg font-bold text-emerald-400">STABLE</div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-3">
                <h3 class="text-sm font-bold text-emerald-400">БІЛИЙ СПИСОК (WHITELIST) [eBPF MAP]</h3>
                <div class="flex gap-2">
                    <input type="text" id="white-ip" class="w-full bg-zinc-950 border border-zinc-700 rounded p-1.5 text-xs text-zinc-200 outline-none focus:border-emerald-500" placeholder="10.0.0.0">
                    <button onclick="updateList('whitelist', 'add')" class="bg-emerald-950 border border-emerald-700 text-emerald-400 px-3 py-1.5 text-xs rounded hover:bg-emerald-900 transition">Додати</button>
                </div>
                <ul id="whitelist-items" class="space-y-1.5 text-xs text-zinc-300 pt-2"></ul>
            </div>

            <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-3">
                <h3 class="text-sm font-bold text-red-400">ЧОРНИЙ СПИСОК (BLACKLIST) [eBPF MAP]</h3>
                <div class="flex gap-2">
                    <input type="text" id="black-ip" class="w-full bg-zinc-950 border border-zinc-700 rounded p-1.5 text-xs text-zinc-200 outline-none focus:border-red-500" placeholder="185.220.101.5">
                    <button onclick="updateList('blacklist', 'add')" class="bg-red-950 border border-red-700 text-red-400 px-3 py-1.5 text-xs rounded hover:bg-red-900 transition">Блокувати</button>
                </div>
                <ul id="blacklist-items" class="space-y-1.5 text-xs text-zinc-300 pt-2"></ul>
            </div>
        </div>
    </div>

    <script>
        let currentToken = localStorage.getItem('sokol_client_token') || '';
        if (currentToken) { document.getElementById('client-token-input').value = currentToken; clientLogin(); }

        async function clientLogin() {
            const token = document.getElementById('client-token-input').value.trim();
            if(!token) return;
            const res = await fetch('/api/client/data', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token}) });
            const data = await res.json();
            if (data.success) {
                currentToken = token;
                localStorage.setItem('sokol_client_token', token);
                document.getElementById('client-login').classList.add('hidden');
                document.getElementById('client-dashboard').classList.remove('hidden');
                document.getElementById('client-title').innerText = data.client.name;
                renderLists(data.client);
                initClientSSE();
            } else { alert('Невірний токен'); }
        }

        async function toggleProtection() {
            const res = await fetch('/api/client/toggle', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token: currentToken}) });
            const data = await res.json();
            if(data.success) {
                const btn = document.getElementById('prot-btn');
                if(data.protection_active) {
                    btn.className = "text-xs px-3 py-1.5 rounded border transition bg-emerald-950/40 text-emerald-400 border-emerald-800";
                    btn.innerText = "ЗАХИСТ: ВКЛ";
                } else {
                    btn.className = "text-xs px-3 py-1.5 rounded border transition bg-red-950/40 text-red-400 border-red-800";
                    btn.innerText = "ЗАХИСТ: ВИМК";
                }
            }
        }

        function initClientSSE() {
            const source = new EventSource("/metrics/stream");
            source.onmessage = function(e) {
                const data = JSON.parse(e.data);
                document.getElementById('live-pps').innerText = data.packets_per_sec.toLocaleString();
                if(data.packets_inspected !== undefined) {
                    document.getElementById('m-packets').innerText = data.packets_inspected.toLocaleString();
                }
                if(data.attacks_blocked !== undefined) {
                    document.getElementById('m-attacks').innerText = data.attacks_blocked.toLocaleString();
                }
            }
        }

        async function updateList(listType, action, ipVal = null) {
            const inputId = listType === 'whitelist' ? 'white-ip' : 'black-ip';
            const ip = ipVal || document.getElementById(inputId).value.trim();
            if (!ip) return;

            const res = await fetch('/api/client/list/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ token: currentToken, list_type: listType, ip, action })
            });
            const data = await res.json();
            if (data.success) {
                if(!ipVal) document.getElementById(inputId).value = '';
                renderLists({ whitelist: data.whitelist, blacklist: data.blacklist });
            }
        }

        function renderLists(client) {
            document.getElementById('whitelist-items').innerHTML = client.whitelist.length ? client.whitelist.map(ip => `<li class="flex justify-between items-center bg-zinc-950 p-2 rounded border border-zinc-800"><span>${ip}</span><button onclick="updateList('whitelist', 'remove', '${ip}')" class="text-red-400 hover:text-red-300 text-[10px] bg-red-950/40 border border-red-900/50 px-2 py-0.5 rounded">[видалити]</button></li>`).join('') : '<li class="text-zinc-600 text-xs italic">Список порожній</li>';
            
            document.getElementById('blacklist-items').innerHTML = client.blacklist.length ? client.blacklist.map(ip => `<li class="flex justify-between items-center bg-zinc-950 p-2 rounded border border-zinc-800"><span>${ip}</span><button onclick="updateList('blacklist', 'remove', '${ip}')" class="text-red-400 hover:text-red-300 text-[10px] bg-red-950/40 border border-red-900/50 px-2 py-0.5 rounded">[видалити]</button></li>`).join('') : '<li class="text-zinc-600 text-xs italic">Список порожній</li>';
        }

        function logoutClient() {
            localStorage.removeItem('sokol_client_token');
            location.reload();
        }
    </script>
</body>
</html>
"###;
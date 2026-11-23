// Connect to the local API and render the selected model.
const $ = (s) => document.querySelector(s);
const state = { view: "windows", viewVersion: 0, request: 0, samples: [], uploads: {}, result: null };

const VIEWS = {
  windows: {
    info: "CIC-MalMem-2022 · Độ chính xác: 99,98% sạch/độc và 86,7% cho 4 lớp.",
    title: "Phân tích tệp .exe",
    hint: "Tra mã băm trước. Nếu chưa có trong dữ liệu, tệp sạch đã được duyệt sẽ được đo RAM trên máy ảo Windows.",
    extension: ".exe",
    endpoint: "/api/analyze/windows",
  },
  android_ram: {
    info: "CCCS-CIC-AndMal-2020 · 14 loại · Độ chính xác: 73,0% với 21 chỉ số RAM.",
    title: "Phân tích tệp .apk",
    hint: "Tra mã băm trước. Nếu chưa có trong dữ liệu, APK sạch đã được duyệt sẽ được đo RAM trên máy ảo Android.",
    extension: ".apk",
    endpoint: "/api/analyze/android",
  },
  android_static: {
    info: "CCCS-CIC-AndMal-2020 · Đặc trưng tĩnh · Độ chính xác: 98,0%.",
    title: "Tra cứu mã băm",
    hint: "Nhận mọi loại tệp để tra mã băm. Mô hình dùng đặc trưng tĩnh đã lưu và chưa thể trích xuất đặc trưng của APK mới.",
  },
};

// Labels for common measurements.
const NICE = {
  "pslist.nproc": "Số tiến trình", "pslist.nppid": "Số tiến trình cha", "pslist.avg_threads": "Luồng trung bình mỗi tiến trình",
  "pslist.avg_handlers": "Handle trung bình mỗi tiến trình", "dlllist.ndlls": "Tổng số DLL đã nạp",
  "dlllist.avg_dlls_per_proc": "DLL trung bình mỗi tiến trình", "handles.nhandles": "Tổng số handle",
  "handles.avg_handles_per_proc": "Handle trung bình mỗi tiến trình", "handles.nfile": "Handle tới file",
  "handles.nevent": "Handle sự kiện", "handles.nkey": "Handle registry", "handles.nthread": "Handle luồng",
  "handles.nmutant": "Handle mutex", "handles.nsection": "Handle vùng nhớ", "handles.nsemaphore": "Handle semaphore",
  "handles.ntimer": "Handle bộ hẹn giờ", "handles.ndirectory": "Handle thư mục", "handles.ndesktop": "Handle desktop",
  "ldrmodules.not_in_load": "DLL không có trong danh sách nạp", "ldrmodules.not_in_init": "DLL không có trong danh sách khởi tạo",
  "ldrmodules.not_in_mem": "DLL không có trong danh sách bộ nhớ", "malfind.ninjections": "Số vùng nghi bị tiêm mã",
  "malfind.commitCharge": "Dung lượng vùng nghi bị tiêm mã", "malfind.protection": "Vùng vừa ghi vừa chạy được",
  "malfind.uniqueInjections": "Số lần tiêm mã khác nhau", "psxview.not_in_pslist": "Tiến trình giấu khỏi danh sách",
  "psxview.not_in_eprocess_pool": "Tiến trình không có trong EPROCESS pool", "psxview.not_in_csrss_handles": "Tiến trình giấu khỏi csrss",
  "modules.nmodules": "Số module nhân", "svcscan.nservices": "Số dịch vụ Windows", "svcscan.kernel_drivers": "Số driver nhân",
  "svcscan.fs_drivers": "Số driver hệ thống file", "svcscan.process_services": "Dịch vụ chạy riêng tiến trình",
  "svcscan.shared_process_services": "Dịch vụ dùng chung tiến trình", "svcscan.nactive": "Dịch vụ đang chạy",
  "callbacks.ncallbacks": "Số callback nhân", "callbacks.nanonymous": "Callback không rõ nguồn",
  "Memory_PssTotal": "Tổng RAM (PSS, KB)", "Memory_PssClean": "PSS sạch (KB)", "Memory_SharedDirty": "RAM chia sẻ đã ghi (KB)",
  "Memory_PrivateDirty": "RAM riêng đã ghi (KB)", "Memory_SharedClean": "RAM chia sẻ chưa ghi (KB)",
  "Memory_PrivateClean": "RAM riêng chưa ghi (KB)", "Memory_HeapSize": "Kích thước heap (KB)", "Memory_HeapAlloc": "Heap đã dùng (KB)",
  "Memory_HeapFree": "Heap còn trống (KB)", "Memory_Views": "Số thành phần giao diện", "Memory_ViewRootImpl": "Số cửa sổ",
  "Memory_AppContexts": "Số ngữ cảnh app", "Memory_Activities": "Số màn hình", "Memory_Assets": "Số tài nguyên đang mở",
  "Memory_LocalBinders": "Binder nội bộ", "Memory_ProxyBinders": "Binder tới dịch vụ khác", "Memory_ParcelMemory": "Dữ liệu gửi qua Binder (KB)",
  "Memory_ParcelCount": "Số gói dữ liệu Binder", "Memory_DeathRecipients": "Số lần theo dõi tiến trình khác",
  "Memory_OpenSSLSockets": "Kết nối mã hóa đang mở", "Memory_WebViews": "Số WebView",
  "Memory_SwapPssDirty": "PSS đã ghi đưa vào swap (KB)", "Memory_AssetManagers": "Số bộ quản lý tài nguyên",
};
const WINDOWS_FEATURE_NOTES = {
  "pslist.nprocs64bit": "Đếm tiến trình có cờ Wow64 theo cách tính gốc.",
  "pslist.avg_handlers": "Dùng số handle theo PID nếu thiếu số đếm từ EPROCESS.",
  "handles.nport": "Đếm đối tượng loại Port. ALPC Port là loại riêng.",
  "malfind.ninjections": "Đếm số vùng mà Malfind 3 phát hiện.",
  "malfind.commitCharge": "Tổng CommitCharge của các vùng phát hiện, tính theo trang.",
  "malfind.protection": "Tổng mã bảo vệ VAD cơ sở.",
  "malfind.uniqueInjections": "Số vùng chia cho số PID có vùng được phát hiện.",
  "svcscan.interactive_process_services": "Đếm bản ghi đúng loại SERVICE_INTERACTIVE_PROCESS.",
  "callbacks.nanonymous": "Đếm callback không xác định được module.",
};
const nice = (k) => NICE[k] || k;
const fmt = (v) => v == null ? "—" : v.toLocaleString("vi-VN", { maximumFractionDigits: Math.abs(v) >= 100 ? 0 : 2 });
const pct = (p) => `${(p * 100).toLocaleString("vi-VN", { maximumFractionDigits: p > 0.995 && p < 1 ? 2 : 1 })}%`;
const MAP_HINT = "Mỗi ô là một nhóm chỉ số rút từ RAM. Ô càng đỏ, các chỉ số trong đó càng khác so với bình thường.";

function toast(msg, ms = 2600) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast._t);
  if (ms) toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const error = new Error(`Yêu cầu thất bại (${r.status}).`);
    error.status = r.status;
    throw error;
  }
  return body;
}

function setView(view) {
  state.view = view;
  state.viewVersion++;
  state.request++;
  state.samples = [];
  document.querySelectorAll("[data-view]").forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active);
  });
  const config = VIEWS[view];
  $("#modelInfo").textContent = config.info;
  $("#uploadTitle").textContent = config.title;
  $("#uploadHint").textContent = config.hint;
  $("#fileInput").accept = config.extension || "";
  $("#typesCard").classList.toggle("hidden", !config.endpoint);
  $("#mapStage").classList.toggle("hidden", !config.endpoint);
  $("#analysis").classList.toggle("static-layout", !config.endpoint);
  resetPanels();
  if (state.uploads[view]) showUpload(state.uploads[view]);
  loadList(view);
}

function resetPanels() {
  state.result = null;
  document.querySelectorAll(".sample-list button.active").forEach((button) => button.classList.remove("active"));
  $("#sampleTitle").textContent = "Chọn một mẫu để bắt đầu";
  $("#sampleSource").textContent = "Các mẫu soạn sẵn được lấy từ dữ liệu kiểm thử.";
  $("#sampleHash").textContent = "—";
  $("#sampleTruth").textContent = "—";
  $("#presetProgress").classList.add("hidden");
  $("#jobProgress").classList.add("hidden");
  $("#jobSteps").replaceChildren();
  $("#memMap").replaceChildren();
  $("#zoneDetail").innerHTML = '<p class="muted">Bấm vào một ô trên bản đồ để xem các chỉ số bên trong.</p>';
  $("#stageEmpty").classList.remove("hidden");
  $("#stageEmpty").textContent = "Chưa có mẫu nào được phân tích.";
  $("#mapTitle").textContent = "Bản đồ bộ nhớ";
  $("#mapHint").textContent = MAP_HINT;
  $("#profileScore").classList.add("hidden");
  $("#ramCard").classList.add("hidden");
  $("#typesTitle").textContent = "Loại mã độc có khả năng nhất";
  setGauge(null);
  $("#typeBars").innerHTML = '<li class="muted">Kết quả sẽ hiện ở đây.</li>';
  $("#indicatorStrip").replaceChildren();
}

async function loadList(view) {
  const version = state.viewVersion;
  const list = $("#sampleList");
  const random = $("#randomBtn");
  random.disabled = true;
  list.replaceChildren();
  try {
    const samples = await api(`/api/samples/${view}`);
    if (version !== state.viewVersion) return;
    state.samples = samples;
    random.disabled = samples.length === 0;
    for (const sample of samples) {
      const row = document.createElement("li");
      const button = document.createElement("button");
      button.dataset.id = sample.id;
      button.textContent = sample.ten;
      if (sample.kho) {
        const label = document.createElement("span");
        label.className = "hard";
        label.title = "Mô hình đoán sai hoặc không chắc";
        label.textContent = "khó";
        button.append(label);
      }
      button.onclick = () => loadSample(view, sample.id);
      row.append(button);
      list.append(row);
    }
  } catch {
    if (version === state.viewVersion) toast("Không tải được danh sách mẫu.");
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function loadSample(view, id) {
  const request = ++state.request;
  delete state.uploads[view];
  resetPanels();
  const progress = $("#presetProgress");
  const usesRam = view !== "android_static";
  $("#sampleSource").textContent = usesRam ? "Đang đọc số đo đã ghi sẵn." : "Đang đọc đặc trưng tĩnh đã lưu.";
  progress.classList.remove("hidden");
  try {
    progress.textContent = usesRam ? "Đọc số đo RAM đã chụp" : "Đọc đặc trưng tĩnh đã lưu";
    await delay(800);
    if (request !== state.request) return;
    progress.textContent = "Chuẩn hóa đặc trưng";
    await delay(800);
    if (request !== state.request) return;
    progress.textContent = "Chạy mô hình";
    const [result] = await Promise.all([api(`/api/samples/${view}/${encodeURIComponent(id)}`), delay(800)]);
    if (request === state.request) render(result);
  } catch {
    if (request === state.request) {
      $("#sampleSource").textContent = "Không phân tích được mẫu đã chọn.";
    }
  } finally {
    if (request === state.request) progress.classList.add("hidden");
  }
}

$("#randomBtn").onclick = () => {
  const sample = state.samples[Math.floor(Math.random() * state.samples.length)];
  if (sample) loadSample(state.view, sample.id);
};

// Results
function render(r) {
  state.result = r;
  document.querySelectorAll(".sample-list button").forEach((b) => b.classList.toggle("active", b.dataset.id === r.id));
  $("#sampleTitle").textContent = r.ten || "Mẫu";
  $("#sampleSource").textContent = r.nguon || "";
  $("#sampleHash").textContent = r.ma_bam || "—";
  $("#sampleTruth").textContent = r.nhan_that || "Chưa biết";

  // Verdict
  const card = $(".verdict-card");
  card.classList.remove("danger", "safe");
  let note = "";
  if (r.sach_doc && r.sach_doc.co) {
    const isMalware = r.sach_doc.doc;
    card.classList.add(isMalware ? "danger" : "safe");
    setGauge(r.sach_doc.tin_cay, isMalware ? "var(--coral)" : "var(--mint)", isMalware ? "Mã độc" : "Sạch");
    note = r.sach_doc.tin_cay < 0.7 ? "Mô hình không chắc chắn, nên phân tích thêm." : "";
  } else {
    const top = r.loai[0];
    setGauge(top.p, "var(--cobalt)", r.so_do_ram ? "độ tin cậy của loại" : "độ tin cậy");
    note = r.sach_doc ? r.sach_doc.ly_do : "";
    if (!r.chac_chan && !r.so_do_ram) note = `Dưới ngưỡng 70%: nghi ngờ ${top.ten}, cần phân tích thêm.`;
  }
  const noteEl = $("#verdictNote");
  noteEl.textContent = note || (r.ghi_chu || "");
  noteEl.classList.toggle("warn", note.startsWith("Mô hình không chắc") || note.startsWith("Dưới ngưỡng"));

  const chips = [];
  if (r.dung === true) chips.push('<span class="chip ok">Đoán đúng nhãn thật</span>');
  if (r.dung === false) chips.push('<span class="chip no">Đoán sai nhãn thật</span>');
  if (r.canh_bao) chips.push('<span class="chip no" title="' + r.canh_bao.replace(/"/g, '&quot;') + '">Chưa xác minh tiến trình mẫu</span>');
  if (r.chua_thay === true) chips.push('<span class="chip">Mô hình chưa thấy mẫu này</span>');
  if (r.chua_thay === false) chips.push('<span class="chip no">Mẫu nằm trong dữ liệu huấn luyện</span>');
  $("#truthRow").innerHTML = chips.join("");

  // Top classes
  const bars = $("#typeBars");
  $("#typesTitle").textContent = r.so_do_windows ? "Dự đoán của mô hình 4 lớp" : "Loại mã độc có khả năng nhất";
  if (r.loai && r.loai.length) {
    bars.innerHTML = r.loai.map((l) => `<li><div class="row"><span>${l.ten}</span><b>${pct(l.p)}</b></div>
      <div class="track"><div class="fill" style="width:0%" data-w="${(l.p * 100).toFixed(1)}"></div></div></li>`).join("");
    requestAnimationFrame(() => bars.querySelectorAll(".fill").forEach((f) => (f.style.width = f.dataset.w + "%")));
  } else {
    bars.innerHTML = `<li class="muted">${r.sach_doc && r.sach_doc.co && !r.sach_doc.doc ? "Không phát hiện mã độc nên không cần phân loại." : "Mô hình này chỉ trả lời sạch hay độc."}</li>`;
  }

  if (r.nen_tang !== "android_static") drawMap(r);
  drawStrip(r);
  drawRamTable(r);
}

function drawRamTable(r) {
  const real = Boolean(r.so_do_ram || r.so_do_windows);
  $("#profileScore").classList.toggle("hidden", !real);
  $("#ramCard").classList.toggle("hidden", !real);
  if (!real) return;
  if (r.so_do_windows) {
    const ref = r.khoang_huan_luyen;
    $("#profileTitle").textContent = "Đối chiếu tập huấn luyện Windows";
    $("#profileValue").textContent =
      `Xác suất mã độc theo mô hình ${pct(r.xac_suat_doc)}. ${ref.ngoai_khoang.length}/${ref.so_da_do} chỉ số đo được nằm ngoài khoảng. ${55 - ref.so_da_do} chỉ số chưa đo được.`;
    $("#ramTitle").textContent = "55 đặc trưng RAM Windows";
    $("#ramHeader").innerHTML = '<th scope="col">Đặc trưng</th><th scope="col">Số đo</th><th scope="col">Khoảng huấn luyện</th>';
    const outside = new Set(ref.ngoai_khoang);
    $("#ramRows").replaceChildren(...Object.entries(r.so_do_windows).map(([key, value]) => {
      const row = document.createElement("tr");
      const title = document.createElement("th");
      title.scope = "row";
      title.textContent = key;
      const explanation = WINDOWS_FEATURE_NOTES[key] || (key.startsWith("psxview.")
        ? (value == null ? "Chưa có nguồn đối chiếu trong PsXView." : "Đối chiếu trên danh sách tiến trình hợp nhất của PsXView.")
        : "");
      if (explanation) {
        const detail = document.createElement("small");
        detail.textContent = explanation;
        title.append(detail);
      }
      const measured = document.createElement("td");
      measured.textContent = value == null ? "Chưa đo được" : fmt(value);
      if (outside.has(key)) {
        const note = document.createElement("small");
        note.textContent = "Ngoài khoảng";
        note.className = "warn";
        measured.append(note);
      }
      const interval = document.createElement("td");
      interval.textContent = `${fmt(ref.cac_khoang[key].min)} – ${fmt(ref.cac_khoang[key].max)}`;
      row.append(title, measured, interval);
      return row;
    }));
    return;
  }
  $("#profileTitle").textContent = "Độ lệch so với hồ sơ RAM của mã độc trong tập huấn luyện";
  $("#ramTitle").textContent = "Bảng số đo RAM trên máy ảo";
  $("#ramHeader").innerHTML = '<th scope="col">Chỉ số</th><th scope="col">Số đo</th>';
  const profile = r.do_lech_ho_so;
  $("#profileValue").textContent = profile
    ? `${fmt(profile.diem * 100)}/100 điểm · So sánh ${profile.so_chi_so} chỉ số. Lệch nhiều nhất ở ${nice(profile.chi_so_lon_nhat).toLowerCase()}.`
    : "Chưa có đủ số liệu tham chiếu để tính độ lệch.";
  $("#ramRows").innerHTML = Object.entries(r.so_do_ram).map(([key, value]) =>
    `<tr><th scope="row">${nice(key)}</th><td>${value == null ? "Chưa đo được" : fmt(value)}</td></tr>`).join("");
}

function setGauge(p, color, label) {
  const g = $("#gaugeVal");
  cancelAnimationFrame(setGauge.frame);
  if (p == null) {
    g.style.strokeDashoffset = 314.16;
    $("#verdictPct").textContent = "—";
    $("#verdictLabel").textContent = "chưa phân tích";
    $("#verdictNote").textContent = "";
    $("#truthRow").innerHTML = "";
    $(".verdict-card").classList.remove("danger", "safe");
    return;
  }
  g.style.stroke = color;
  setGauge.frame = requestAnimationFrame(() => (g.style.strokeDashoffset = 314.16 * (1 - p)));
  $("#verdictPct").textContent = pct(p);
  $("#verdictLabel").textContent = label;
}

// Memory map
const NS = "http://www.w3.org/2000/svg";
const el = (tag, attrs = {}, parent) => {
  const n = document.createElementNS(NS, tag);
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  if (parent) parent.appendChild(n);
  return n;
};

function heat(m) {
  // Interpolate from a normal reading to a strong deviation.
  const a = [227, 234, 248], b = [226, 72, 78];
  const t = Math.min(Math.max(m, 0), 1) ** 0.9;
  return `rgb(${a.map((x, i) => Math.round(x + (b[i] - x) * t)).join(",")})`;
}

function drawMap(r) {
  const svg = $("#memMap");
  svg.innerHTML = "";
  $("#zoneDetail").innerHTML = '<p class="muted">Bấm vào một ô trên bản đồ để xem các chỉ số bên trong.</p>';
  $("#stageEmpty").classList.add("hidden");
  $("#mapHint").textContent = MAP_HINT;

  const zones = r.khoi || [];
  // Memory module outline
  el("rect", { x: 40, y: 28, width: 560, height: 420, rx: 28, fill: "#f7f9fc", stroke: "#d4dbe6", "stroke-width": 1.5 }, svg);
  for (let i = 0; i < 26; i++) {
    el("rect", { x: 66 + i * 20, y: 452, width: 12, height: 26, rx: 3, fill: i === 12 ? "transparent" : "#d9c38f" }, svg);
  }
  el("rect", { x: 40, y: 448, width: 560, height: 6, fill: "#e4e9f1" }, svg);

  $("#mapTitle").textContent = r.nen_tang === "windows" ? "Bản đồ bộ nhớ Windows (theo plugin Volatility)" : "Bản đồ bộ nhớ của app Android";
  if (r.so_do_windows) $("#mapHint").textContent = "Ô càng đỏ, số đo càng lệch so với máy sạch trong tập huấn luyện.";
  else if (r.so_do_ram) $("#mapHint").textContent = "Ô càng đỏ, số đo càng lệch so với hồ sơ RAM của mã độc trong tập huấn luyện.";

  const cols = 3;
  const rows = Math.ceil(zones.length / cols);
  const gap = 16, x0 = 66, y0 = 54, W = 508, H = 372;
  const cw = (W - gap * (cols - 1)) / cols, ch = (H - gap * (rows - 1)) / rows;

  zones.forEach((z, i) => {
    const cx = x0 + (i % cols) * (cw + gap), cy = y0 + Math.floor(i / cols) * (ch + gap);
    const level = z.muc == null ? "Chưa có đối chiếu" : levelText(z.muc);
    const g = el("g", { class: "zone", tabindex: 0, role: "button", "aria-label": `${z.ten}, ${level}` }, svg);
    el("rect", { class: "cell", x: cx, y: cy, width: cw, height: ch, rx: 16, fill: z.muc == null ? "#eef1f6" : heat(z.muc) }, g);
    // Use a segmented scale for each group.
    const n = 6;
    for (let k = 0; k < n; k++) {
      el("rect", { x: cx + 16 + k * ((cw - 66) / n), y: cy + ch - 22, width: (cw - 66) / n - 4, height: 8, rx: 2,
        fill: k / n < z.muc ? "rgba(255,255,255,.85)" : "rgba(24,33,47,.08)" }, g);
    }
    const dark = z.muc > 0.55;
    const label = el("text", { x: cx + 16, y: cy + 34, "font-size": 18, "font-weight": 600, fill: dark ? "#fff" : "#18212f" }, g);
    label.textContent = z.ten;
    const sub = el("text", { x: cx + 16, y: cy + 60, "font-size": 15, fill: dark ? "rgba(255,255,255,.85)" : "#687386" }, g);
    sub.textContent = level;
    // Mark groups with high deviation.
    const hx = cx + cw - 22, hy = cy + ch - 18;
    if (z.muc > 0.5) el("circle", { class: "hot-ring", cx: hx, cy: hy, r: 10, fill: "#e2484e" }, g);
    el("circle", { cx: hx, cy: hy, r: 10, fill: z.muc > 0.5 ? "#e2484e" : "#fff", stroke: z.muc > 0.5 ? "#fff" : "#c6cfdc", "stroke-width": 3 }, g);
    const open = () => showZone(z);
    g.addEventListener("click", open);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  });

  // Open the group with the greatest deviation.
  const worst = [...zones].sort((a, b) => (b.muc ?? -1) - (a.muc ?? -1))[0];
  if (worst) showZone(worst);
}

function levelText(m) { return m > 0.5 ? "Khác nhiều" : m > 0.25 ? "Khác vừa" : "Gần bình thường"; }
function levelCls(m) { return m > 0.5 ? "hi" : m > 0.25 ? "mid" : "lo"; }

function showZone(z) {
  const box = $("#zoneDetail");
  const ref = referenceLabel(state.result);
  const level = z.muc == null ? "Chưa có đối chiếu" : levelText(z.muc);
  box.innerHTML = `<h4>${z.ten}</h4><p class="muted">${z.mo_ta}</p><span class="lvl ${z.muc == null ? "muted" : levelCls(z.muc)}">${level}</span>
    <table><tr><td class="muted">Chỉ số</td><td class="muted">Mẫu này</td><td class="muted">Trung vị ${ref}</td></tr>
    ${z.chi_so.map((c) => `<tr><td>${nice(c.ten)}</td><td><b>${fmt(c.gia_tri)}</b></td><td>${fmt(c.trung_vi)}</td></tr>`).join("")}</table>`;
}

function referenceLabel(r) {
  if (r.nen_tang === "windows") return "máy sạch";
  return r.so_do_ram ? "mã độc" : "các mẫu khác";
}

// Largest measurement deviations
function drawStrip(r) {
  const strip = $("#indicatorStrip");
  const all = (r.khoi || []).flatMap((z) => z.chi_so.map((c) => ({ ...c, khoi: z.ten })));
  const top = all.filter((c) => c.do_lech != null).sort((a, b) => b.do_lech - a.do_lech).slice(0, 3);
  if (!top.length) { strip.innerHTML = ""; return; }
  const ref = referenceLabel(r);
  strip.innerHTML = top.map((c) => {
    const max = Math.max(c.gia_tri, c.trung_vi) * 1.25 || 1;
    return `<div class="card ind"><span class="k">${nice(c.ten)}</span>
      <span class="v">${fmt(c.gia_tri)}<small>trung vị ${ref}: ${fmt(c.trung_vi)}</small></span>
      <div class="meter"><i style="left:${(c.trung_vi / max) * 100}%"></i><b style="left:${(c.gia_tri / max) * 100}%"></b></div>
      <span class="desc">Thuộc vùng ${c.khoi}</span></div>`;
  }).join("");
}

// Hash lookup comes before any live measurement.
const dropzone = $("#dropzone");
const fileInput = $("#fileInput");
dropzone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});
for (const event of ["dragenter", "dragover"]) {
  dropzone.addEventListener(event, (e) => { e.preventDefault(); dropzone.classList.add("over"); });
}
for (const event of ["dragleave", "drop"]) {
  dropzone.addEventListener(event, (e) => { e.preventDefault(); dropzone.classList.remove("over"); });
}
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer.files[0]) checkFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) checkFile(fileInput.files[0]);
  fileInput.value = "";
});

function uploadForm(file) {
  const body = new FormData();
  body.append("file", file);
  return body;
}

async function checkFile(file) {
  const view = state.view;
  const config = VIEWS[view];
  const upload = { view, filename: file.name, message: "Đang tính mã băm và tra cứu…" };
  state.request++;
  state.uploads[view] = upload;
  resetPanels();
  showUpload(upload);
  try {
    const lookup = await api("/api/lookup", { method: "POST", body: uploadForm(file) });
    if (state.uploads[view] !== upload) return;
    upload.filename = lookup.ten_file;
    upload.sha256 = lookup.sha256;
    upload.result = lookup.ket_qua.find((result) => result.nen_tang === view);
    if (upload.result) return;
    if (lookup.ket_qua.length) {
      upload.message = "Tìm thấy mã băm trong dữ liệu của mô hình khác. Chọn thẻ tương ứng để tra lại.";
      return;
    }
    if (!config.endpoint) {
      upload.message = "Không tìm thấy mã băm trong bộ dữ liệu. Chưa thể trích xuất đặc trưng tĩnh cho APK mới.";
      return;
    }
    if (!file.name.toLowerCase().endsWith(config.extension)) {
      upload.message = `Không tìm thấy mã băm trong dữ liệu. Hãy chọn tệp ${config.extension} để đo RAM.`;
      return;
    }
    upload.message = "Mã băm chưa có trong dữ liệu. Đang gửi yêu cầu đo RAM…";
    upload.live = true;
    showUpload(upload);
    const { job_id: id } = await api(config.endpoint, { method: "POST", body: uploadForm(file) });
    do {
      upload.job = await api(`/api/jobs/${id}`, { cache: "no-store" });
      showUpload(upload);
      if (["loi", "xong"].includes(upload.job.trang_thai)) break;
      await delay(1000);
    } while (state.uploads[view] === upload);
    upload.result = upload.job.ket_qua;
  } catch (error) {
    if (error.status === 422) upload.message = "Tệp này chưa nằm trong danh sách mẫu sạch đã duyệt nên không được chạy trên máy ảo. Dùng các tệp trong thư mục mau-demo.";
    else if (error.status === 413) upload.message = `Tệp quá lớn (${(file.size / 1048576).toFixed(0)} MB). Giới hạn: tra mã băm 1 GB, đo RAM APK 64 MB, EXE 64 MB.`;
    else if (error.status === 503) upload.message = "Hàng đợi máy ảo đã đầy. Hãy thử lại sau.";
    else if (error.status === 400 && upload.live) upload.message = "Tệp không đúng định dạng.";
    else upload.message = upload.live ? "Không thể đo RAM trên máy ảo." : "Không thể tra cứu mã băm.";
  } finally {
    showUpload(upload);
  }
}

const STEP_NAMES = {
  sha256: "Kiểm tra SHA-256",
  may_ao: "Chuẩn bị máy ảo Android",
  cai_dat: "Cài ứng dụng",
  doc_ram: "Đọc số đo RAM",
  go_app: "Gỡ ứng dụng",
  khoi_phuc: "Khôi phục ảnh chụp sạch",
  khoi_dong: "Khởi động và chờ VMware Tools",
  chep: "Chép tệp vào máy ảo",
  chup_ram: "Tạm dừng máy ảo và lấy RAM",
  volatility: "Rút đặc trưng bằng Volatility 3",
  cham_diem: "Chạy mô hình",
  don: "Trả máy ảo về ảnh chụp sạch",
  luu: "Lưu kết quả",
};
const STEP_STATUS = { cho: "Chờ", dang_chay: "Đang chạy", xong: "Xong", loi: "Lỗi", bo_qua: "Bỏ qua" };

function showUpload(upload) {
  if (state.view !== upload.view || state.uploads[upload.view] !== upload) return;
  const job = upload.job;
  if (upload.result) {
    render(upload.result);
  } else {
    $("#sampleTitle").textContent = upload.filename;
    $("#sampleSource").textContent = upload.message;
    $("#sampleHash").textContent = upload.sha256 || "—";
  }
  $("#jobProgress").classList.toggle("hidden", !job);
  if (!job) return;
  const evidence = job.tep_ket_qua ? ` Bản ghi: ${job.tep_ket_qua}.` : "";
  const summaries = {
    cho: "Đang chờ đến lượt dùng máy ảo.",
    dang_chay: "Đang phân tích trên máy ảo.",
    loi: (evidence ? "Đo RAM gặp lỗi. Xem bước báo lỗi và bản ghi trong app/results." : "Đo RAM gặp lỗi. Chưa lưu được bản ghi.") + evidence,
    xong: `Hoàn tất sau ${fmt(job.thoi_gian)} giây.` + evidence,
  };
  const status = $("#jobStatus");
  if (status.textContent !== summaries[job.trang_thai]) status.textContent = summaries[job.trang_thai];
  const items = job.buoc.map((step) => {
    const item = document.createElement("li");
    item.dataset.status = step.trang_thai;
    const name = document.createElement("strong");
    name.textContent = step.ma === "chay"
      ? (upload.view === "windows" ? "Chạy mẫu và chờ 60 giây" : "Mở ứng dụng và chạy Monkey")
      : STEP_NAMES[step.ma];
    const duration = step.thoi_gian == null ? "" : ` · ${fmt(step.thoi_gian)} giây`;
    const detail = document.createElement("span");
    detail.textContent = STEP_STATUS[step.trang_thai] + duration;
    item.append(name, detail);
    return item;
  });
  $("#jobSteps").replaceChildren(...items);
}

for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => setView(button.dataset.view));
}
setView("windows");

"""Colab model launcher for the RiskVoid agent kit.

Run inside a Colab GPU runtime with:   %run /content/serve.py
(the notebook and the Claude Code /rv-start command both do this for you)

What it does:
  1. picks a profile from the GPU it finds (L4 -> Q4, A100-40 -> Q8, A100-80/H100/G4 -> Q8 with long context)
  2. gets llama-server with CUDA (Drive cache -> prebuilt release -> source build), caches it in Drive
  3. downloads the Qwen3.8-27B GGUF from Hugging Face at a pinned revision:
     the mainstream build by default, or the abliterated (refusal-removed) build with RVKIT_MODEL=abliterated
  4. starts an OpenAI-compatible API on :8000, protected by an API key
  5. opens a tunnel (Cloudflare quick tunnel, or ngrok if NGROK_TOKEN is set)
  6. prints   RVKIT_ENDPOINT {"url": ..., "key": ..., "model": ...}   and the ./rvkit connect <url> <key> <model> line
  7. disconnects the runtime after IDLE_MINUTES without requests (saves compute units)

Settings come from environment variables (all optional):
  RVKIT_PROFILE   auto | l4 | a100-40 | a100-80     (default auto)
  RVKIT_MODEL     qwen | abliterated   (default qwen)
                    qwen         lmstudio-community/Qwen3.8-27B-GGUF, Qwen's weights unchanged, served as qwen38-27b
                    abliterated  huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF, refusals removed, served as qwen38-27b-obl;
                                 you are responsible for how you use it
  RVKIT_REPO      override the GGUF repo (the served name still follows RVKIT_MODEL)
  RVKIT_REVISION  override the pinned revision (default: the pinned commit, or main when RVKIT_REPO is set)
  RVKIT_QUANT     override quant, e.g. Q5_K_M
  RVKIT_API_KEY   fixed API key (else Colab secret LLM_API_KEY, else random)
  RVKIT_THINKING  1 to enable thinking mode (slower, deeper)  (default 0)
  RVKIT_IDLE_MINUTES  default 30
  RVKIT_TUNNEL    auto | cloudflare | ngrok   (default auto)
  RVKIT_DRIVE     1 to cache llama-server in Google Drive (default 1)
  RVKIT_REBUILD   1 to force a fresh llama.cpp build
  RVKIT_LLAMA_TAG llama.cpp release to use instead of the pinned one (e.g. b11900)
"""
import glob, json, os, re, secrets, shutil, subprocess, tarfile, threading, time, urllib.request

# RVKIT_MODEL: (GGUF repo, pinned commit, served name). Pinned so a re-upload can't change what runs.
# Qwen publishes no GGUF of Qwen3.8-27B; lmstudio-community converts with stock llama.cpp, plain Q4_K_M/Q8_0 files.
MODELS = {
    "qwen":        ("lmstudio-community/Qwen3.8-27B-GGUF",
                    "5a7da681f60570ab5b439a587e912d2e5eddb582", "qwen38-27b"),
    "abliterated": ("huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF",
                    "1c69098e9c32db6dc06fc48f1d6cc75ad07da89e", "qwen38-27b-obl"),
}
DEFAULT_MODEL = "qwen"
PORT = 8000
BIN_DIR = "/content/llama-bin"
# Pinned versions (each at least two weeks old when pinned). RVKIT_LLAMA_TAG overrides the llama.cpp release.
LLAMA_CPP_TAG = "b11840"
HF_HUB_VERSION = "2.3.0"
PYNGROK_VERSION = "9.0.3"
DRIVE_DIR = "/content/drive/MyDrive/riskvoid-llm"
MODEL_DIR = "/content/model"  # one subfolder per repo, so both variants can sit side by side
CLOUDFLARED_VERSION = "2026.10.3"  # quick tunnel; bump together with the checksum (release notes list it)
CLOUDFLARED_SHA256 = "053b80b0a23031a038fdbf3c073f59f82b8f1f152aa67971d7383ffafc0dbab0"  # cloudflared-linux-amd64
PROFILES = {  # name: (quant, context, min VRAM MiB)
    "l4":      ("Q4_K_M", 32768, 21000),
    "a100-40": ("Q8_0",   65536, 39000),
    "a100-80": ("Q8_0",  131072, 78000),
}


def env(name, default=""):
    return os.environ.get(name, default).strip()


def secret(name):
    try:
        from google.colab import userdata
        return userdata.get(name)
    except Exception:
        return None


def step(msg):
    print(f"\n▶ {msg}", flush=True)


def sh(cmd, log="/content/rvkit-build.log"):
    with open(log, "a") as f:
        r = subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT)
    if r.returncode:
        print(open(log).read()[-3000:])
        raise RuntimeError(f"command failed: {cmd}")


# ---------------------------------------------------------------- 1. GPU / profile
def pick_profile():
    out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                         capture_output=True, text=True).stdout.strip()
    if not out:
        raise SystemExit("No GPU. Runtime → Change runtime type → L4 (or A100), then run again.")
    name, vram = out.split(",")[0].strip(), int(out.split(",")[-1])
    want = env("RVKIT_PROFILE", "auto").lower()
    if want == "auto":
        want = "a100-80" if vram >= 78000 else "a100-40" if vram >= 39000 else "l4" if vram >= 21000 else None
        if not want:
            raise SystemExit(f"{name} ({vram} MiB) is too small. Use an L4 or A100 runtime.")
    quant, ctx, need = PROFILES[want]
    if vram < need:
        raise SystemExit(f"{name} has {vram} MiB, but profile '{want}' needs ~{need}. Use RVKIT_PROFILE=auto.")
    quant = env("RVKIT_QUANT") or quant
    print(f"GPU: {name} ({vram // 1024} GB) → profile {want}: {quant}, {ctx // 1024}K context")
    return want, quant, ctx


# ---------------------------------------------------------------- 2. llama-server
def server_bin():
    return os.path.join(BIN_DIR, "llama-server")


def lib_env():
    """Prepend BIN_DIR to the library path; keep Colab's default (it holds libcuda.so.1)."""
    return {**os.environ, "LD_LIBRARY_PATH": ":".join(p for p in [BIN_DIR, os.environ.get("LD_LIBRARY_PATH", "")] if p)}


def llama_tag():
    return env("RVKIT_LLAMA_TAG") or LLAMA_CPP_TAG


def bin_works():
    try:
        r = subprocess.run([server_bin(), "--version"], capture_output=True, text=True, timeout=30,
                           env=lib_env())
        return r.returncode == 0
    except Exception:
        return False


def try_prebuilt():
    """Official llama.cpp Linux CUDA build of the pinned release, if one is published."""
    try:
        rel = json.load(urllib.request.urlopen(f"https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/{llama_tag()}", timeout=20))
        assets = [a for a in rel["assets"] if re.search(r"ubuntu.*cuda.*x64|linux.*cuda.*x64", a["name"], re.I)]
        if not assets:
            return False
        a = assets[0]
        print("trying prebuilt", a["name"])
        sh(f"rm -rf /content/llama-pre && mkdir -p /content/llama-pre && cd /content/llama-pre && "
           f"wget -q -O pkg '{a['browser_download_url']}' && (unzip -q pkg || tar xf pkg)")
        found = glob.glob("/content/llama-pre/**/llama-server", recursive=True)
        if not found:
            return False
        shutil.rmtree(BIN_DIR, ignore_errors=True)
        shutil.copytree(os.path.dirname(found[0]), BIN_DIR)
        os.chmod(server_bin(), 0o755)
        return bin_works()
    except Exception as e:
        print("prebuilt not usable:", e)
        return False


def build_from_source():
    print(f"building llama.cpp {llama_tag()} with CUDA (~10–15 min, only once if Drive caching is on) ...")
    sh(f"rm -rf /content/llama.cpp && git clone -q --depth 1 --branch {llama_tag()} https://github.com/ggml-org/llama.cpp /content/llama.cpp")
    sh("cd /content/llama.cpp && cmake -B build -DGGML_CUDA=ON -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF "
       "-DCMAKE_CUDA_ARCHITECTURES='80;89;90' -DCMAKE_BUILD_TYPE=Release")
    sh("cd /content/llama.cpp && cmake --build build --target llama-server -j $(nproc)")
    shutil.rmtree(BIN_DIR, ignore_errors=True)
    os.makedirs(BIN_DIR)
    shutil.copy("/content/llama.cpp/build/bin/llama-server", server_bin())
    if not bin_works():
        raise RuntimeError("built llama-server does not run, see /content/rvkit-build.log")


def get_llama_server(use_drive):
    cache = os.path.join(DRIVE_DIR, f"llama-bin-{llama_tag()}.tar.gz") if use_drive else None
    rebuild = env("RVKIT_REBUILD") == "1"
    if bin_works() and not rebuild:
        print("llama-server already present"); return
    if cache and os.path.exists(cache) and not rebuild:
        with tarfile.open(cache) as t:
            t.extractall("/content", filter="data")
        if bin_works():
            print("llama-server restored from Drive cache"); return
    if rebuild or not try_prebuilt():
        build_from_source()
    if cache:
        with tarfile.open(cache, "w:gz") as t:
            t.add(BIN_DIR, arcname=os.path.basename(BIN_DIR))
        print("cached llama-server in Drive:", cache)


# ---------------------------------------------------------------- 3. model
def pick_model():
    """RVKIT_MODEL (+ RVKIT_REPO / RVKIT_REVISION overrides) -> (variant, repo, revision, served name)."""
    variant = env("RVKIT_MODEL", DEFAULT_MODEL).lower() or DEFAULT_MODEL
    if variant not in MODELS:
        raise SystemExit(f"RVKIT_MODEL={variant!r} is unknown. Use one of: {', '.join(MODELS)}.")
    repo, revision, alias = MODELS[variant]
    if env("RVKIT_REPO") and env("RVKIT_REPO") != repo:
        repo, revision = env("RVKIT_REPO"), "main"
    revision = env("RVKIT_REVISION") or revision
    return variant, repo, revision, alias


def resolve_files(repo, revision, quant, list_files=None):
    """GGUF file(s) for `quant` in the repo at `revision`: plainest name first, all parts of a split model."""
    if list_files is None:
        from huggingface_hub import HfApi
        list_files = HfApi().list_repo_files
    all_gguf = [f for f in list_files(repo, revision=revision) if f.endswith(".gguf") and "mmproj" not in f.lower()]
    files = [f for f in all_gguf if quant.lower() in f.lower()]
    extra = ("mtp", "ud-", "dflash")  # speculative-decoding heads and non-standard mixes go last
    files.sort(key=lambda f: (any(x in f.lower() for x in extra), len(f), f))
    if not files:
        raise SystemExit(f"No {quant} file in {repo}@{revision}. Available:\n  " + "\n  ".join(sorted(all_gguf)))
    first = files[0]
    if re.search(r"-\d{5}-of-\d{5}\.gguf$", first):  # split model: fetch all parts
        stem = re.sub(r"-\d{5}-of-\d{5}\.gguf$", "", first)
        return sorted(f for f in files if f.startswith(stem))
    return [first]


def download_model(repo, revision, quant):
    os.environ["HF_XET_HIGH_PERFORMANCE"] = "1"
    subprocess.run(f"pip install -q huggingface_hub=={HF_HUB_VERSION}", shell=True)
    if secret("HF_TOKEN"):
        os.environ["HF_TOKEN"] = secret("HF_TOKEN")
    from huggingface_hub import hf_hub_download
    parts = resolve_files(repo, revision, quant)
    local = os.path.join(MODEL_DIR, repo.replace("/", "--"))
    for f in parts:
        print("downloading", f)
        hf_hub_download(repo, f, revision=revision, local_dir=local)
    return os.path.join(local, parts[0])


# ---------------------------------------------------------------- 4. server
def start_server(model_path, alias, ctx, key, thinking):
    subprocess.run("pkill -f llama-server", shell=True)
    args = [server_bin(), "-m", model_path, "--alias", alias,
            "--host", "127.0.0.1", "--port", str(PORT), "--api-key", key,
            "-c", str(ctx), "-np", "1", "-ngl", "999", "--flash-attn", "on",
            "--cache-type-k", "q8_0", "--cache-type-v", "q8_0",
            "--jinja", "--metrics", "--top-k", "20"]
    if thinking:
        args += ["--temp", "1.0", "--top-p", "0.95"]
    else:
        args += ["--temp", "0.7", "--top-p", "0.8",
                 "--chat-template-kwargs", json.dumps({"enable_thinking": False})]
    proc = subprocess.Popen(args, stdout=open("/content/server.log", "w"), stderr=subprocess.STDOUT,
                            env=lib_env())
    for _ in range(200):
        try:
            if json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2)).get("status") == "ok":
                return proc
        except Exception:
            pass
        if proc.poll() is not None:
            print(open("/content/server.log").read()[-4000:])
            raise SystemExit("llama-server exited. Log above.")
        time.sleep(3)
    raise SystemExit("llama-server did not become ready in 10 min; see /content/server.log")


# ---------------------------------------------------------------- 5. tunnel
def start_tunnel():
    mode = env("RVKIT_TUNNEL", "auto").lower()
    token = secret("NGROK_TOKEN")
    if mode == "ngrok" or (mode == "auto" and token):
        subprocess.run(f"pip install -q pyngrok=={PYNGROK_VERSION}", shell=True)
        from pyngrok import ngrok, conf
        conf.get_default().auth_token = token
        domain = secret("NGROK_DOMAIN")
        return ngrok.connect(PORT, "http", **({"domain": domain} if domain else {})).public_url, bool(domain)
    subprocess.run("pkill -f cloudflared", shell=True)
    if not os.path.exists("/usr/local/bin/cloudflared"):  # pinned release, SHA-256 from its release notes
        sh(f"wget -q -O /tmp/cloudflared https://github.com/cloudflare/cloudflared/releases/download/"
           f"{CLOUDFLARED_VERSION}/cloudflared-linux-amd64 && "
           f"echo '{CLOUDFLARED_SHA256}  /tmp/cloudflared' | sha256sum -c - && "
           "install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared")
    subprocess.Popen(["cloudflared", "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{PORT}"],
                     stdout=open("/content/tunnel.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", open("/content/tunnel.log").read())
        if m:
            return m.group(0), False
        time.sleep(1)
    raise SystemExit("tunnel failed; see /content/tunnel.log")


def smoke_test(url, key, alias):
    t = time.time()
    for attempt in range(10):  # quick tunnels need a few seconds to propagate
        try:
            req = urllib.request.Request(f"{url}/v1/chat/completions",
                data=json.dumps({"model": alias, "max_tokens": 60,
                                 "messages": [{"role": "user", "content": "Reply with: ready"}]}).encode(),
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                         "User-Agent": "rvkit"})
            r = json.load(urllib.request.urlopen(req, timeout=120))
            n = r.get("usage", {}).get("completion_tokens", 0)
            print(f"smoke test OK ({n} tokens, {time.time() - t:.1f}s): {r['choices'][0]['message'].get('content', '')[:80]!r}")
            return
        except Exception as e:
            last = e
            time.sleep(5)
    print("⚠ smoke test through the tunnel failed:", last)


# ---------------------------------------------------------------- 6. idle watchdog
def start_watchdog(key, idle_minutes):
    def metrics():
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{PORT}/metrics", headers={"Authorization": f"Bearer {key}"})
            txt = urllib.request.urlopen(req, timeout=5).read().decode()
            val = lambda k: sum(float(v) for v in re.findall(rf"^llamacpp:{k}(?:{{[^}}]*}})? ([0-9.e+]+)", txt, re.M))
            return val("prompt_tokens_total") + val("tokens_predicted_total"), val("requests_processing")
        except Exception:
            return None, 0

    def loop():
        last, since = metrics()[0], time.time()
        while True:
            time.sleep(60)
            total, busy = metrics()
            if total != last or busy > 0:
                last, since = total, time.time()
            elif time.time() - since > idle_minutes * 60:
                print(f"\n{idle_minutes} idle minutes, releasing the GPU to save compute units", flush=True)
                try:
                    from google.colab import runtime
                    runtime.unassign()
                except Exception as e:
                    print("could not auto-disconnect:", e)
                return

    threading.Thread(target=loop, daemon=True, name="rvkit-watchdog").start()


# ---------------------------------------------------------------- main
def main():
    t0 = time.time()
    step("Checking GPU")
    profile, quant, ctx = pick_profile()
    variant, repo, revision, alias = pick_model()
    print(f"Model: {variant} → {repo} @ {revision[:12]}, {quant}, served as '{alias}'")
    if variant == "abliterated":
        print("⚠ Abliterated build: refusals removed. You are responsible for how you use it.")
    key = env("RVKIT_API_KEY") or secret("LLM_API_KEY") or ("rv-" + secrets.token_urlsafe(24))

    use_drive = env("RVKIT_DRIVE", "1") == "1"
    if use_drive:
        step("Mounting Google Drive (caches the llama.cpp build; approve the popup)")
        try:
            from google.colab import drive
            drive.mount("/content/drive")
            os.makedirs(DRIVE_DIR, exist_ok=True)
        except Exception as e:
            print("Drive not available, continuing without cache:", e)
            use_drive = False

    step("Getting llama-server")
    get_llama_server(use_drive)

    step("Downloading model")
    model = download_model(repo, revision, quant)

    step(f"Starting model server ({alias})")
    start_server(model, alias, ctx, key, env("RVKIT_THINKING") == "1")

    step("Opening tunnel")
    url, fixed = start_tunnel()
    smoke_test(url, key, alias)

    idle = int(env("RVKIT_IDLE_MINUTES", "30"))
    start_watchdog(key, idle)

    info = {"url": f"{url}/v1", "key": key, "model": alias, "profile": profile, "quant": quant, "ctx": ctx}
    json.dump(info, open("/content/rvkit-endpoint.json", "w"))
    print(f"\n✅ {alias} ({variant}, {repo}) ready in {(time.time() - t0) / 60:.1f} min. Auto-disconnect after {idle} idle minutes. Keep this tab open.")
    print("\n================ RUN ON YOUR MAC (in the kit folder) ================")
    print(f"./rvkit connect {url}/v1 {key} {alias}")
    print("======================================================================")
    if fixed:
        print("(ngrok fixed domain: if you used the same key before, you can skip this step)")
    print("RVKIT_ENDPOINT " + json.dumps(info))


if __name__ == "__main__":  # %run executes it as __main__; importing it (for tests) does not start anything
    main()

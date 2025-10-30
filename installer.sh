#!/usr/bin/env bash
# =====================================================
# Sing-box Proxy Installer - 改进版
# Version: 2.0
# 特性：移除跟踪、支持自定义密码、配置备份
# =====================================================

set -euo pipefail

VERSION='Sing-box Installer v2.0'
GH_PROXY=''
TEMP_DIR='/tmp/singboxinstaller'
WORK_DIR='/etc/sing-box'
LOG_DIR="${WORK_DIR}/logs"
CONF_DIR="${WORK_DIR}/conf"
BACKUP_DIR="${WORK_DIR}/backup"
DEFAULT_PORT_REALITY=443
DEFAULT_PORT_WS=8080
DEFAULT_PORT_SS=8388
TLS_SERVER_DEFAULT='www.cloudflare.com'
DEFAULT_NEWEST_VERSION='1.12.0'
export DEBIAN_FRONTEND=noninteractive

trap 'rm -rf "$TEMP_DIR" >/dev/null 2>&1 || true' EXIT
mkdir -p "$TEMP_DIR" "$WORK_DIR" "$CONF_DIR" "$LOG_DIR" "$BACKUP_DIR"

# 彩色输出
ok() { echo -e "\033[32m\033[01m$*\033[0m"; }
warn() { echo -e "\033[33m\033[01m$*\033[0m"; }
err() { echo -e "\033[31m\033[01m$*\033[0m" >&2; }
die() { err "$*"; exit 1; }

ESC=$(printf '\033')
YELLOW="${ESC}[33m"
GREEN="${ESC}[32m"
RED="${ESC}[31m"
BLUE="${ESC}[34m"
RESET="${ESC}[0m"

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "${LOG_DIR}/installer.log"
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "请使用 root 运行此脚本。"
}

detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64) SB_ARCH=arm64 ;;
    x86_64|amd64) SB_ARCH=amd64 ;;
    armv7l) SB_ARCH=armv7 ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
  log_action "检测到系统架构: $SB_ARCH"
}

detect_os() {
  local pretty=""
  [ -s /etc/os-release ] && pretty="$(. /etc/os-release; echo "$PRETTY_NAME")"
  case "$pretty" in
    *Debian*|*Ubuntu*) OS_FAMILY="Debian"; PKG_INSTALL="apt -y install";;
    *CentOS*|*Rocky*|*Alma*|*Red\ Hat*) OS_FAMILY="CentOS"; PKG_INSTALL="yum -y install";;
    *Fedora*) OS_FAMILY="Fedora"; PKG_INSTALL="dnf -y install";;
    *Alpine*) OS_FAMILY="Alpine"; PKG_INSTALL="apk add --no-cache";;
    *Arch*) OS_FAMILY="Arch"; PKG_INSTALL="pacman -S --noconfirm";;
    *) die "不支持的系统: $pretty" ;;
  esac
  log_action "检测到操作系统: $OS_FAMILY"
}

install_deps() {
  local deps=(wget curl jq tar openssl)
  for d in "${deps[@]}"; do
    if ! command -v "$d" >/dev/null 2>&1; then
      ok "安装依赖: $d"
      $PKG_INSTALL "$d" || die "安装 $d 失败"
      log_action "已安装依赖: $d"
    fi
  done
}

get_latest_version() {
  local v
  v=$(wget -qO- "${GH_PROXY}https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
      | grep -oE '"tag_name":\s*"v[0-9.]+"' | head -n1 | tr -dc '0-9.')
  echo "${v:-$DEFAULT_NEWEST_VERSION}"
}

backup_config() {
  if [ -f "$WORK_DIR/config.json" ]; then
    local backup_file="${BACKUP_DIR}/config_$(date +%Y%m%d_%H%M%S).json"
    cp "$WORK_DIR/config.json" "$backup_file"
    ok "已备份配置到: $backup_file"
    log_action "配置已备份到: $backup_file"
    ls -t "${BACKUP_DIR}"/config_*.json 2>/dev/null | tail -n +11 | xargs -r rm -f
  fi
}

ensure_singbox() {
  if [ -x "${WORK_DIR}/sing-box" ]; then
    return
  fi
  local ver
  ver=$(get_latest_version)
  ok "下载 sing-box v${ver} (${SB_ARCH}) ..."
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${SB_ARCH}.tar.gz"
  wget -qO- "${GH_PROXY}$url" | tar xz -C "$TEMP_DIR" || die "下载/解压 sing-box 失败"
  mv "$TEMP_DIR/sing-box-${ver}-linux-${SB_ARCH}/sing-box" "$WORK_DIR/" || die "移动 sing-box 失败"
  chmod +x "${WORK_DIR}/sing-box"
  log_action "sing-box v${ver} 安装完成"
}

ensure_qrencode() {
  command -v qrencode >/dev/null 2>&1 && return
  ok "正在安装二维码生成工具..."
  if command -v apt >/dev/null 2>&1; then
    apt update -y >/dev/null 2>&1
    apt install -y qrencode >/dev/null 2>&1 || warn "qrencode 安装失败"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y qrencode >/dev/null 2>&1 || warn "qrencode 安装失败"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache qrencode >/dev/null 2>&1 || warn "qrencode 安装失败"
  fi
}

ensure_systemd_service() {
  if [ -f /etc/init.d/sing-box ] && ! command -v systemctl >/dev/null 2>&1; then
    cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/var/run/${RC_SVCNAME}.pid"
output_log="/etc/sing-box/logs/sing-box.log"
error_log="/etc/sing-box/logs/sing-box.log"
depend() { need net; after net; }
start_pre() { mkdir -p /etc/sing-box/logs /var/run; rm -f "$pidfile"; }
EOF
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default >/dev/null 2>&1 || true
  else
    cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
Type=simple
WorkingDirectory=/etc/sing-box
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1 || true
  fi
  log_action "systemd 服务已配置"
}

svc_restart() {
  backup_config
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sing-box
    sleep 1
    if systemctl is-active --quiet sing-box; then
      ok "✅ 服务已启动"
    else
      die "❌ 服务启动失败，查看日志：tail -n 200 ${LOG_DIR}/sing-box.log"
    fi
  else
    rc-service sing-box restart
  fi
  log_action "服务已重启"
}

merge_config() {
  local files=("$CONF_DIR"/*.json)
  if [ ! -e "${files[0]}" ]; then
    cat > "${CONF_DIR}/00_base.json" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "${LOG_DIR}/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [ { "type": "local" } ],
    "strategy": "prefer_ipv4"
  },
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
  fi

  jq -s '
    def pickone(k): (map(select(type=="object" and has(k)) | .[k]) | last) // null;
    def catarr(k): (map(select(type=="object" and has(k)) | .[k]) | add) // [];
    {
      log: pickone("log"),
      dns: pickone("dns"),
      ntp: pickone("ntp"),
      outbounds: catarr("outbounds"),
      inbounds: catarr("inbounds")
    }
  ' "$CONF_DIR"/*.json > "$WORK_DIR/config.json" 2>/dev/null || warn "配置合并失败"

  jq . "$WORK_DIR/config.json" >/dev/null 2>&1 || err "配置文件无效"
}

read_ip_default() {
  SERVER_IP=$(curl -s https://api.ip.sb/ip || curl -s https://ifconfig.me || echo "127.0.0.1")
  ok "检测到公网 IP: ${SERVER_IP}"
}

read_uuid() {
  read -rp "请输入 UUID（留空自动生成）: " UUID
  if [ -z "$UUID" ]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
    ok "已自动生成 UUID: ${UUID}"
  else
    if [[ ! "$UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
      warn "UUID 格式不正确，自动生成新的..."
      UUID=$(cat /proc/sys/kernel/random/uuid)
      ok "已自动生成 UUID: ${UUID}"
    else
      ok "使用自定义 UUID: ${UUID}"
    fi
  fi
}

read_password() {
  local prompt="$1"
  local password=""
  read -rp "${prompt}（留空自动生成）: " password
  if [ -z "$password" ]; then
    password=$(cat /proc/sys/kernel/random/uuid)
    ok "已自动生成密码: ${password}"
  else
    if [ ${#password} -lt 8 ]; then
      warn "密码长度不足8位，自动生成安全密码..."
      password=$(cat /proc/sys/kernel/random/uuid)
      ok "已自动生成密码: ${password}"
    else
      ok "使用自定义密码: ${password}"
    fi
  fi
  echo "$password"
}

read_port() {
  local hint="$1" def="$2"
  read -rp "$hint [按回车默认: $def]: " PORT
  PORT="${PORT:-$def}"
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "端口必须为数字"
  if [ "$PORT" -lt 100 ] || [ "$PORT" -gt 65535 ]; then
    die "端口必须在 100-65535 之间"
  fi
}

install_vless_tcp_reality() {
  ensure_singbox
  ensure_systemd_service
  merge_config
  
  ok "开始安装 VLESS + TCP + Reality 协议"
  read_ip_default
  read_uuid
  read -rp "Reality 域名（sni/握手域名）[按回车默认: ${TLS_SERVER_DEFAULT}]: " TLS_DOMAIN
  TLS_DOMAIN="${TLS_DOMAIN:-$TLS_SERVER_DEFAULT}"
  read_port "监听端口" "$DEFAULT_PORT_REALITY"

  local kp priv pub
  kp="$("${WORK_DIR}/sing-box" generate reality-keypair)"
  priv="$(awk '/PrivateKey/{print $NF}' <<<"$kp")"
  pub="$(awk '/PublicKey/{print $NF}' <<<"$kp")"
  echo "$priv" > "${CONF_DIR}/reality_private.key"
  echo "$pub" > "${CONF_DIR}/reality_public.key"

  cat > "${CONF_DIR}/10_vless_tcp_reality.json" <<EOF
{
  "inbounds": [{
    "type": "vless",
    "tag": "vless-reality",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{ "uuid": "${UUID}" }],
    "tls": {
      "enabled": true,
      "server_name": "${TLS_DOMAIN}",
      "reality": {
        "enabled": true,
        "handshake": { "server": "${TLS_DOMAIN}", "server_port": 443 },
        "private_key": "${priv}",
        "short_id": [""]
      }
    }
  }]
}
EOF

  merge_config
  svc_restart
  log_action "VLESS Reality 安装完成"
  ok "✅ VLESS + TCP + Reality 安装完成"
  
  ensure_qrencode
  local link="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${TLS_DOMAIN}&fp=chrome&pbk=${pub}&type=tcp#VLESS-REALITY"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${GREEN}导入链接：${RESET}"
  echo -e "${YELLOW}${link}${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
    echo ""
  fi
  show_menu_hint
}

install_vless_ws() {
  ok "开始安装 VLESS + WS协议"
  ensure_singbox
  ensure_systemd_service
  merge_config

  read_ip_default
  read_uuid
  read_port "监听端口" "$DEFAULT_PORT_WS"
  local path="/${UUID}-vless"

  cat > "${CONF_DIR}/11_vless_ws.json" <<EOF
{
  "inbounds": [{
    "type": "vless",
    "tag": "vless-ws",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{ "uuid": "${UUID}" }],
    "transport": {
      "type": "ws",
      "path": "${path}"
    }
  }]
}
EOF

  merge_config
  svc_restart
  log_action "VLESS WS 安装完成"
  ok "✅ VLESS + WS 已安装完成"
  
  ensure_qrencode
  local link="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&type=ws&path=$(printf %s "$path" | sed 's=/=%2F=g')#VLESS-WS"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${GREEN}导入链接：${RESET}"
  echo -e "${YELLOW}${link}${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
    echo ""
  fi
  show_menu_hint
}

install_shadowsocks() {
  ensure_singbox
  ensure_systemd_service
  merge_config

  ok "开始安装 Shadowsocks"
  read_ip_default
  SS_PASS=$(read_password "请输入 Shadowsocks 密码")
  read_port "监听端口" "$DEFAULT_PORT_SS"
  local method="aes-128-gcm"

  cat > "${CONF_DIR}/12_ss.json" <<EOF
{
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "shadowsocks",
    "listen": "::",
    "listen_port": ${PORT},
    "method": "${method}",
    "password": "${SS_PASS}"
  }]
}
EOF

  merge_config
  svc_restart
  log_action "Shadowsocks 安装完成"
  ok "✅ Shadowsocks 已安装完成"
  
  ensure_qrencode
  local b64
  b64="$(printf '%s' "${method}:${SS_PASS}@${SERVER_IP}:${PORT}" | base64 | tr -d '\n')"
  local link="ss://${b64}#Shadowsocks"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${GREEN}导入链接：${RESET}"
  echo -e "${YELLOW}${link}${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
    echo ""
  fi
  show_menu_hint
}

enable_bbr() {
  ok "启用 BBR..."
  modprobe tcp_bbr 2>/dev/null || true
  grep -q '^net.core.default_qdisc=fq' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
  grep -q '^net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
  
  local current_cc
  current_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
  if [ "$current_cc" = "bbr" ]; then
    ok "✅ BBR 已成功启用"
  else
    warn "⚠️ BBR 启用可能失败，当前: $current_cc"
  fi
  log_action "BBR 配置完成"
  show_menu_hint
}

change_port() {
  echo ""
  echo "选择要修改端口的协议："
  echo "1) VLESS Reality"
  echo "2) VLESS WS"
  echo "3) Shadowsocks"
  read -rp "输入 1/2/3: " which
  
  case "$which" in
    1) local file="${CONF_DIR}/10_vless_tcp_reality.json" ;;
    2) local file="${CONF_DIR}/11_vless_ws.json" ;;
    3) local file="${CONF_DIR}/12_ss.json" ;;
    *) err "无效选择"; return ;;
  esac
  
  [ -f "$file" ] || die "未检测到对应协议配置"
  
  local old_port
  old_port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$file" | head -n1)
  ok "当前端口: ${old_port}"
  read_port "新端口" "$old_port"
  
  jq --argjson p "$PORT" '(.. | objects | select(has("listen_port"))).listen_port = $p' "$file" > "${file}.tmp"
  mv "${file}.tmp" "$file"
  merge_config
  svc_restart
  ok "✅ 端口已从 ${old_port} 修改为 ${PORT}"
  log_action "端口修改: ${old_port} -> ${PORT}"
  show_menu_hint
}

change_user_cred() {
  echo ""
  echo "选择要修改凭据的协议："
  echo "1) VLESS（Reality + WS 会同时修改 UUID）"
  echo "2) Shadowsocks 密码"
  read -rp "输入 1/2: " which
  
  case "$which" in
    1)
      local f1="${CONF_DIR}/10_vless_tcp_reality.json"
      local f2="${CONF_DIR}/11_vless_ws.json"
      if [ -f "$f1" ]; then
        local old_uuid
        old_uuid=$(jq -r '..|objects|select(has("users"))|.users[]?.uuid' "$f1" | head -n1)
        ok "当前 UUID: ${old_uuid}"
      fi
      read_uuid
      for f in "$f1" "$f2"; do
        [ -f "$f" ] || continue
        jq --arg u "$UUID" '(.. | objects | select(has("users")) | .users[]? | select(has("uuid"))).uuid = $u' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      done
      merge_config
      svc_restart
      ok "✅ VLESS UUID 已修改为: ${UUID}"
      log_action "VLESS UUID 已修改"
      show_menu_hint
      ;;
    2)
      local f="${CONF_DIR}/12_ss.json"
      [ -f "$f" ] || die "未检测到 Shadowsocks 配置"
      local old_pass
      old_pass=$(jq -r '..|objects|select(has("password"))|.password' "$f" | head -n1)
      ok "当前密码: ${old_pass}"
      local newpass
      newpass=$(read_password "请输入新的 SS 密码")
      jq --arg p "$newpass" '(.. | objects | select(has("password"))).password = $p' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      merge_config
      svc_restart
      ok "✅ Shadowsocks 密码已修改为: ${newpass}"
      log_action "Shadowsocks 密码已修改"
      show_menu_hint
      ;;
    *) err "无效选择" ;;
  esac
}

uninstall_all() {
  echo ""
  warn "⚠️  即将卸载 sing-box 及其所有配置"
  echo "备份文件位于: ${BACKUP_DIR}"
  read -rp "确认卸载？(输入 yes 确认): " confirm
  [ "$confirm" = "yes" ] || { echo "已取消"; return; }
  
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload || true
  else
    rc-service sing-box stop 2>/dev/null || true
    rc-update del sing-box default 2>/dev/null || true
    rm -f /etc/init.d/sing-box
  fi
  
  if [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
    ok "保留备份文件在: ${BACKUP_DIR}"
  fi
  rm -rf "${WORK_DIR}/sing-box" "${CONF_DIR}" "${LOG_DIR}" "${WORK_DIR}/config.json"
  ok "✅ 卸载完成"
  log_action "系统已卸载"
}

show_generated_links() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " ${BLUE}已生成的链接与二维码${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  ensure_qrencode
  local found_any=false
  local f1="${CONF_DIR}/10_vless_tcp_reality.json"
  if [ -f "$f1" ]; then
    found_any=true
    local uuid port sni pub server_ip link
    uuid=$(jq -r '..|objects|select(has("users"))|.users[]?.uuid' "$f1" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f1" | head -n1)
    sni=$(jq -r '..|objects|select(has("server_name"))|.server_name' "$f1" | head -n1)
    pub=$(cat "${CONF_DIR}/reality_public.key" 2>/dev/null || echo "")
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    link="vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&type=tcp#VLESS-REALITY"
    echo -e "${GREEN}🔹 VLESS Reality${RESET}"
    echo -e "${YELLOW}${link}${RESET}"
    echo ""
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo ""
    fi
  fi

  local f2="${CONF_DIR}/11_vless_ws.json"
  if [ -f "$f2" ]; then
    found_any=true
    local uuid port path server_ip link
    uuid=$(jq -r '..|objects|select(has("users"))|.users[]?.uuid' "$f2" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f2" | head -n1)
    path=$(jq -r '..|objects|select(has("transport"))|.transport.path' "$f2" | head -n1)
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    link="vless://${uuid}@${server_ip}:${port}?encryption=none&type=ws&path=$(printf %s "$path" | sed 's=/=%2F=g')#VLESS-WS"
    echo -e "${GREEN}🔹 VLESS WS${RESET}"
    echo -e "${YELLOW}${link}${RESET}"
    echo ""
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo ""
    fi
  fi

  local f3="${CONF_DIR}/12_ss.json"
  if [ -f "$f3" ]; then
    found_any=true
    local pass port method server_ip b64 link
    pass=$(jq -r '..|objects|select(has("password"))|.password' "$f3" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f3" | head -n1)
    method=$(jq -r '..|objects|select(has("method"))|.method' "$f3" | head -n1)
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    b64=$(printf '%s' "${method}:${pass}@${server_ip}:${port}" | base64 | tr -d '\n')
    link="ss://${b64}#Shadowsocks"
    echo -e "${GREEN}🔹 Shadowsocks${RESET}"
    echo -e "${YELLOW}${link}${RESET}"
    echo ""
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo ""
    fi
  fi

  if [ "$found_any" = false ]; then
    warn "未检测到任何已安装的协议配置"
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  show_menu_hint
}

show_service_status() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " ${BLUE}服务状态${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status sing-box --no-pager || true
  else
    rc-service sing-box status || true
  fi
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${YELLOW}最近日志：${RESET}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ -f "${LOG_DIR}/sing-box.log" ]; then
    tail -n 20 "${LOG_DIR}/sing-box.log"
  else
    warn "未找到日志文件"
  fi
  echo ""
  show_menu_hint
}

restore_backup() {
  echo ""
  echo "可用的备份文件："
  if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
    warn "未找到任何备份文件"
    return
  fi
  local backups
  backups=($(ls -t "${BACKUP_DIR}"/config_*.json 2>/dev/null))
  if [ ${#backups[@]} -eq 0 ]; then
    warn "未找到任何备份文件"
    return
  fi
  local i=1
  for backup in "${backups[@]}"; do
    local timestamp
    timestamp=$(basename "$backup" | sed 's/config_\(.*\)\.json/\1/')
    echo "$i) $timestamp"
    i=$((i+1))
  done
  echo ""
  read -rp "选择要恢复的备份编号 (1-${#backups[@]}): " choice
  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#backups[@]}" ]; then
    local selected="${backups[$((choice-1))]}"
    cp "$selected" "$WORK_DIR/config.json"
    svc_restart
    ok "✅ 已恢复备份: $(basename $selected)"
    log_action "恢复备份: $(basename $selected)"
  else
    err "无效选择"
  fi
  show_menu_hint
}

show_menu_hint() {
  echo ""
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${GREEN}如需重新打开菜单，请输入：${RESET}${YELLOW}menu${RESET}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
}

install_shortcut() {
  local cmd_path="/usr/local/bin/menu"
  local script_url="https://raw.githubusercontent.com/jagdd/install/main/installer.sh"
  cat > "$cmd_path" <<EOF
#!/usr/bin/env bash
bash <(curl -Ls ${script_url})
EOF
  chmod +x "$cmd_path"
  log_action "快捷命令已安装"
}

main_menu() {
  while true; do
    clear
    echo -e "${BLUE}╔════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║${RESET}     ${GREEN}Sing-box 代理管理工具${RESET}          ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}        ${YELLOW}Version 2.0 改进版${RESET}            ${BLUE}║${RESET}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}  主要功能${RESET}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "  1) 安装 VLESS + TCP + Reality (直连推荐)"
    echo "  2) 安装 VLESS + WS (CDN/软路由)"
    echo "  3) 安装 Shadowsocks (中转)"
    echo "  4) 启用 BBR 加速 (强烈推荐)"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}  配置管理${RESET}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "  5) 修改端口"
    echo "  6) 修改用户名/密码"
    echo "  7) 查看已生成的链接"
    echo "  8) 查看服务状态"
    echo "  9) 恢复备份配置"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}  系统管理${RESET}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "  10) 卸载脚本"
    echo "  0) 退出"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    read -rp "请选择 [0-10]: " opt
    case "$opt" in
      1) install_vless_tcp_reality ;;
      2) install_vless_ws ;;
      3) install_shadowsocks ;;
      4) enable_bbr ;;
      5) change_port ;;
      6) change_user_cred ;;
      7) show_generated_links ;;
      8) show_service_status ;;
      9) restore_backup ;;
      10) uninstall_all ;;
      0) ok "感谢使用！"; exit 0 ;;
      *) err "无效选择，请输入 0-10"; sleep 2 ;;
    esac
    read -rp "按回车键继续..." dummy
  done
}

main() {
  need_root
  detect_arch
  detect_os
  install_deps
  install_shortcut
  main_menu
}

main

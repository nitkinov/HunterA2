#!/data/data/com.termux/files/usr/bin/bash
# HunterA 2 — Installer for Termux (no root)

set -e

# --- Проверка Termux ---
if [ ! -d "$PREFIX" ] || [ ! -x "$PREFIX/bin/pkg" ]; then
    echo "❌ Ошибка: этот скрипт предназначен для запуска в Termux."
    echo "   $PREFIX не найден или pkg недоступен."
    exit 1
fi

# --- Проверка Python ---
if ! command -v python3 &> /dev/null; then
    echo "⚠️  Python3 не найден. Устанавливаю..."
    pkg install -y python
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PY_VERSION 3.11" | awk '{print ($1 < $2)}') )); then
    echo "⚠️  Обнаружен Python $PY_VERSION. HunterA 2 требует Python 3.11+."
    echo "   Обновите Python: pkg upgrade python"
    echo "   ВНИМАНИЕ: это может потребовать переустановки всех Python-модулей."
fi

# --- Цвета ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║        HunterA 2 — Installer             ║"
echo "║        by tg @heyscally                  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# --- 1. Обновление пакетов ---
echo -e "${YELLOW}[1/6]${NC} Обновление пакетов Termux..."
pkg update -y >/dev/null 2>&1 || true
pkg upgrade -y >/dev/null 2>&1 || true

# --- 2. Системные зависимости ---
echo -e "${YELLOW}[2/6]${NC} Системные зависимости..."
SYSTEM_PKGS=(
    python python-pip clang make pkg-config
    libxml2 libxslt libffi openssl
    binutils binutils-is-llvm rust
    git
)
for pkg in "${SYSTEM_PKGS[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "  → ${CYAN}$pkg${NC}"
        pkg install -y "$pkg" >/dev/null 2>&1 || echo -e "  ${YELLOW}⚠ $pkg не установлен${NC}"
    fi
done

# --- 3. Termux-native Python-пакеты ---
echo -e "${YELLOW}[3/6]${NC} Termux-native пакеты..."
# cryptography — ставим через pkg, чтобы избежать сборки Rust
pkg install -y python-cryptography >/dev/null 2>&1 && \
    echo -e "  ${GREEN}✓${NC} python-cryptography (native)" || \
    echo -e "  ${YELLOW}⚠${NC} python-cryptography — пропускаю"

# --- 4. Настройка pip и TUR ---
echo -e "${YELLOW}[4/6]${NC} Настройка pip и TUR..."
python3 -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1

# Добавляем TUR в конфиг pip как extra-index-url
PIP_CONF_DIR="$HOME/.config/pip"
PIP_CONF="$PIP_CONF_DIR/pip.conf"
mkdir -p "$PIP_CONF_DIR"
if ! grep -q "termux-user-repository" "$PIP_CONF" 2>/dev/null; then
    echo "[install]" >> "$PIP_CONF"
    echo "extra-index-url = https://termux-user-repository.github.io/pypi/" >> "$PIP_CONF"
    echo -e "  ${GREEN}✓${NC} TUR добавлен в pip.conf"
else
    echo -e "  ${GREEN}✓${NC} TUR уже в pip.conf"
fi

# --- 5. Python-зависимости ---
echo -e "${YELLOW}[5/6]${NC} Python-библиотеки..."

# pydantic-core — ставим из TUR
echo -e "  → pydantic-core (из TUR)..."
python3 -m pip install pydantic-core \
    --extra-index-url https://termux-user-repository.github.io/pypi/ \
    --only-binary=:all: >/dev/null 2>&1 || \
    echo -e "  ${YELLOW}⚠ pydantic-core — fallback на pypi${NC}"

# Остальные библиотеки
declare -A PKGS=(
    ["textual"]="textual>=0.50"
    ["httpx"]="httpx>=0.27"
    ["pydantic"]="pydantic>=2.6"
    ["dns"]="dnspython>=2.6"
    ["whois"]="python-whois>=0.9"
    ["bs4"]="beautifulsoup4>=4.12"
    ["cryptography"]="cryptography>=42.0"
    ["lxml"]="lxml>=5.0"
    ["textual_plotext"]="textual-plotext>=0.3"
)

for mod in "${!PKGS[@]}"; do
    spec="${PKGS[$mod]}"
    if python3 -c "import importlib.util; exit(0 if importlib.util.find_spec('$mod') else 1)" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $mod"
        continue
    fi
    echo -e "  → ${CYAN}$spec${NC}"
    # Для lxml — специальные CFLAGS
    if [ "$mod" = "lxml" ]; then
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
echo -e "${YELLOW}[6/6]${NC} Установка HunterA 2..."
cd "$(dirname "$0")"
python3 -m pip install -e . >/dev/null 2>&1
echo -e "  ${GREEN}✓${NC} HunterA 2 установлен"

# --- Итог ---
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Готово!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Запуск: ${BOLD}${CYAN}huntera2${NC}"
echo ""

# --- Проверка ---
echo -e "${YELLOW}Проверка:${NC}"
FAIL=0
for mod in textual httpx pydantic dns whois bs4 cryptography lxml textual_plotext; do
    if python3 -c "import importlib.util; exit(0 if importlib.util.find_spec('$mod') else 1)" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $mod"
    else
        echo -e "  ${RED}✗${NC} $mod"
        FAIL=$((FAIL+1))
    fi
done
echo ""
[ $FAIL -eq 0 ] && echo -e "${GREEN}Все зависимости на месте.${NC}" || \
    echo -e "${YELLOW}$FAIL модулей отсутствуют — запустите install.sh повторно.${NC}"

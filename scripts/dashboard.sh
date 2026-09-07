#!/usr/bin/env bash
#
# Chạy SOC Dashboard, tự nạp .env.
#
# Lý do tồn tại: biến môi trường không sống qua phiên SSH. Chạy thẳng
# `streamlit run src/app.py` trong một terminal mới thì DASHBOARD_PASSWORD rỗng
# và trang chỉ hiện màn hình "chưa được cấu hình bảo mật".
#
#     ./scripts/dashboard.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

cd "${PROJECT_ROOT}"

ENV_FILE="${GATEKEEPER_ENV_FILE:-${PROJECT_ROOT}/.env}"

if [ ! -f "${ENV_FILE}" ]; then
    echo "[-] Không tìm thấy ${ENV_FILE}"
    echo "[-] Tạo file .env rồi thêm DASHBOARD_PASSWORD vào."

    exit 1
fi

# allexport để mọi biến trong .env thành biến môi trường cho tiến trình con
set -o allexport
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +o allexport

# Báo lỗi ngay tại đây thay vì để Streamlit hiện màn hình khoá khó hiểu
if [ -z "${DASHBOARD_PASSWORD:-}" ] && [ -z "${DASHBOARD_ALLOW_ANONYMOUS:-}" ]; then
    echo "[-] ${ENV_FILE} chưa có DASHBOARD_PASSWORD."
    echo "[-] Thêm bằng lệnh:"
    echo "      printf '\\nDASHBOARD_PASSWORD=DatMatKhauCuaMay\\n' >> ${ENV_FILE}"

    exit 1
fi

PORT="${DASHBOARD_PORT:-8501}"

echo "[+] Nạp cấu hình từ ${ENV_FILE}"
echo "[+] Mật khẩu dashboard: đã đặt"
echo "[+] Mở http://localhost:${PORT} (qua IAP tunnel)"
echo

exec streamlit run src/app.py \
    --server.port="${PORT}" \
    --server.address=0.0.0.0

"""
╔══════════════════════════════════════════════════════════════════╗
║         SOC DASHBOARD — DDoS MONITORING CONTROL CENTER           ║
╚══════════════════════════════════════════════════════════════════╝
"""


import glob
import hmac
import io
import os

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from features import FEATURE_NAMES

try:
    from google.cloud import storage as gcs
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False


# Base directory of the dashboard
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# Tự nạp .env ngay khi khởi động.
#
# Biến môi trường KHÔNG sống qua phiên SSH: mở một terminal mới rồi chạy thẳng
# `streamlit run src/app.py` là DASHBOARD_PASSWORD rỗng, và trang chỉ hiện màn
# hình "chưa được cấu hình bảo mật". Đọc .env tại đây khiến dashboard tự đủ,
# chạy kiểu gì cũng có mật khẩu mà không cần nhớ `source .env`.
#
# Không ghi đè biến đã có sẵn trong môi trường, để lệnh `export` tạm thời vẫn
# thắng file .env khi cần.
def _load_dotenv():
    env_path = os.environ.get(
        "GATEKEEPER_ENV_FILE",
        os.path.join(BASE_DIR, "..", ".env")
    )

    try:
        with open(env_path, encoding="utf-8") as fh:
            lines = fh.readlines()

    except OSError:
        return

    for raw in lines:
        line = raw.strip()

        # Bỏ dòng trống và dòng chú thích
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()

        # Bỏ dấu nháy bao quanh giá trị nếu có
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


# Directory containing unprocessed flow logs
LOG_DIR = os.path.join(
    BASE_DIR,
    "..",
    "logs",
    "dirty_flows"
)

GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME", "")
GCS_LOG_PREFIX = os.environ.get("GCS_LOG_PREFIX", "ddos-logs/")
READ_FROM_GCS = bool(GCS_BUCKET_NAME) and GCS_AVAILABLE

# Mật khẩu truy cập dashboard. Trang này công khai toàn bộ IP bị chặn, cổng bị
# nhắm và vector đặc trưng của từng cuộc tấn công — chính là bản đồ để attacker
# biết cái gì lọt lưới. Trên Cloud Run nên đặt IAP phía trước; biến này là lớp
# bảo vệ tối thiểu cho trường hợp deploy --allow-unauthenticated.
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

# Chỉ cho phép chạy không mật khẩu khi khai báo rõ ràng (dev trên máy cá nhân)
ALLOW_ANONYMOUS = os.environ.get(
    "DASHBOARD_ALLOW_ANONYMOUS", ""
).strip().lower() in ("1", "true", "yes", "on")

# Giới hạn số file CSV đọc mỗi lần refresh. Không có giới hạn thì dashboard sẽ
# tải TOÀN BỘ bucket mỗi 10 giây, và chi phí đó tăng tuyến tính mãi mãi.
MAX_LOG_FILES = int(os.environ.get("DASHBOARD_MAX_LOG_FILES", "50"))

# Chu kỳ tự làm mới, tính bằng giây
REFRESH_INTERVAL_S = int(os.environ.get("DASHBOARD_REFRESH_S", "10"))


# Multiclass model path.
#
# PHẢI là multiclass_eval.pkl, không phải multiclass.pkl. Cùng một lý lẽ với
# FIX-31 ở tuyến nhị phân: multiclass.pkl được fit trên 100% dữ liệu nên không
# còn dòng nào chưa thấy để đo, mọi con số gán cho nó đều không kiểm chứng được.
#
# Ở đây hậu quả không chỉ là lý thuyết. Đo trên 60.000 dòng thuộc lớp Syn:
#
#                          Syn ngày 1     Syn ngày 2
#       multiclass.pkl        40,84%         99,97%
#       multiclass_eval.pkl   99,72%         60,50%
#
# multiclass.pkl sai 59,1% sang UDPLag trên chính dữ liệu nó đã học thuộc.
# Nguyên nhân: cap 3 triệu dòng/lớp lấy ngẫu nhiên từ 5,94 triệu dòng Syn gộp
# hai ngày, nên khoảng 77% mẫu là ngày 2 và model bỏ rơi phân bố ngày 1.
#
# multiclass_eval.pkl fit ngày 1 / chấm ngày 2 chưa từng thấy, nên có số đo
# trung thực: tổng 88,73%, riêng lớp Syn 88,17%.
MULTICLASS_MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "multiclass_eval.pkl"
)


# Label encoder path
LABEL_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "label.pkl"
)


# Feature columns used by the multiclass model, shared with the training
# pipeline so the dashboard cannot drift out of sync with the model
FEATURE_COLUMNS = list(FEATURE_NAMES)


# Core color palette, shared by the CSS theme and the charts
# Modeled after the CloudWatch dashboard: near-black canvas, dark navy
# panels, and an amber/gold accent for data
COLORS = {
    "bg": "#0e1015",
    "panel": "#181b22",
    "panel_border": "#2a2e38",
    "sidebar": "#14161c",
    "sidebar_dark": "#0e1015",
    "text": "#eceef2",
    "muted": "#8b909c",
    "critical": "#ff9900",
    "warning": "#f5c542",
    "accent": "#ff9900",
    "grid": "#242832",
}

ATTACK_COLOR_SEQUENCE = [
    "#ff9900", "#f5c542", "#2ec9c9", "#6fb1e8",
    "#c792ea", "#e8735f", "#a6c96a", "#d9a441",
]


# Read all CSV files from a GCS bucket, used on Cloud Run since there is
# no shared disk with VM1, which is the machine actually writing the logs
def _load_from_gcs(bucket_name, prefix):
    client = gcs.Client()
    blobs = list(client.list_blobs(bucket_name, prefix=prefix))
    csv_blobs = [b for b in blobs if b.name.endswith(".csv")]

    # Chỉ lấy các file mới nhất. Bản cũ tải toàn bộ bucket mỗi 10 giây.
    csv_blobs.sort(key=lambda b: b.updated, reverse=True)
    csv_blobs = csv_blobs[:MAX_LOG_FILES]

    if not csv_blobs:
        return pd.DataFrame(), []

    frames = []
    for blob in csv_blobs:
        try:
            content = blob.download_as_bytes()
            frames.append(pd.read_csv(io.BytesIO(content)))
        except Exception as exc:
            st.warning(f"Unable to read gs://{bucket_name}/{blob.name}: {exc}")

    if not frames:
        return pd.DataFrame(), [b.name for b in csv_blobs]

    return pd.concat(frames, ignore_index=True), [b.name for b in csv_blobs]


# Read all CSV files from local disk
def _load_from_local(log_dir):
    csv_files = sorted(
        glob.glob(os.path.join(log_dir, "*.csv")),
        key=os.path.getmtime,
        reverse=True
    )[:MAX_LOG_FILES]

    if not csv_files:
        return pd.DataFrame(), csv_files

    frames = []
    for path in csv_files:
        try:
            frames.append(pd.read_csv(path))
        except Exception as exc:
            st.warning(f"Unable to read {os.path.basename(path)}: {exc}")

    if not frames:
        return pd.DataFrame(), csv_files

    return pd.concat(frames, ignore_index=True), csv_files


# Load and merge all dirty flow CSV files
@st.cache_data(ttl=REFRESH_INTERVAL_S)
def load_dirty_flows(log_dir, read_from_gcs, bucket_name, prefix):
    if read_from_gcs:
        df, sources = _load_from_gcs(bucket_name, prefix)
    else:
        df, sources = _load_from_local(log_dir)

    if df.empty:
        return df, sources

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df, sources


# Load the multiclass model and label encoder
@st.cache_resource
def load_multiclass_model():
    # Check whether the multiclass model exists
    if not os.path.exists(MULTICLASS_MODEL_PATH):
        return None, None

    # Load the model files
    try:
        model = joblib.load(MULTICLASS_MODEL_PATH)
        label_encoder = None

        # Load the label encoder when available
        if os.path.exists(LABEL_ENCODER_PATH):
            label_encoder = joblib.load(LABEL_ENCODER_PATH)

        # Đối chiếu hợp đồng feature ngay lúc nạp, giống gatekeeper làm với
        # model nhị phân. Nếu multiclass_eval.pkl là bản cũ, predict() sẽ ném lỗi ở
        # MỌI lần gọi; bản trước chỉ hiện một dòng warning nhỏ giữa trang rồi
        # âm thầm vẽ biểu đồ bằng cột `reason`. Người xem vẫn thấy một biểu đồ
        # "phân loại tấn công" trông bình thường mà thực chất model đã chết.
        n_model = getattr(model, "n_features_in_", None)

        if n_model is not None and int(n_model) != len(FEATURE_COLUMNS):
            st.error(
                f"⚠️ `models/multiclass_eval.pkl` nhận {int(n_model)} feature "
                f"nhưng `features.py` khai báo {len(FEATURE_COLUMNS)}. "
                "Model đã cũ so với bộ đặc trưng hiện tại — biểu đồ phân loại "
                "sẽ dùng cột `reason` thay vì dự đoán. "
                "Chạy lại `python3 src/trainer.py`."
            )

            return None, label_encoder

        return model, label_encoder

    # Handle model loading errors
    except Exception as exc:
        st.error(f"Unable to load multiclass model: {exc}")
        return None, None


# Classify detected attacks using the multiclass model.
#
# Chỉ suy luận trên những dòng THỰC SỰ có vector đặc trưng. Bản cũ gọi
# .fillna(0) cho mọi dòng, kể cả dòng do rate limiter chặn với features=None —
# vector toàn số 0 vẫn được model gán một nhãn nào đó, và biểu đồ
# "Attack Type Distribution" hiển thị loại tấn công hoàn toàn bịa ra.
def classify_attack_types(df, model, label_encoder):
    # Copy to avoid mutating the original DataFrame
    df = df.copy()

    # Use the detection reason as the default attack label
    df["attack_type"] = df["reason"]

    # Keep the original labels when no model is available
    if model is None:
        return df, 0

    # Check whether all required feature columns exist
    has_feature_columns = set(FEATURE_COLUMNS).issubset(df.columns)

    if not has_feature_columns:
        return df, 0

    # Dòng đủ điều kiện suy luận: có cờ has_features (log mới) hoặc, với log
    # cũ chưa có cột đó, không có ô đặc trưng nào bị thiếu.
    if "has_features" in df.columns:
        eligible = pd.to_numeric(
            df["has_features"], errors="coerce"
        ).fillna(0).astype(int) == 1

    else:
        eligible = df[FEATURE_COLUMNS].notna().all(axis=1)

    skipped = int((~eligible).sum())

    if not eligible.any():
        return df, skipped

    X = df.loc[eligible, FEATURE_COLUMNS].astype(np.float32)

    # Run multiclass prediction on the eligible rows only
    try:
        preds = model.predict(X)

        # Convert numeric predictions back to attack names
        if label_encoder is not None:
            preds = label_encoder.inverse_transform(preds.astype(int))

        # Store the predicted attack types
        df.loc[eligible, "attack_type"] = preds

    # Keep the original labels only when prediction fails
    except Exception as exc:
        st.warning(
            f"Multiclass prediction failed ({exc}). "
            "Using original labels instead."
        )

        return df, skipped

    return df, skipped


# Inject custom CSS for the whole dashboard theme
def inject_theme():
    st.markdown(
        f"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

            html, body, [class*="css"] {{
                font-family: 'Inter', sans-serif;
            }}

            .stApp {{
                background: {COLORS["bg"]};
                color: {COLORS["text"]};
            }}

            /* Sidebar styled after the CloudWatch dark nav panel */
            section[data-testid="stSidebar"] {{
                background: {COLORS["sidebar"]};
                border-right: 1px solid {COLORS["panel_border"]};
            }}
            section[data-testid="stSidebar"] * {{
                color: {COLORS["text"]} !important;
            }}
            section[data-testid="stSidebar"] hr {{
                border-color: {COLORS["panel_border"]} !important;
            }}

            /* Header bar mimicking the CloudWatch breadcrumb and title strip */
            .soc-header {{
                display: flex;
                align-items: center;
                gap: 14px;
                padding: 14px 18px;
                background: {COLORS["panel"]};
                border: 1px solid {COLORS["panel_border"]};
                border-left: 4px solid {COLORS["accent"]};
                border-radius: 6px;
                margin-bottom: 18px;
            }}
            .soc-header h1 {{
                font-size: 1.3rem;
                font-weight: 700;
                letter-spacing: 0.01em;
                margin: 0;
                color: {COLORS["text"]};
            }}
            .soc-header .soc-sub {{
                font-family: 'Roboto Mono', monospace;
                font-size: 0.75rem;
                color: {COLORS["muted"]};
                margin-top: 2px;
            }}
            .soc-pulse {{
                width: 10px;
                height: 10px;
                border-radius: 50%;
                background: {COLORS["accent"]};
                box-shadow: 0 0 0 0 rgba(255,153,0,0.6);
                animation: soc-ping 1.8s ease-out infinite;
                flex-shrink: 0;
            }}
            @keyframes soc-ping {{
                0%   {{ box-shadow: 0 0 0 0 rgba(255,153,0,0.55); }}
                70%  {{ box-shadow: 0 0 0 9px rgba(255,153,0,0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(255,153,0,0); }}
            }}
            @media (prefers-reduced-motion: reduce) {{
                .soc-pulse {{ animation: none; }}
            }}

            /* Metric cards styled like CloudWatch's dark flat widgets */
            div[data-testid="stMetric"] {{
                background: {COLORS["panel"]};
                border: 1px solid {COLORS["panel_border"]};
                border-radius: 6px;
                padding: 12px 16px;
            }}
            div[data-testid="stMetricLabel"] {{
                font-family: 'Inter', sans-serif;
                font-size: 0.72rem;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                color: {COLORS["muted"]};
            }}
            div[data-testid="stMetricValue"] {{
                font-family: 'Roboto Mono', monospace;
                font-size: 1.6rem;
                color: {COLORS["accent"]};
            }}

            /* Section headings above each chart, CloudWatch widget-title style */
            h3 {{
                font-size: 0.95rem !important;
                font-weight: 600 !important;
                color: {COLORS["text"]} !important;
                letter-spacing: 0.01em;
                border-bottom: 1px solid {COLORS["panel_border"]};
                padding-bottom: 8px;
            }}

            /* Data tables styled as a flat bordered dark panel */
            div[data-testid="stDataFrame"] {{
                border: 1px solid {COLORS["panel_border"]};
                border-radius: 6px;
                overflow: hidden;
            }}

            hr {{
                border-color: {COLORS["panel_border"]} !important;
            }}

            /* Text input styled like the CloudWatch search field */
            div[data-testid="stTextInput"] input {{
                background: {COLORS["panel"]} !important;
                color: {COLORS["text"]} !important;
                border: 1px solid {COLORS["panel_border"]} !important;
                border-radius: 4px !important;
            }}
        </style>
        """,
        unsafe_allow_html=True
    )


# Ngủ một nhịp rồi rerun.
#
# Nhánh "chưa có dữ liệu" của bản cũ gọi st.rerun() KHÔNG kèm sleep, tạo ra
# vòng lặp quay tít: mỗi vòng là một lượt list_blobs() + download toàn bộ
# bucket, chạy nhanh hết mức CPU cho phép. Trên Cloud Run đó vừa là hoá đơn
# GCS tăng vọt vừa là một instance luôn ở 100% CPU.
def schedule_refresh():
    import time

    time.sleep(REFRESH_INTERVAL_S)
    st.rerun()


# Chặn truy cập khi chưa nhập đúng mật khẩu.
#
# Trả về True nếu được phép xem. So sánh bằng hmac.compare_digest để không rò
# rỉ độ dài/nội dung mật khẩu qua thời gian phản hồi.
def check_password():
    if ALLOW_ANONYMOUS:
        return True

    if not DASHBOARD_PASSWORD:
        st.error(
            "🔒 Dashboard chưa được cấu hình bảo mật.\n\n"
            "Trang này công khai toàn bộ IP bị chặn, cổng bị nhắm và vector "
            "đặc trưng của từng cuộc tấn công. Hãy đặt biến môi trường "
            "`DASHBOARD_PASSWORD`, hoặc đặt Cloud IAP phía trước và bật "
            "`DASHBOARD_ALLOW_ANONYMOUS=1`."
        )

        st.stop()

    if st.session_state.get("authenticated"):
        return True

    st.markdown("### 🔒 SOC Dashboard")

    entered = st.text_input(
        "Mật khẩu truy cập",
        type="password",
        key="password_input"
    )

    if entered:
        if hmac.compare_digest(entered, DASHBOARD_PASSWORD):
            st.session_state["authenticated"] = True

            return True

        st.error("Mật khẩu không đúng.")

    st.stop()


# Render the dashboard header along with the data source status line
def render_header(source_label):
    st.markdown(
        f"""
        <div class="soc-header">
            <div class="soc-pulse"></div>
            <div>
                <h1>SOC · Real-Time DDoS Monitoring</h1>
                <div class="soc-sub">{source_label}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# Start the Streamlit dashboard
def main():
    # Configure the Streamlit page
    st.set_page_config(
        page_title="SOC Dashboard — DDoS Monitor",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Apply the custom theme to the whole page
    inject_theme()

    # Yêu cầu xác thực trước khi render bất cứ dữ liệu nào
    check_password()

    # Sidebar configuration options
    with st.sidebar:
        st.markdown("##### ⚙️ Configuration")

        auto_refresh = st.checkbox(
            f"Automatically refresh every {REFRESH_INTERVAL_S}s",
            value=True
        )

        st.divider()

        source_caption = (
            f"gs://{GCS_BUCKET_NAME}/{GCS_LOG_PREFIX}  ·  Cloud Run"
            if READ_FROM_GCS else
            "logs/dirty_flows/  ·  local on VM1"
        )
        st.caption(f"**Data source**  \n`{source_caption}`")

    render_header(source_caption)

    # Search bar for filtering logs, styled after the Kibana query bar
    search_term = st.text_input(
        "Search",
        placeholder="Search...",
        label_visibility="collapsed",
    )

    # Load the dirty flow logs
    df, csv_files = load_dirty_flows(
        LOG_DIR, READ_FROM_GCS, GCS_BUCKET_NAME, GCS_LOG_PREFIX
    )

    # Show an empty-state message when no logs exist
    if df.empty:
        source_hint = (
            f"GCS bucket `{GCS_BUCKET_NAME}`" if READ_FROM_GCS
            else "`logs/dirty_flows/`"
        )
        st.info(
            f"No data found in {source_hint}. "
            "The dashboard will update when Gatekeeper starts blocking traffic."
        )

        # Refresh the dashboard when enabled
        if auto_refresh:
            schedule_refresh()

        return

    # Load the multiclass classification model
    model, label_encoder = load_multiclass_model()

    # Warn when the multiclass model is unavailable
    if model is None:
        st.warning(
            "Unable to find `models/multiclass_eval.pkl`. "
            "Attack charts will use the `reason` field instead of multiclass predictions."
        )

    # Classify attacks using the loaded model
    df, skipped = classify_attack_types(df, model, label_encoder)

    # Nói rõ khi có dòng không suy luận được, thay vì gán nhãn bịa
    if skipped:
        st.caption(
            f"ℹ️ {skipped:,} sự kiện không có vector đặc trưng "
            f"(flow quá nhỏ, bị rate limiter chặn) nên giữ nguyên nhãn "
            f"`reason` thay vì đoán loại tấn công."
        )

    # Apply the free-text search filter across all columns.
    #
    # regex=False là bắt buộc: mặc định str.contains coi chuỗi nhập vào là
    # biểu thức chính quy, nên gõ "(" là crash và gõ "(a+)+$" là ReDoS treo
    # nguyên instance.
    if search_term:
        mask = df.apply(
            lambda col: col.astype(str).str.contains(
                search_term, case=False, na=False, regex=False
            )
        ).any(axis=1)
        df = df[mask]

        if df.empty:
            st.info(f"No results match \"{search_term}\".")
            return

    # High-level security metrics
    col1, col2, col3, col4 = st.columns(4)

    # Count unique blocked source IPs
    col1.metric("Blocked IPs", f"{df['src_ip'].nunique():,}")

    # Count total blocked events
    col2.metric("DROP Events", f"{len(df):,}")

    # Count scanned CSV files
    col3.metric("CSV Files Scanned", f"{len(csv_files):,}")

    # Find the latest recorded event
    last_timestamp = df["timestamp"].max()

    # Display the latest event time
    if pd.notna(last_timestamp):
        latest_time = last_timestamp.strftime("%H:%M:%S")
    else:
        latest_time = "—"

    col4.metric("Latest Update", latest_time)

    st.divider()

    # Two columns for the main charts
    left, right = st.columns([1, 1])

    # Attack distribution chart
    with left:
        st.markdown("### Attack Type Distribution")

        # Count events by attack type
        pie_data = df["attack_type"].value_counts().reset_index()
        pie_data.columns = ["attack_type", "count"]

        # Build the attack distribution chart
        fig_pie = px.pie(
            pie_data,
            names="attack_type",
            values="count",
            hole=0.62,
            color_discrete_sequence=ATTACK_COLOR_SEQUENCE,
        )
        fig_pie.update_traces(
            textfont_size=12,
            marker=dict(line=dict(color=COLORS["bg"], width=2)),
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color=COLORS["text"],
            font_family="Inter, sans-serif",
            legend=dict(orientation="h", yanchor="bottom", y=-0.15),
            margin=dict(t=10, b=10, l=10, r=10),
        )

        # Render the pie chart
        st.plotly_chart(fig_pie, use_container_width=True)

    # Blocked traffic over time
    with right:
        st.markdown("### Blocked Traffic Over Time")

        # Aggregate blocked events by minute
        df_time = (
            df.set_index("timestamp")
            .resample("1min")
            .size()
            .reset_index(name="blocked_count")
        )

        # Build the traffic timeline chart, styled after the CloudWatch
        # spiky orange line chart
        fig_line = go.Figure()
        fig_line.add_trace(
            go.Scatter(
                x=df_time["timestamp"],
                y=df_time["blocked_count"],
                mode="lines",
                line=dict(color=COLORS["accent"], width=1.6),
            )
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color=COLORS["text"],
            font_family="Inter, sans-serif",
            xaxis=dict(gridcolor=COLORS["grid"], showgrid=False),
            yaxis=dict(gridcolor=COLORS["grid"], showgrid=True, title="Event count"),
            margin=dict(t=10, b=10, l=10, r=10),
        )

        # Render the timeline chart
        st.plotly_chart(fig_line, use_container_width=True)

    st.divider()

    # Most active attacking IPs
    st.markdown("### Top 10 Attacking IPs")

    # Count blocked events per source IP
    top_ips = df["src_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["src_ip", "blocked_count"]

    # Display the top attacking IP table
    st.dataframe(top_ips, use_container_width=True, hide_index=True)

    # Latest detailed security logs
    st.markdown("### Detailed Logs — Latest 100 Events")

    # Columns shown in the dashboard. Lọc theo cột thực có để log cũ (thiếu
    # cột mới) không làm cả trang crash bằng KeyError.
    display_columns = [
        column
        for column in [
            "timestamp",
            "src_ip",
            "protocol",
            "dst_port",
            "pps",
            "reason",
            "attack_type"
        ]
        if column in df.columns
    ]

    # Sort logs by newest timestamp
    latest_logs = (
        df.sort_values("timestamp", ascending=False)
        [display_columns]
        .head(100)
    )

    # Render the detailed log table
    st.dataframe(latest_logs, use_container_width=True, hide_index=True)

    # Refresh the dashboard on the configured interval
    if auto_refresh:
        schedule_refresh()


# Run the dashboard application
if __name__ == "__main__":
    main()
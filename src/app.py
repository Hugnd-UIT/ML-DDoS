"""
╔══════════════════════════════════════════════════════════════════╗
║         SOC DASHBOARD — DDoS MONITORING CONTROL CENTER           ║
╚══════════════════════════════════════════════════════════════════╝
"""


import glob
import io
import os

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:
    from google.cloud import storage as gcs
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False


# Base directory of the dashboard
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


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


# Multiclass model path
MULTICLASS_MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "multiclass.pkl"
)


# Label encoder path
LABEL_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "label.pkl"
)


# 19 feature columns used by the multiclass model
FEATURE_COLUMNS = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Down/Up Ratio",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Total",
    "Protocol",
    "SYN Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward"
]


# Core color palette, shared by the CSS theme and the charts
COLORS = {
    "bg": "#0a0e14",
    "panel": "#11161f",
    "panel_border": "#1f2937",
    "text": "#e6e9ef",
    "muted": "#7c8798",
    "critical": "#ff5c5c",
    "warning": "#ffb454",
    "accent": "#00d9c0",
    "grid": "#1a2130",
}

ATTACK_COLOR_SEQUENCE = [
    "#00d9c0", "#ff5c5c", "#ffb454", "#5b8cff",
    "#c792ea", "#66d9ef", "#f78c6c", "#a6e22e",
]


# Read all CSV files from a GCS bucket, used on Cloud Run since there is
# no shared disk with VM1, which is the machine actually writing the logs
def _load_from_gcs(bucket_name, prefix):
    client = gcs.Client()
    blobs = list(client.list_blobs(bucket_name, prefix=prefix))
    csv_blobs = [b for b in blobs if b.name.endswith(".csv")]

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
    csv_files = sorted(glob.glob(os.path.join(log_dir, "*.csv")))
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
@st.cache_data(ttl=10)
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

        return model, label_encoder

    # Handle model loading errors
    except Exception as exc:
        st.error(f"Unable to load multiclass model: {exc}")
        return None, None


# Classify detected attacks using the multiclass model
def classify_attack_types(df, model, label_encoder):
    # Copy to avoid mutating the original DataFrame
    df = df.copy()

    # Use the detection reason as the default attack label
    df["attack_type"] = df["reason"]

    # Keep the original labels when no model is available
    if model is None:
        return df

    # Check whether all required feature columns exist
    has_feature_columns = set(FEATURE_COLUMNS).issubset(df.columns)

    # Identify rows containing all 19 feature values
    if has_feature_columns:
        has_features = df[FEATURE_COLUMNS].notna().all(axis=1)
    else:
        has_features = pd.Series(False, index=df.index)

    # Select only rows that can be classified by the model
    ai_rows = df[has_features]

    # Keep the default reason labels when no rows qualify
    if ai_rows.empty:
        return df

    # Build the model input using the exact feature order
    X = ai_rows[FEATURE_COLUMNS].astype(np.float32)

    # Run multiclass prediction
    try:
        preds = model.predict(X)

        # Convert numeric predictions back to attack names
        if label_encoder is not None:
            preds = label_encoder.inverse_transform(preds.astype(int))

        # Store the predicted attack types
        df.loc[ai_rows.index, "attack_type"] = preds

    # Keep the original reason labels when prediction fails
    except Exception as exc:
        st.warning(
            f"Multiclass prediction failed ({exc}). "
            "Using the original 'reason' labels instead."
        )

    return df


# Inject custom CSS for the whole dashboard theme
def inject_theme():
    st.markdown(
        f"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

            html, body, [class*="css"] {{
                font-family: 'Inter', sans-serif;
            }}

            .stApp {{
                background:
                    radial-gradient(circle at 15% 0%, rgba(0,217,192,0.06), transparent 45%),
                    {COLORS["bg"]};
                color: {COLORS["text"]};
            }}

            section[data-testid="stSidebar"] {{
                background-color: {COLORS["panel"]};
                border-right: 1px solid {COLORS["panel_border"]};
            }}

            /* Header bar with a pulsing status dot */
            .soc-header {{
                display: flex;
                align-items: center;
                gap: 14px;
                padding: 4px 0 18px 0;
                border-bottom: 1px solid {COLORS["panel_border"]};
                margin-bottom: 22px;
            }}
            .soc-header h1 {{
                font-size: 1.55rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                margin: 0;
                color: {COLORS["text"]};
            }}
            .soc-header .soc-sub {{
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.78rem;
                color: {COLORS["muted"]};
                margin-top: 2px;
            }}
            .soc-pulse {{
                width: 11px;
                height: 11px;
                border-radius: 50%;
                background: {COLORS["critical"]};
                box-shadow: 0 0 0 0 rgba(255,92,92,0.6);
                animation: soc-ping 1.8s ease-out infinite;
                flex-shrink: 0;
            }}
            @keyframes soc-ping {{
                0%   {{ box-shadow: 0 0 0 0 rgba(255,92,92,0.55); }}
                70%  {{ box-shadow: 0 0 0 10px rgba(255,92,92,0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(255,92,92,0); }}
            }}
            @media (prefers-reduced-motion: reduce) {{
                .soc-pulse {{ animation: none; }}
            }}

            /* Metric cards with a colored left border */
            div[data-testid="stMetric"] {{
                background: {COLORS["panel"]};
                border: 1px solid {COLORS["panel_border"]};
                border-left: 3px solid {COLORS["accent"]};
                border-radius: 10px;
                padding: 14px 18px;
            }}
            div[data-testid="stMetricLabel"] {{
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.72rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: {COLORS["muted"]};
            }}
            div[data-testid="stMetricValue"] {{
                font-family: 'JetBrains Mono', monospace;
                font-size: 1.7rem;
                color: {COLORS["text"]};
            }}

            /* Section headings above each chart */
            h3 {{
                font-size: 1rem !important;
                font-weight: 600 !important;
                color: {COLORS["text"]} !important;
                letter-spacing: 0.01em;
            }}

            /* Data tables use a monospace font for easier scanning */
            div[data-testid="stDataFrame"] {{
                border: 1px solid {COLORS["panel_border"]};
                border-radius: 10px;
                overflow: hidden;
            }}

            hr {{
                border-color: {COLORS["panel_border"]} !important;
            }}
        </style>
        """,
        unsafe_allow_html=True
    )


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

    # Sidebar configuration options
    with st.sidebar:
        st.markdown("##### ⚙️ Configuration")

        auto_refresh = st.checkbox(
            "Automatically refresh every 10s",
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
            st.rerun()

        return

    # Load the multiclass classification model
    model, label_encoder = load_multiclass_model()

    # Warn when the multiclass model is unavailable
    if model is None:
        st.warning(
            "Unable to find `models/multiclass.pkl`. "
            "Attack charts will use the `reason` field instead of multiclass predictions."
        )

    # Classify attacks using the loaded model
    df = classify_attack_types(df, model, label_encoder)

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

        # Build the traffic timeline chart with an area fill under the line
        fig_line = go.Figure()
        fig_line.add_trace(
            go.Scatter(
                x=df_time["timestamp"],
                y=df_time["blocked_count"],
                mode="lines+markers",
                line=dict(color=COLORS["critical"], width=2),
                marker=dict(size=5, color=COLORS["critical"]),
                fill="tozeroy",
                fillcolor="rgba(255,92,92,0.12)",
            )
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color=COLORS["text"],
            xaxis=dict(gridcolor=COLORS["grid"], showgrid=True),
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

    # Columns shown in the dashboard
    display_columns = [
        "timestamp",
        "src_ip",
        "protocol",
        "dst_port",
        "pps",
        "reason",
        "attack_type"
    ]

    # Sort logs by newest timestamp
    latest_logs = (
        df.sort_values("timestamp", ascending=False)
        [display_columns]
        .head(100)
    )

    # Render the detailed log table
    st.dataframe(latest_logs, use_container_width=True, hide_index=True)

    # Refresh the dashboard every 10 seconds
    if auto_refresh:
        import time
        time.sleep(10)
        st.rerun()


# Run the dashboard application
if __name__ == "__main__":
    main()
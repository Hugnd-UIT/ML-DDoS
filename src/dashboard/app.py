"""
╔══════════════════════════════════════════════════════════════════╗
║         SOC DASHBOARD — DDoS MONITORING CONTROL CENTER           ║
╚══════════════════════════════════════════════════════════════════╝
"""


import glob
import os

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st


# Define the base directory of the dashboard
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# Define the directory containing dirty flow logs
LOG_DIR = os.path.join(
    BASE_DIR,
    "..",
    "..",
    "logs",
    "dirty_flows"
)


# Define the multiclass model path
MULTICLASS_MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "..",
    "models",
    "multiclass.pkl"
)


# Define the label encoder path
LABEL_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "..",
    "..",
    "models",
    "label.pkl"
)


# Define the 19 feature columns used by the multiclass model
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


# Load and merge all dirty flow CSV files
@st.cache_data(ttl=10)
def load_dirty_flows(log_dir):
    # Find all CSV files in the log directory
    csv_files = sorted(
        glob.glob(
            os.path.join(
                log_dir,
                "*.csv"
            )
        )
    )


    # Return empty data when no log files exist
    if not csv_files:
        return (
            pd.DataFrame(),
            csv_files
        )


    # Store successfully loaded DataFrames
    frames = []


    # Read each CSV file
    for path in csv_files:
        try:
            frame = pd.read_csv(
                path
            )

            frames.append(
                frame
            )

        except Exception as exc:
            # Warn when a CSV file cannot be read
            st.warning(
                f"Unable to read "
                f"{os.path.basename(path)}: "
                f"{exc}"
            )


    # Return empty data when every file failed
    if not frames:
        return (
            pd.DataFrame(),
            csv_files
        )


    # Merge all loaded CSV files
    df = pd.concat(
        frames,
        ignore_index=True
    )


    # Convert timestamps into datetime values
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )


    return (
        df,
        csv_files
    )


# Load the multiclass model and label encoder
@st.cache_resource
def load_multiclass_model():
    # Check whether the multiclass model exists
    if not os.path.exists(
        MULTICLASS_MODEL_PATH
    ):
        return (
            None,
            None
        )


    # Load the model files
    try:
        model = joblib.load(
            MULTICLASS_MODEL_PATH
        )

        label_encoder = None


        # Load the label encoder when available
        if os.path.exists(
            LABEL_ENCODER_PATH
        ):
            label_encoder = joblib.load(
                LABEL_ENCODER_PATH
            )


        return (
            model,
            label_encoder
        )


    # Handle model loading errors
    except Exception as exc:
        st.error(
            f"Unable to load multiclass model: "
            f"{exc}"
        )

        return (
            None,
            None
        )


# Classify detected attacks using the multiclass model
def classify_attack_types(
    df,
    model,
    label_encoder
):
    # Create a copy to avoid modifying the original DataFrame
    df = df.copy()


    # Use the detection reason as the default attack label
    df["attack_type"] = df["reason"]


    # Keep the original labels when no model is available
    if model is None:
        return df


    # Check whether all required feature columns exist
    has_feature_columns = (
        set(FEATURE_COLUMNS).issubset(
            df.columns
        )
    )


    # Identify rows containing all 19 feature values
    if has_feature_columns:
        has_features = (
            df[FEATURE_COLUMNS]
            .notna()
            .all(axis=1)
        )
    else:
        has_features = pd.Series(
            False,
            index=df.index
        )


    # Select only rows that can be classified by the model
    ai_rows = df[
        has_features
    ]


    # Keep the default reason labels when no AI rows exist
    if ai_rows.empty:
        return df


    # Build the model input using the exact feature order
    X = (
        ai_rows[FEATURE_COLUMNS]
        .astype(np.float32)
    )


    # Run multiclass prediction
    try:
        preds = model.predict(
            X
        )


        # Convert numeric predictions back to attack names
        if label_encoder is not None:
            preds = (
                label_encoder
                .inverse_transform(
                    preds.astype(int)
                )
            )


        # Store the predicted attack types
        df.loc[
            ai_rows.index,
            "attack_type"
        ] = preds


    # Keep the original reason labels when prediction fails
    except Exception as exc:
        st.warning(
            "Multiclass prediction failed "
            f"({exc}). Using the original "
            "'reason' labels instead."
        )


    return df


# Start the Streamlit dashboard
def main():
    # Configure the Streamlit page
    st.set_page_config(
        page_title="SOC Dashboard — DDoS Monitor",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )


    # Apply the dashboard dark theme
    st.markdown(
        """
        <style>
            .stApp {
                background-color: #0e1117;
                color: #e6e6e6;
            }

            [data-testid="stMetricValue"] {
                font-size: 1.8rem;
            }
        </style>
        """,
        unsafe_allow_html=True
    )


    # Display the dashboard title
    st.title(
        "🛡️ SOC Dashboard — "
        "Real-Time DDoS Monitoring"
    )


    # Configure dashboard options
    with st.sidebar:
        st.header(
            "⚙️ Configuration"
        )

        auto_refresh = st.checkbox(
            "Automatically refresh every 10s",
            value=True
        )

        st.caption(
            "Data source: "
            "`logs/dirty_flows/`"
        )


    # Load the dirty flow logs
    df, csv_files = load_dirty_flows(
        LOG_DIR
    )


    # Show an empty-state message when no logs exist
    if df.empty:
        st.info(
            "No data found in "
            "`logs/dirty_flows/`. "
            "The dashboard will update "
            "when Gatekeeper starts "
            "blocking traffic."
        )


        # Refresh the dashboard when enabled
        if auto_refresh:
            st.rerun()

        return


    # Load the multiclass classification model
    model, label_encoder = (
        load_multiclass_model()
    )


    # Warn when the multiclass model is unavailable
    if model is None:
        st.warning(
            "Unable to find "
            "`models/multiclass.pkl`. "
            "Attack charts will use the "
            "`reason` field instead of "
            "multiclass predictions."
        )


    # Classify attacks using the loaded model
    df = classify_attack_types(
        df,
        model,
        label_encoder
    )


    # Display high-level security metrics
    col1, col2, col3, col4 = (
        st.columns(4)
    )


    # Count unique blocked source IPs
    col1.metric(
        "Blocked IPs",
        f"{df['src_ip'].nunique():,}"
    )


    # Count total blocked events
    col2.metric(
        "DROP Events",
        f"{len(df):,}"
    )


    # Count scanned CSV files
    col3.metric(
        "CSV Files Scanned",
        f"{len(csv_files):,}"
    )


    # Find the latest recorded event
    last_timestamp = (
        df["timestamp"].max()
    )


    # Display the latest event time
    if pd.notna(last_timestamp):
        latest_time = (
            last_timestamp.strftime(
                "%H:%M:%S"
            )
        )
    else:
        latest_time = "—"


    col4.metric(
        "Latest Update",
        latest_time
    )


    # Add a visual separator
    st.divider()


    # Create two columns for the main charts
    left, right = st.columns(
        [1, 1]
    )


    # Display the attack distribution chart
    with left:
        st.subheader(
            "🥧 Attack Type Distribution"
        )


        # Count events by attack type
        pie_data = (
            df["attack_type"]
            .value_counts()
            .reset_index()
        )


        # Rename columns for Plotly
        pie_data.columns = [
            "attack_type",
            "count"
        ]


        # Build the attack distribution chart
        fig_pie = px.pie(
            pie_data,
            names="attack_type",
            values="count",
            hole=0.4,
            template="plotly_dark"
        )


        # Render the pie chart
        st.plotly_chart(
            fig_pie,
            use_container_width=True
        )


    # Display blocked traffic over time
    with right:
        st.subheader(
            "📈 Blocked Traffic Over Time"
        )


        # Aggregate blocked events by minute
        df_time = (
            df.set_index("timestamp")
            .resample("1min")
            .size()
            .reset_index(
                name="blocked_count"
            )
        )


        # Build the traffic timeline chart
        fig_line = px.line(
            df_time,
            x="timestamp",
            y="blocked_count",
            template="plotly_dark",
            markers=True
        )


        # Render the timeline chart
        st.plotly_chart(
            fig_line,
            use_container_width=True
        )


    # Add a visual separator
    st.divider()


    # Display the most active attacking IPs
    st.subheader(
        "🚨 Top 10 Attacking IPs"
    )


    # Count blocked events per source IP
    top_ips = (
        df["src_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )


    # Rename the IP statistics columns
    top_ips.columns = [
        "src_ip",
        "blocked_count"
    ]


    # Display the top attacking IP table
    st.dataframe(
        top_ips,
        use_container_width=True,
        hide_index=True
    )


    # Display the latest detailed security logs
    st.subheader(
        "📋 Detailed Logs — Latest 100 Events"
    )


    # Select the columns shown in the dashboard
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
        df.sort_values(
            "timestamp",
            ascending=False
        )
        [display_columns]
        .head(100)
    )


    # Render the detailed log table
    st.dataframe(
        latest_logs,
        use_container_width=True,
        hide_index=True
    )


    # Refresh the dashboard every 10 seconds
    if auto_refresh:
        import time

        time.sleep(10)

        st.rerun()


# Run the dashboard application
if __name__ == "__main__":
    main()
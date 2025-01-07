# app.py
from flask import Flask
from dash import Dash, html, dcc, Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import threading
from traffic_capture import NetworkMonitor

# Initialize Flask and Dash
app = Flask(__name__)
dash_app = Dash(__name__, server=app)

# Initialize network monitor
monitor = NetworkMonitor()

# Set up the dashboard layout
dash_app.layout = html.Div([
    html.H1("Network Traffic Monitor", className="text-center mb-4"),

    # Refresh interval
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # update every 5 seconds
        n_intervals=0
    ),

    # Traffic Overview
    html.Div([
        html.Div([
            dcc.Graph(id='traffic-graph'),
        ], className="mb-4"),

        # Protocol Distribution
        html.Div([
            dcc.Graph(id='protocol-pie')
        ], className="mb-4"),

        # Top IPs
        html.Div([
            dcc.Graph(id='top-ips')
        ], className="mb-4")
    ])
])

@dash_app.callback(
    [Output('traffic-graph', 'figure'),
     Output('protocol-pie', 'figure'),
     Output('top-ips', 'figure')],
    Input('interval-component', 'n_intervals')
)
def update_graphs(n):
    # Get latest statistics
    stats = monitor.get_statistics(minutes=5)

    # Prepare data for traffic graph
    traffic_data = []
    for timestamp, stat in stats.items():
        traffic_data.append({
            'timestamp': datetime.fromtimestamp(timestamp),
            'packets': stat['packets'],
            'bytes': stat['bytes'] / 1024  # Convert to KB
        })

    df_traffic = pd.DataFrame(traffic_data)

    # Create traffic graph
    traffic_fig = px.line(df_traffic, x='timestamp', y=['packets', 'bytes'],
                         title='Network Traffic Over Time')
    traffic_fig.update_layout(yaxis_title='Count / Size (KB)')

    # Aggregate protocol data
    protocols = defaultdict(int)
    for stat in stats.values():
        for protocol, count in stat['protocols'].items():
            protocols[protocol] += count

    # Create protocol pie chart
    protocol_fig = px.pie(values=list(protocols.values()),
                         names=list(protocols.keys()),
                         title='Protocol Distribution')

    # Aggregate IP data
    ip_sources = defaultdict(int)
    for stat in stats.values():
        for ip, count in stat['ip_sources'].items():
            ip_sources[ip] += count

    # Create top IPs bar chart
    top_ips = dict(sorted(ip_sources.items(),
                         key=lambda x: x[1],
                         reverse=True)[:10])
    ip_fig = px.bar(x=list(top_ips.keys()),
                    y=list(top_ips.values()),
                    title='Top 10 Source IPs')

    return traffic_fig, protocol_fig, ip_fig

if __name__ == '__main__':
    # Start network capture in a separate thread
    capture_thread = threading.Thread(
        target=monitor.start_capture,
        kwargs={'interface': 'eth0'},  # Use 'en0' for Mac, 'eth0' for Linux
        daemon=True
    )
    capture_thread.start()

    # Run the web application
    app.run(host='0.0.0.0', port=5001, debug=True)
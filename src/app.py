# app.py
from flask import Flask
from dash import Dash, html, dcc, Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import threading
from collections import defaultdict
from traffic_capture import NetworkMonitor

app = Flask(__name__)
dash_app = Dash(__name__, server=app)

monitor = NetworkMonitor()

dash_app.layout = html.Div([
    html.H1("Network Traffic Monitor", className="text-center mb-4"),

    dcc.Interval(
        id='interval-component',
        interval=5 * 1000,
        n_intervals=0
    ),

    html.Div([
        html.Div([
            dcc.Graph(id='traffic-graph'),
        ], className="mb-4"),

        html.Div([
            dcc.Graph(id='protocol-pie')
        ], className="mb-4"),

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
    stats = monitor.get_statistics(minutes=5)

    traffic_data = []
    for timestamp, stat in stats.items():
        traffic_data.append({
            'timestamp': datetime.fromtimestamp(timestamp),
            'packets': stat['packets'],
            'bytes': stat['bytes'] / 1024
        })

    df_traffic = pd.DataFrame(traffic_data)

    traffic_fig = px.line(df_traffic, x='timestamp', y=['packets', 'bytes'],
                          title='Network Traffic Over Time')
    traffic_fig.update_layout(yaxis_title='Count / Size (KB)')

    protocols = defaultdict(int)
    for stat in stats.values():
        for protocol, count in stat['protocols'].items():
            protocols[protocol] += count

    protocol_fig = px.pie(values=list(protocols.values()),
                          names=list(protocols.keys()),
                          title='Protocol Distribution')

    ip_sources = defaultdict(int)
    for stat in stats.values():
        for ip, count in stat['ip_sources'].items():
            ip_sources[ip] += count

    top_ips = dict(sorted(ip_sources.items(),
                          key=lambda x: x[1],
                          reverse=True)[:10])
    ip_fig = px.bar(x=list(top_ips.keys()),
                    y=list(top_ips.values()),
                    title='Top 10 Source IPs')

    return traffic_fig, protocol_fig, ip_fig


if __name__ == '__main__':
    capture_thread = threading.Thread(
        target=monitor.start_capture,
        kwargs={'interface': 'eth0'},
        daemon=True
    )
    capture_thread.start()

    app.run(host='0.0.0.0', port=5001, debug=True)
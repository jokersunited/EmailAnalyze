import plotly.graph_objects as go
import plotly.offline as plt
import plotly.express as plx
import pandas as pd
import numpy as np
from pytz import timezone

def get_date_plot(email_list):
    sg = timezone('Asia/Singapore')
    bad_data = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 0, 1] for x in email_list if x.phish == 'FAIL']
    good_data = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 1, 0] for x in email_list if x.phish == 'PASS']
    data = bad_data + good_data
    date_frame = pd.DataFrame(data, columns=["Date", "Clean", "Phish"])

    print(date_frame)

    grouped = date_frame.groupby(pd.Grouper(key="Date", freq="MS")).sum().reset_index()

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=grouped['Date'],
        y=grouped['Phish'],
        customdata=[str(x.month_name()) + " " + str(x.year) for x in grouped['Date']],
        hovertemplate='<b>%{customdata}</b><br><i>Total Emails</i>: %{y}',
        name="Phishing Emails",
        line=dict(color='firebrick')
    ))
    fig.add_trace(go.Scatter(
        x=grouped['Date'],
        y=grouped['Clean'],
        customdata=[str(x.month_name()) + " " + str(x.year) for x in grouped['Date']],
        hovertemplate='<b>%{customdata}</b><br><i>Total Emails</i>: %{y}',
        name="Normal Emails",
        line=dict(color='darkblue')
    ))
    fig.update_layout(
        title="Emails by Month",
        xaxis_title="Date",
        yaxis_title="Frequency",
        legend_title="Type"
    )

    return plt.plot(fig, output_type="div")


def get_pie(email_list):
    email_share_dict = {"Count": [0, 0]}
    for email in email_list:
        if email.phish == "FAIL":
            email_share_dict["Count"][0] += 1
        else:
            email_share_dict["Count"][1] += 1

    pie_df = pd.DataFrame.from_dict(email_share_dict)
    print(pie_df)

    fig = go.Figure()

    fig.add_trace(go.Pie(
        labels=['Bad', 'Good'],
        values=pie_df['Count'],
        hoverinfo='label+percent',
        textinfo='value',
        textfont_size=20,
        marker=dict(colors=["red", "blue"])
        )
    )
    fig.update_layout(
        title="Email Type",
        legend_title="Type"
    )
    return plt.plot(fig, output_type="div")

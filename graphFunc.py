import plotly.graph_objects as go
import plotly.offline as plt
import plotly.express as plx
import pandas as pd
import numpy as np
from pytz import timezone

wordFrame = pd.read_csv("phishwords.csv", encoding="ISO-8859-1", engine='python')
columns = wordFrame.columns

tags = ["Very Unlikely", "Likely", "Neutral", "Likely", "Very Likely"]

def get_date_plot(email_list):
    sg = timezone('Asia/Singapore')
    data1 = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 1, 0, 0, 0, 0] for x in email_list
                if x.get_phishtag() == tags[0]]
    data2 = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 0, 1, 0, 0, 0] for x in email_list
                if x.get_phishtag() == tags[1]]
    data3 = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 0, 0, 1, 0, 0] for x in email_list
                if x.get_phishtag() == tags[2]]
    data4 = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 0, 0, 0, 1, 0] for x in email_list
                if x.get_phishtag() == tags[3]]
    data5 = [[pd.Timestamp(x.date).to_period('D').to_timestamp().tz_localize(sg), 0, 0, 0, 0, 1] for x in email_list
                if x.get_phishtag() == tags[4]]
    data = data1 + data2 + data3 + data4 + data5
    date_frame = pd.DataFrame(data, columns=["Date", "Very Unlikely", "Likely", "Neutral", "Likely", "Very Likely"])
    print(date_frame)
    grouped = date_frame.groupby(pd.Grouper(key="Date", freq="MS")).sum().reset_index()

    fig = go.Figure()

    for x in tags:
        fig.add_trace(go.Scatter(
            x=grouped['Date'],
            y=grouped[x],
            customdata=[str(x.month_name()) + " " + str(x.year) for x in grouped['Date']],
            hovertemplate='<b>%{customdata}</b><br><i>Total Emails</i>: %{y}',
            name=x,
            line=dict(color='firebrick')
        ))
    fig.update_layout(
        title="Emails by Month",
        xaxis_title="Date",
        yaxis_title="Frequency",
        legend_title="Type"
    )

    return plt.plot(fig, output_type="div")
    pass

def get_dist(email_list):
    email_share_dict = {"Count": [0]*len(columns)}
    for email in email_list:
        for cat in email.cat:
            print(cat)
            print(email_share_dict["Count"])
            if cat.lower() in columns:
                email_share_dict["Count"][columns.tolist().index(cat.lower())] += 1

    dist_df = pd.DataFrame.from_dict(email_share_dict)

    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=columns,
        y=dist_df['Count'],
        marker_color=['red']*len(dist_df)
        )
    )
    fig.update_layout(
        title="Email Types",
        legend_title="Types"
    )

    return plt.plot(fig, output_type="div")

def get_pie(email_list):
    email_share_dict = {"Count": [0, 0]}
    for email in email_list:
        if email.phish == 1:
            email_share_dict["Count"][0] += 1
        else:
            email_share_dict["Count"][1] += 1

    pie_df = pd.DataFrame.from_dict(email_share_dict)

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

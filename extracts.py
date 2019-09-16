import os
from scapy.all import rdpcap
import pandas as pd
import multiprocessing
from datetime import datetime

files = os.listdir('./csv/')

def format_data():
    data_points = {}
    print("Formating data")
    for f in files:

    # if f == '172.16.2.114.pcap':
        print("processing {}".format(f))
        packets = rdpcap(f)
        points = []

        for p in packets:
            points.append(
                {
                    'timestamp': p.time,
                    'src': p.getlayer(1).src,
                    'dst': p.getlayer(1).dst
                }
            )
        data_points[f] = points

        with open('./csv/' + f + '.csv', 'w') as fl:
            df = pd.DataFrame(points)
            df.to_csv(fl, sep=',')
    print("Format data done")

def handle(first_ts, last_ts, src_ip, dst_ip, df):
    try:
        i = 15
        next_ts = first_ts
        timeseries = []
        print("Write to database for flow {}-{}".format(src_ip, dst_ip))
        while True:
            p = df[
                (df['src'] == src_ip ) &
                (df['dst'] == dst_ip ) &
                (df['timestamp'] > next_ts) &
                (df['timestamp'] < (next_ts + i))
            ]
            body = {
                'timestamp': next_ts,
                'flow': src_ip + '-' + dst_ip
            }
            if len(p) > 0:
                body['value'] = 1
            else:
                body['value'] = 0
            timeseries.append(body)
            if next_ts > last_ts:
                break
            next_ts += i
        timeseries = pd.DataFrame(timeseries)
        with open('./timeseries/'+ src_ip + '-' + dst_ip + '.csv', 'w') as f:
            timeseries.to_csv(f)
        print("Done")
    except Exception as e:
        print(e)




if __name__ == "__main__":
    # read data from csv
    p = multiprocessing.Pool()
    data_points = {}
    for f in files:
        data_points[f] = pd.read_csv('./csv/' + f)

    # get first ts
    first_ts = float(data_points[data_points.keys()[0]][0:1].timestamp)
    for f in data_points.keys():
        if float(data_points[f][0:1].timestamp) < first_ts:
            first_ts = float(data_points[f][0:1].timestamp)

    # build time series data
    for f in data_points.keys():
        last_ts = float(data_points[f].tail(1).timestamp)
        df = data_points[f]
        list_of_src = df.src.unique()
        for src_ip in list_of_src:
            list_of_dst = df[df['src'] == src_ip].dst.unique()
            jobs = []
            for dst_ip in list_of_dst:
                # Find the first timestamp
                first_ts = float(df[(df.src == src_ip) & (df.dst == dst_ip)].head(1).timestamp)
                # Round the first timestamp
                first_ts_str = str(round(first_ts))
                last_digest = first_ts_str[-4:]
                if last_digest not in ['00.0', '15.0', '30.0', '45.0']:
                    last_digest = int(float(last_digest))
                    if last_digest > 0 and last_digest < 15:
                        last_digest = '00.0'
                    elif last_digest > 15 and last_digest < 30:
                        last_digest = '15.0'
                    elif last_digest > 30 and last_digest < 45:
                        last_digest = '30.0'
                    elif last_digest > 45:
                        last_digest = '45.0'
                    first_ts = float(first_ts_str[:8] + last_digest)
                last_ts = float(df[(df.src == src_ip) & (df.dst == dst_ip)].tail(1).timestamp)
                print("First ts {}".format(first_ts))
                p.apply_async(handle, args=(first_ts, last_ts, src_ip, dst_ip, df,))
    p.close()
    p.join()
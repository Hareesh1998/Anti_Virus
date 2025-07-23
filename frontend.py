import streamlit as st
import pandas as pd
import requests
import time


st.set_page_config(layout="wide")

file_loc1 = r'D:\School\CIS549\Term Project\small_arm_oat'
file_loc2 = r'D:\School\CIS549\Term Project\small_apk_dataset\Fusob\variety1'

def get_report(md5reponse):
    time.sleep(5)
    url = "https://www.virustotal.com/api/v3/files/"+md5reponse['md5']

    headers = {
        "Accept": "application/json",
        "x-apikey": "d5166c48ffb2e3a2a43ddc9dcf0c5d3f2256e4d77a263b466a888ac3337e1ce7"
    }

    response = requests.request("GET", url, headers=headers)
    return response.json()


def send_file(file):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {
        'apikey': 'd5166c48ffb2e3a2a43ddc9dcf0c5d3f2256e4d77a263b466a888ac3337e1ce7'}

    try:
        file_path = file_loc1+r"\\"+file.name
        files = {'file': (file.name, open(file_path, 'rb'))}
    except:
        try:
            file_path = file_loc2+r"\\"+file.name
            files = {'file': (file.name, open(file_path, 'rb'))}
        except:
            files = {'file': (file.name, open(file.name, 'rb'))}

    response = requests.post(url, files=files, params=params)

    return get_report(response.json())


def analyze_report(report):
    count = 0
    for k, v in report['data']['attributes']['last_analysis_results'].items():
        count += 1

    return count


def analyze_report(report):
    count = 0
    for k, v in report['data']['attributes']['last_analysis_results'].items():
        count += 1

    return count


aggr_report = {}


def format_report(data):
    total_virus_outputs = {}
    output_dict = {}

    try:
        file_type = data['data']['attributes']['meaningful_name'].split('.')[1]
    except:
        file_type = data['data']['attributes']['type_description']

    detect_count = data['data']['attributes']['last_analysis_stats']['suspicious'] + \
        data['data']['attributes']['last_analysis_stats']['malicious']
    total_av=sum(data['data']['attributes']['last_analysis_stats'].values())-data['data']['attributes']['last_analysis_stats']['timeout']
    accuracy = detect_count/total_av
    total_virus_outputs['detect_count'] = detect_count
    total_virus_outputs['total_av'] = total_av
    total_virus_outputs['accuracy'] = accuracy
    for k, v in data['data']['attributes']['last_analysis_results'].items():
        if v['category'] == 'undetected' or v['category'] == 'type-unsupported':
            total_virus_outputs[k] = 0
        elif v['category'] == 'timeout':
            pass
        else:
            total_virus_outputs[k] = 1
    output_dict[file_type] = total_virus_outputs
    return output_dict


if st.button('Click Here to Submit to VirusTotal'):
    for file in uploaded_files:
        report = send_file(file)
        # st.write(report)
        file_type = file.name.split('.')[1]
        hashVal = report['data']['attributes']['md5']
        if file_type == 'oat':
            meaningfulName = file.name.split('_')[0] +'_' + hashVal
        else:
            meaningfulName = report['data']['attributes']['popular_threat_classification']['popular_threat_category'][0]['value'] +'_' + report['data']['attributes']['popular_threat_classification']['popular_threat_name'][0]['value'] + '_' + hashVal
        cleaned_report = format_report(report)
        aggr_report[meaningfulName] = cleaned_report 
    st.write("Write JSON Output: ", aggr_report)

    list_of_names = []
    detect = []
    total_av = []
    accuracy = []
    for k, v in aggr_report.items():
        list_of_names.append(k)
        for k2, v2 in v.items():
            detect.append(v2['detect_count'])
            for k3, v3 in v.items():
                total_av.append(v3['total_av'])
                for k4, v4 in v.items():
                    accuracy.append(v4['accuracy'])
    st.write("Write File Names/Count: ", list_of_names)
    st.write("Write Total Detected: ", detect)
    st.write("Write Total AV Count: ", total_av)
    st.write("Write Accuracy Percentage : ", accuracy)

    #Graphs	and DataFrames
    def load_detect_data():
        st.title("💬 Total Virus' Detected")
        df = pd.DataFrame(detect, list_of_names)
        st.bar_chart(df, width=900, height=600, use_container_width=False)
        st.subheader("This Graph Displays the Total Number of AVs that detected Ransomware")
    chart_data = load_detect_data()

    def load_total_av_data():
        st.title("💬 Total Anti-Virus")
        df = pd.DataFrame(total_av, list_of_names)
        st.bar_chart(df, width=900, height=600, use_container_width=False)
        st.subheader("This Graph Displays the Total Number of AVs that Didn't Timeout")

    chart_data = load_total_av_data()

    def load_accuracy_data():
        st.title("💬 Total Accuracy Percentage")
        df = pd.DataFrame(accuracy, list_of_names)
        st.bar_chart(df, width=900, height=600, use_container_width=False)
        st.subheader("This Graph Displays the Detection Accuracy")
    chart_data = load_accuracy_data()
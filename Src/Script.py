# SOC-Autonomous-Agent 

# Setup & installs
#pip install -q pandas numpy python-dateutil imageio pillow
import os, json, time, random, hashlib
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from dateutil import parser
from PIL import Image, ImageDraw, ImageFont
import imageio
Path('data').mkdir(exist_ok=True)
Path('assets').mkdir(exist_ok=True)

# Synthetic alerts generator
import pandas as pd
import hashlib
from datetime import datetime, timedelta
import random

def generate_synthetic_alerts(n=160, seed=42):
    random.seed(seed)
    base_time = datetime.utcnow()
    src_ips = ["203.0.113.{}".format(i) for i in range(10,60)] + ["198.51.100.{}".format(i) for i in range(2,20)]
    dst_ips = ["10.0.0.{}".format(i) for i in range(2,120)]
    signatures = [
        'SQLi attempt','XSS attempt','Brute force login','Suspicious download',
        'Malware beaconing','Ransomware behavior','C2 handshake','Port scan',
        'Suspicious PowerShell','Data exfil via FTP'
    ]
    severities = ['low','medium','high']
    rows = []
    for i in range(n):
        t = base_time - timedelta(minutes=int(random.random()*60*24*7))
        sig = random.choices(signatures, weights=[5,4,6,3,2,1,1,4,2,1])[0]
        src = random.choice(src_ips)
        dst = random.choice(dst_ips)
        dst_port = random.choice([22,80,443,3389,21,8080,8443,445,53,1433])
        proto = random.choice(['TCP','UDP','ICMP'])
        severity = random.choices(severities, weights=[4,3,2])[0]
        phash = ''
        if sig in ['Malware beaconing','Ransomware behavior','Suspicious download']:
            phash = hashlib.sha1(("file{}".format(i)).encode()).hexdigest()
        row = {
            'alert_id': 'ALRT-{:04d}'.format(i+1),
            'timestamp': t.isoformat(),
            'signature': sig,
            'src_ip': src,
            'dst_ip': dst,
            'dst_port': dst_port,
            'protocol': proto,
            'severity': severity,
            'file_hash': phash,
            'raw': "{} observed from {} -> {}:{} protocol {}".format(sig, src, dst, dst_port, proto)
        }
        rows.append(row)
    df = pd.DataFrame(rows).sort_values('timestamp', ascending=False)
    return df

alerts_df = generate_synthetic_alerts(160)
alerts_df.to_csv('data/alerts.csv', index=False)
print('Wrote data/alerts.csv with', len(alerts_df), 'rows')



# Mocks, MITRE mapping, and agents
import hashlib

def mock_domain_reputation(domain):
    if pd.isna(domain):
        return {"label": "Unknown", "score": 0}

    domain = str(domain)
    score = len(domain) % 3

    return [
        {"label": "Benign", "score": 0.1},
        {"label": "Suspicious", "score": 0.5},
        {"label": "High-Risk", "score": 0.9}
    ][score]

def mock_ip_reputation(ip):
    if pd.isna(ip):
        return {"label": "Unknown", "score": 0}

    ip = str(ip)
    risk = sum(ord(c) for c in ip) % 3

    return [
        {"label": "Clean", "score": 0.1},
        {"label": "Suspicious", "score": 0.5},
        {"label": "Malicious", "score": 0.9}
    ][risk]


def mock_whois(handle):
    h = hashlib.sha1(handle.encode()).hexdigest()
    registrar = 'Reg-' + h[:6]
    created = (datetime.utcnow() - timedelta(days=int(h[:4],16)%4000)).date().isoformat()
    return {'handle': handle, 'registrar': registrar, 'created': created}

def mock_geoip(ip):
    countries = ['US','GB','DE','FR','RU','CN','IN','BR','NL','CA']
    idx = int(hashlib.md5(ip.encode()).hexdigest()[:4],16) % len(countries)
    return {'ip': ip, 'country': countries[idx]}

def mock_hash_reputation(hsh):
    # Prevent NaN / float errors
    if pd.isna(hsh) or hsh.strip() == "":
        return "Unknown"

    hsh = str(hsh)

    # Mock categorization
    try:
        val = int(hsh[:6], 16)
    except:
        return "Unknown"

    if val % 5 == 0:
        return "Malicious"
    elif val % 3 == 0:
        return "Suspicious"
    else:
        return "Clean"
    
def mock_file_reputation(file):
    if pd.isna(file):
        return {"label": "Unknown", "score": 0}

    file = str(file)
    if file.endswith(".exe"):
        return {"label": "Suspicious", "score": 0.6}
    elif file.endswith(".dll"):
        return {"label": "Malicious", "score": 0.9}
    else:
        return {"label": "Clean", "score": 0.1}

def mock_process_reputation(proc):
    if pd.isna(proc):
        return {"label": "Unknown", "score": 0}

    proc = str(proc)
    if "powershell" in proc.lower():
        return {"label": "Suspicious", "score": 0.7}
    else:
        return {"label": "Clean", "score": 0.1}



MITRE_MAP = {
    'SQLi attempt': [{'tactic':'Initial Access','technique':'T1190','name':'Exploit Public-Facing Application'}],
    'XSS attempt': [{'tactic':'Initial Access','technique':'T1190','name':'Exploit Public-Facing Application'}],
    'Brute force login': [{'tactic':'Credential Access','technique':'T1110','name':'Brute Force'}],
    'Suspicious download': [{'tactic':'Execution','technique':'T1204','name':'User Execution'}],
    'Malware beaconing': [{'tactic':'Command and Control','technique':'T1041','name':'Exfiltration Over C2 Channel'}],
    'Ransomware behavior': [{'tactic':'Impact','technique':'T1486','name':'Data Encrypted for Impact'}],
    'C2 handshake': [{'tactic':'Command and Control','technique':'T1105','name':'Ingress Tool Transfer'}],
    'Port scan': [{'tactic':'Discovery','technique':'T1046','name':'Network Service Scanning'}],
    'Suspicious PowerShell': [{'tactic':'Execution','technique':'T1059.001','name':'PowerShell'}],
    'Data exfil via FTP': [{'tactic':'Exfiltration','technique':'T1041','name':'Exfiltration Over C2 Channel'}],
}

def map_to_mitre(signature):
    return MITRE_MAP.get(signature, [{'tactic':'Unknown','technique':'T0000','name':'Unknown'}])


import pandas as pd
def ingestion_agent(alerts_csv='data/alerts.csv', top_n=30):
    df = pd.read_csv(alerts_csv)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp', ascending=False).head(top_n)
    return df

def enrichment_agent(row):
    enriched = dict(row)

    # Map real fields
    file = enriched.get("file_hash", "")
    proc = enriched.get("signature", "")
    dom  = enriched.get("dst_ip", "")
    ip   = enriched.get("src_ip", "")
    hsh  = enriched.get("file_hash", "")

    # Normalize
    file = "" if pd.isna(file) else str(file)
    proc = "" if pd.isna(proc) else str(proc)
    dom  = "" if pd.isna(dom) else str(dom)
    ip   = "" if pd.isna(ip) else str(ip)
    hsh  = "" if pd.isna(hsh) else str(hsh)

    # Apply mocks
    enriched["file_reputation"]    = mock_file_reputation(file)
    enriched["process_reputation"] = mock_process_reputation(proc)
    enriched["domain_reputation"]  = mock_domain_reputation(dom)
    enriched["ip_reputation"]      = mock_ip_reputation(ip)

    # Hash reputation fix
    hrep = mock_hash_reputation(hsh)
    if isinstance(hrep, str):
        hrep = {
            "label": hrep,
            "score": 0.9 if hrep == "Malicious" else 0.5 if hrep == "Suspicious" else 0.1
        }

    enriched["hash_reputation"] = hrep
    return enriched



def attack_mapping_agent(enriched):
    techniques = map_to_mitre(enriched['signature'])
    enriched['mitre'] = techniques
    return enriched

def triage_agent(enriched):
    score = 0

    score += enriched['ip_reputation']['score'] * 0.6
    score += enriched['domain_reputation']['score'] * 0.4
    score += enriched['process_reputation']['score'] * 0.7
    score += enriched['file_reputation']['score'] * 0.8
    score += enriched['hash_reputation']['score'] * 1.0

    sev = enriched.get("severity", "").lower()
    if sev == "high":
        score += 1.5
    elif sev == "medium":
        score += 0.8
    elif sev == "low":
        score += 0.3

    sig = enriched.get("signature", "").lower()
    if "mimikatz" in sig:
        score += 2.0
    if "c2" in sig:
        score += 1.5
    if enriched.get("dst_port") in [4444, 1337, 3389]:
        score += 1.0

    score = round(score, 3)

    if score >= 3.5:
        level = "HIGH"
    elif score >= 2.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    enriched["triage"] = {
        "score": score,
        "level": level
    }

    return enriched 

def response_agent(enriched):
    level = enriched['triage']['level']
    mitre = enriched.get('mitre', [])
    actions = []
    if level == 'HIGH':
        actions += [
            'Isolate affected host from network (block src IP at perimeter).',
            'Collect forensic image of endpoint and network captures.',
            'Notify SOC analyst and Incident Manager.'
        ]
    elif level == 'MEDIUM':
        actions += [
            'Quarantine suspicious files and block src IP temporarily.',
            'Increase monitoring on related hosts and network segments.'
        ]
    else:
        actions += [
            'Log the event for trending; schedule periodic review.',
            'Monitor for recurrence; no immediate containment required.'
        ]
    for t in mitre:
        if 'PowerShell' in t.get('name',''):
            actions.append('Run PowerShell history extraction and YARA scan for scripts.')
        if t.get('technique') == 'T1486':
            actions.append('Backup critical data and prepare recovery steps (ransomware).')
    enriched['response_recommendations'] = actions
    return enriched

def evaluator_agent(enriched, ground_truth={}):
    aid = enriched['alert_id']
    true = ground_truth.get(aid, {}).get('true_level', None)
    pred = enriched['triage']['level']
    match = (true == pred) if true else None
    completeness = min(1.0, len(enriched.get('response_recommendations', [])) / 4.0)
    enriched['evaluation'] = {'true_level': true, 'predicted_level': pred, 'match': match, 'completeness': round(completeness,2)}
    return enriched


# Memory & Orchestrator
import json, time
MEM_PATH = 'data/soc_memory.json'
if not os.path.exists(MEM_PATH):
    open(MEM_PATH,'w').write(json.dumps({'incidents': [], 'alerts_seen': []}, indent=2))

def read_mem():
    return json.load(open(MEM_PATH))

def write_mem(m):
    open(MEM_PATH,'w').write(json.dumps(m, indent=2))

def mem_push_incident(incident):
    m = read_mem()
    m['incidents'].append(incident)
    m['incidents'] = m['incidents'][-200:]
    write_mem(m)

def mem_push_alert_id(aid):
    m = read_mem()
    m['alerts_seen'].append({'alert_id': aid, 'ts': time.time()})
    m['alerts_seen'] = m['alerts_seen'][-500:]
    write_mem(m)

def run_pipeline(top_n=30, verbose=False):
    df_top = ingestion_agent('data/alerts.csv', top_n=top_n)
    processed = []
    ground_truth = {}
    for idx, row in df_top.iterrows():
        aid = row['alert_id']
        sig = row['signature']
        if 'Ransomware' in sig or 'ransom' in sig.lower() or 'Malware' in sig:
            ground_truth[aid] = {'true_level':'HIGH'}
        elif 'Brute' in sig or 'Port scan' in sig:
            ground_truth[aid] = {'true_level':'MEDIUM'}
        else:
            ground_truth[aid] = {'true_level':'LOW'}
    for i, row in df_top.iterrows():
        enr = enrichment_agent(row)
        enr = attack_mapping_agent(enr)
        enr = triage_agent(enr)
        enr = response_agent(enr)
        enr = evaluator_agent(enr, ground_truth=ground_truth)
        mem_push_incident({'alert_id': enr['alert_id'], 'triage': enr['triage'], 'ts': datetime.utcnow().isoformat()})
        mem_push_alert_id(enr['alert_id'])
        processed.append(enr)
        if verbose:
            print('Processed', enr['alert_id'], '->', enr['triage']['level'])
    return processed

processed = run_pipeline(top_n=30, verbose=True)



# Results table and demo GIF creation
import imageio
import textwrap
from PIL import Image, ImageDraw, ImageFont
import pandas as pd

proc_df = pd.DataFrame([{ 'alert_id': p['alert_id'], 'signature': p['signature'], 'src_ip': p['src_ip'], 'triage_level': p['triage']['level'], 'score': p['triage']['score'], 'true_level': p['evaluation']['true_level'], 'match': p['evaluation']['match'], 'response_actions': len(p['response_recommendations']) } for p in processed])
print(proc_df.head(20))

sample_high = next((p for p in processed if p['triage']['level']=='HIGH'), None)

def text_to_image(text, size=(900,240), bgcolor='white'):
    img = Image.new('RGB', size, color=bgcolor)
    d = ImageDraw.Draw(img)
    try:
        fnt = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 14)
    except:
        fnt = None
    lines = textwrap.wrap(text, width=110)
    y = 10
    for line in lines:
        d.text((10,y), line, fill=(0,0,0), font=fnt)
        y += 18
    return img

frames = []
if sample_high:
    frames.append(text_to_image('SOC-Agent Demo: Ingestion -> Enrichment -> Mapping -> Triage -> Response'))
    frames.append(text_to_image('Alert RAW: ' + sample_high['raw'][:400]))
    frames.append(text_to_image('IP Reputation: ' + str(sample_high['ip_reputation'])))
    frames.append(text_to_image('Mapped MITRE: ' + str(sample_high['mitre'])))
    frames.append(text_to_image('Triage: ' + str(sample_high['triage'])))
    frames.append(text_to_image('Recommendations: ' + '; '.join(sample_high['response_recommendations'][:4])))
    gif_path = 'assets/soc_demo.gif'
    imageio.mimsave(gif_path, frames, duration=2)
    print('Wrote demo GIF to', gif_path)
else:
    print('No HIGH incident to demo')


# Evaluation metrics
import pandas as pd
df_eval = pd.DataFrame([{ 'alert_id': p['alert_id'], 'pred': p['triage']['level'], 'score': p['triage']['score'], 'true': p['evaluation']['true_level'], 'match': p['evaluation']['match'], 'completeness': p['evaluation']['completeness'] } for p in processed])
accuracy = df_eval['match'].dropna().mean()
avg_completeness = df_eval['completeness'].mean()
print('Triage accuracy (where truth available):', round(float(accuracy),3))
print('Average response completeness:', round(float(avg_completeness),3))
print('Triage distribution:')
print(df_eval['pred'].value_counts())



#!/usr/bin/env python3
"""Real full-CLI security and positive-control tests in the owned lab netns."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import threading
import time


def load(path):
    spec=importlib.util.spec_from_file_location('accepted_runtime_protocol',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--enabled',choices=['0','1'],required=True)
    parser.add_argument('--collector-dir',type=Path,required=True)
    args=parser.parse_args();root=args.root;enabled=args.enabled=='1';os.umask(0o077)
    protocol=load(Path(__file__).with_name('runtime_protocol.py'))
    sockpath=Path(json.loads((root/'scope.json').read_text())['socket_path'])
    users=json.loads((root/'fixture/users.json').read_text())
    context=ssl.create_default_context(cafile=str(root/'fixture/cert.pem'))
    assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
    def publication():return protocol.unix_json(sockpath,'/diagnostics/anytls-stage')
    first=publication();assert first['availability']=='inactive' and first['snapshot'] is None
    for auth in [b'X'*32+b'\0\0',hashlib.sha256(users['fixture-one'].encode()).digest()+b'\xff\xff'+b'X']:
        with socket.create_connection(('127.0.0.1',7443),timeout=3) as raw:
            with context.wrap_socket(raw,server_hostname='anytls-runtime.test') as c:
                c.settimeout(3);c.sendall(auth)
                try:rejected=c.recv(1)==b''
                except (ConnectionResetError,ssl.SSLError):rejected=True
                assert rejected,'invalid credentials/padding not rejected'
        after=publication();assert after['availability']=='inactive' and after['snapshot'] is None
    protocol_result=protocol.probe(root)
    result={'protocol':protocol_result,'preauth_inactive':True,'malformed_auth_padding_rejected':True,
            'private_trust_only':True,'enabled':enabled}
    secret=json.loads((root/'fixture/management.json').read_text())['secret']
    statuses={}
    for kind,port in [('tcp',9090),('tls',9091)]:
        cls=http.client.HTTPSConnection if kind=='tls' else http.client.HTTPConnection
        kwargs={'context':context} if kind=='tls' else {}
        for path,expected in [('/version',200),('/diagnostics/anytls-stage',404)]:
            c=cls('localhost',port,timeout=2,**kwargs);c.request('GET',path,headers={'Authorization':'Bearer '+secret})
            response=c.getresponse();response.read(65536);statuses[kind+path]=response.status;c.close();assert response.status==expected
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2);s.connect(str(sockpath));s.sendall(b'POST /diagnostics/anytls-stage HTTP/1.0\r\nHost: localhost\r\n\r\n')
        assert s.recv(1024).split()[1]==b'405'
    child=os.fork()
    if child==0:
        try:
            os.setgroups([]);os.setgid(65534);os.setuid(65534)
            with socket.socket(socket.AF_UNIX) as s:s.connect(str(sockpath))
        except PermissionError:os._exit(0)
        except BaseException:os._exit(2)
        os._exit(1)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==0
    result.update(management_route_statuses=statuses,unix_post_rejected=True,unprivileged_unix_access_denied=True)
    if enabled:
        # A controlled incomplete protocol body, distinct from idle read_header.
        # Target is a separate plain TCP fixture that verifies all delivered bytes.
        body=bytes(range(256))*16;target_received=[];listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',19081));listener.listen(1);listener.settimeout(20)
        def target():
            try:
                c,_=listener.accept()
                with c:
                    c.settimeout(20)
                    for _ in range(4):
                        data=protocol.readn(c,len(body));target_received.append(data==body);c.sendall(hashlib.sha256(data).digest())
            finally:listener.close()
        thread=threading.Thread(target=target,daemon=True);thread.start()
        with socket.create_connection(('127.0.0.1',7443),timeout=3) as raw:
            with context.wrap_socket(raw,server_hostname='anytls-runtime.test') as c:
                c.settimeout(20);auth=hashlib.sha256(users['fixture-one'].encode()).digest()+b'\0\x40'+b'\0'*64
                payload=b'\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',19081)+body
                c.sendall(auth+protocol.frame(4,0,b'v=2\nclient=pcs-stage-positive-control')+protocol.frame(1,1)+struct.pack('!BIH',2,1,len(payload))+payload[:8])
                found=False;deadline=time.monotonic()+13
                while time.monotonic()<deadline:
                    p=publication();b=p.get('snapshot') or {}
                    found=any(a['stage']=='read_body' and a['age_ms']>=1000 for s in b.get('sessions') or [] if s.get('inflight_known') for a in s.get('active') or [])
                    if found:break
                    time.sleep(.25)
                assert found,'incomplete-body stage not observable'
                c.sendall(payload[8:]);received=bytearray()
                while len(received)<32:
                    command,sid,size=struct.unpack('!BIH',protocol.readn(c,7));data=protocol.readn(c,size)
                    if command==2 and sid==1:received.extend(data)
                assert bytes(received)==hashlib.sha256(body).digest()
                stage_spec=importlib.util.spec_from_file_location('frozen_stage_failure_control',args.collector_dir/'stage.py')
                stage=importlib.util.module_from_spec(stage_spec);stage_spec.loader.exec_module(stage)
                scope=json.loads((root/'scope.json').read_text())['scope'];key=(root/'fixture/alias.key').read_bytes()
                controls=[]
                for case in ('missing_socket','unsafe_output','unsafe_cursor'):
                    private=root/('failure-'+case);private.mkdir(mode=0o700)
                    cursor=private/'cursor.json';endpoint=sockpath
                    if case=='missing_socket':endpoint=sockpath.with_name('missing.sock')
                    reader=stage.StageReader(endpoint,key,cursor,enabled=True)
                    if case=='unsafe_output':(private/'stage.jsonl').symlink_to(private/'trap')
                    if case=='unsafe_cursor':cursor.symlink_to(private/'trap')
                    tick=time.monotonic()
                    outcome=stage.collect_regular_stage(reader,stage.StageLog(private),scope,regular_tick=tick,next_regular=tick+10)
                    if case=='missing_socket':assert outcome['availability']=='transport_error'
                    if case=='unsafe_output':assert outcome['output_status']=='failed' and outcome['checkpoint_status']=='not_advanced'
                    if case=='unsafe_cursor':assert outcome['output_status']=='written' and outcome['checkpoint_status']=='failed'
                    assert outcome['fault_count_increment']==0
                    c.sendall(protocol.frame(2,1,body));received=bytearray()
                    while len(received)<32:
                        command,sid,size=struct.unpack('!BIH',protocol.readn(c,7));data=protocol.readn(c,size)
                        if command==2 and sid==1:received.extend(data)
                    assert bytes(received)==hashlib.sha256(body).digest()
                    controls.append({'case':case,'same_authenticated_session_exact_reply':True,
                         'fault_count_increment':outcome['fault_count_increment'],
                         'availability':outcome['availability'],'output_status':outcome['output_status'],
                         'checkpoint_status':outcome['checkpoint_status']})
                result['actual_consumer_failure_controls']=controls
                result['failure_control_scope']='unchanged production stage helper against live CLI; same TLS session continues. Full normal collector normal/rollup ordering is separately observed in runtime cost trials and unit-tested under failure.'
        thread.join(2);assert target_received==[True]*4
        result['incomplete_body_positive_control']={'observed_read_body':True,'fully_recovered_exact_payload':True,'body_bytes':len(body)}
        p=publication();assert p['availability']=='ready' and p['snapshot'] is not None
        result['ready_after_valid_auth']=True
    else:
        p=publication();assert p['availability']=='inactive' and p['snapshot'] is None
        result['off_stays_inactive']=True
    result['ok']=True
    (root/'security-result.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()

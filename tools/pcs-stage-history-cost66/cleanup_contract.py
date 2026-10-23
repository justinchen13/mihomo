"""Owned helper readback. Pure classifiers plus bounded read-only /proc/cgroup reads."""
from pathlib import Path

def parse_properties(text):
 result={}
 for line in text.splitlines():
  if '=' not in line:continue
  k,v=line.split('=',1)
  if k in result:raise ValueError('duplicate systemd property')
  result[k]=v
 return result

def classify_unit(result,proof):
 name=proof['unit'];name=name if name.endswith('.service') else name+'.service'
 try:p=parse_properties(result.stdout)
 except ValueError:return {'known':False,'owned':False,'inactive':False,'reason':'duplicate_properties'}
 if p.get('Id')!=name:return {'known':False,'owned':False,'inactive':False,'reason':'unit_id_unknown'}
 if p.get('LoadState')=='not-found':
  valid=result.returncode in (0,1,4) and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('ControlGroup') in ('',None)
  return {'known':valid,'owned':False,'absent':valid,'inactive':valid,'properties':p}
 owned=p.get('Description')==proof['description']
 expected=proof.get('cgroup_path');actual=p.get('ControlGroup')
 cg_matches=actual=='' or expected is not None and '/sys/fs/cgroup'+actual==expected
 known=result.returncode==0 and owned and p.get('LoadState')=='loaded' and p.get('MainPID','').isdigit() and cg_matches
 return {'known':known,'owned':owned,'absent':False,'inactive':known and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0','properties':p}

def pid_readback(proof):
 pid=proof.get('pid');expected=proof.get('start_ticks')
 if type(pid) is not int or pid<=0 or type(expected) is not int:return {'known':False,'departed':False,'reason':'initial_pid_identity_unknown'}
 try:
  value=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split();start=int(value[19])
 except FileNotFoundError:return {'known':True,'departed':True,'pid':pid,'initial_start_ticks':expected,'status':'absent'}
 except (OSError,ValueError,IndexError):return {'known':False,'departed':False,'reason':'pid_read_failed'}
 return {'known':True,'departed':start!=expected,'pid':pid,'initial_start_ticks':expected,'current_start_ticks':start,'status':'reused_identity' if start!=expected else 'still_present'}

def cgroup_readback(path):
 if not isinstance(path,str) or not path.startswith('/sys/fs/cgroup/'):return {'known':False,'empty_or_absent':False,'reason':'initial_cgroup_unknown'}
 p=Path(path)
 try:
  raw=(p/'cgroup.events').read_text();values=dict(line.split() for line in raw.splitlines())
  if values.get('populated') not in ('0','1'):raise ValueError('populated unknown')
  return {'known':True,'empty_or_absent':values['populated']=='0','path':path,'populated':int(values['populated']),'absent':False}
 except FileNotFoundError:
  try:
   p.stat()
  except FileNotFoundError:return {'known':True,'empty_or_absent':True,'path':path,'absent':True}
  except OSError:pass
  return {'known':False,'empty_or_absent':False,'reason':'cgroup_events_unavailable'}
 except (OSError,ValueError):return {'known':False,'empty_or_absent':False,'reason':'cgroup_read_failed'}

def cleanup_gate(unit,pid,cgroup):
 return (unit.get('known') is True and unit.get('inactive') is True and
         pid.get('known') is True and pid.get('departed') is True and
         cgroup.get('known') is True and cgroup.get('empty_or_absent') is True)

def helper_readback(proof,command):
 result=command(['systemctl','show',proof['unit'],'--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ControlGroup'],timeout=3,check=False)
 unit=classify_unit(result,proof);pid=pid_readback(proof);cg=cgroup_readback(proof.get('cgroup_path'))
 return {'unit':proof['unit'],'unit_readback':unit,'pid_readback':pid,'cgroup_readback':cg,'pass':cleanup_gate(unit,pid,cg)}

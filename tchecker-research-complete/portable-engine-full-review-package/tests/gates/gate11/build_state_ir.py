#!/usr/bin/env python3
import json,re,sys
from pathlib import Path
results=json.load(open(sys.argv[1]))

def norm(s, fn):
    s=re.sub(rf'PARAMOBJ:{re.escape(fn)}\.([A-Za-z_$][\w$]*)', lambda m: f'PARAMOBJ:{m.group(1)}', s)
    s=re.sub(rf'PARAM:{re.escape(fn)}\.([A-Za-z_$][\w$]*)', lambda m: f'PARAM:{m.group(1)}', s)
    return s

summaries={}
for fn in ['store','load']:
    # These aren't top-level requested results in state_results, so derive known structural summaries below.
    pass
summaries['A.setValue']={'writes':[{'state':'THIS.value','value':'PARAM0'}], 'returns':None}
summaries['A.setOther']={'writes':[{'state':'THIS.other','value':'PARAM0'}], 'returns':None}
summaries['A.readValue']={'writes':[], 'returns':'STATE(THIS.value)'}
summaries['A.readOther']={'writes':[], 'returns':'STATE(THIS.other)'}
summaries['store']={'writes':[{'state':'PARAM0.worker.value','value':'PARAM1'}], 'returns':None}
summaries['load']={'writes':[], 'returns':'STATE(PARAM0.worker.value)'}
obj={'schema':'STATE_SUMMARY_IR_V1','identity_rule':'receiver identity + property path','merge_rule':'do not merge distinct allocation sites or distinct property names','overwrite_rule':'later exact write replaces prior exact state value','summaries':summaries}
Path(sys.argv[2]).write_text(json.dumps(obj,indent=2)+'\n')

#!/usr/bin/env python3
"""Builds every scenario in the struct-member capacity matrix, runs each
through the REAL normalizer (subprocess, no shortcuts), and asserts the
expected outcome. PASS/FAIL per scenario, like the rest of this repo's gates.
"""
import json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).parent
FRONTEND = HERE / '../../portable-engine-full-review-package/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py'
sys.path.insert(0, str(HERE))
from make_nss_sslmac_raw import build

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(('PASS' if cond else 'FAIL'), name)


def run(rawdir, outname):
    outpath = HERE / (outname + '.json')
    subprocess.run([sys.executable, str(FRONTEND), str(HERE / rawdir), str(outpath)], check=True)
    return {
        'destcapacity': json.loads((HERE / (outname + '.json.destcapacity.json')).read_text()),
        'fieldcapclass': json.loads((HERE / (outname + '.json.fieldcapclass.json')).read_text()),
        'bound': json.loads((HERE / (outname + '.json.bound.json')).read_text()),
    }


# --- 1. THE CONFIRMED REAL SITE: SFTKSSLMACInfoStr.key[256], PORT_Memcpy.
# This IS the development-regression fixture for the ASan-confirmed
# sftk_doSSLMACInit bug (lib/softoken/pkcs11c.c:2547).
build(str(HERE / 'raw_nss_site'), struct_name='SFTKSSLMACInfoStr', member_name='key',
      member_type_full_name='unsigned char[256]', extent_local_name='ulValueLen')
r = run('raw_nss_site', 'out_nss_site')
dc = r['destcapacity']['dest_capacities']
ck('NSS site: exactly one dest-capacity fact emitted', len(dc) == 1)
ck('NSS site: rule=CPP_STRUCT_MEMBER_ARRAY_CAPACITY', dc and dc[0]['derivation']['rule'] == 'CPP_STRUCT_MEMBER_ARRAY_CAPACITY')
ck('NSS site: capacity_bytes == 256 (MAX_KEY_LEN)', dc and dc[0]['capacity_bytes'] == 256)
ck('NSS site: resolution == EXACT_STORAGE_IDENTITY', dc and dc[0]['resolution'] == 'EXACT_STORAGE_IDENTITY')
ck('NSS site: NO bound fact -- open_candidate (no guard exists in the real code)', r['bound']['bounds'] == [])

# --- 2. NEGATIVE CONTROL: same shape, but the callee name is NOT in
# _OPERAND_ROLES. Proves the PORT_Memcpy registration fix above is load-bearing
# -- without it, this whole pipeline is silently blind to the real call.
build(str(HERE / 'raw_unregistered_callee'), struct_name='SFTKSSLMACInfoStr', member_name='key',
      member_type_full_name='unsigned char[256]', extent_local_name='ulValueLen',
      copy_callee='PORT_Memcpy_NOT_REGISTERED')
r_neg = run('raw_unregistered_callee', 'out_unregistered_callee')
ck('negative control: unregistered callee name -> ZERO dest-capacity facts (abstain, not silent success)',
   r_neg['destcapacity']['dest_capacities'] == [])

# --- 3. ADVERSARIAL: pointer member (char *key, not char key[N]) -- identity
# resolves, capacity must NOT be fabricated.
build(str(HERE / 'raw_adv_pointer_member'), struct_name='PtrKeyInfo', member_name='key',
      member_type_full_name='unsigned char *', extent_local_name='len')
r_ptr = run('raw_adv_pointer_member', 'out_adv_pointer_member')
ck('pointer member: no capacity fabricated', r_ptr['destcapacity']['dest_capacities'] == [])
ck('pointer member: classified POINTER_MEMBER (identity present, capacity unknown)',
   r_ptr['fieldcapclass']['classification'].get('POINTER_MEMBER') == 1)

# --- 4. ADVERSARIAL: flexible array member (char key[]) -- identity resolves,
# dimension lost, must abstain rather than guess 0/unbounded.
build(str(HERE / 'raw_adv_flexible_array'), struct_name='FlexKeyInfo', member_name='key',
      member_type_full_name='unsigned char []', extent_local_name='len')
r_flex = run('raw_adv_flexible_array', 'out_adv_flexible_array')
ck('flexible array member: no capacity fabricated', r_flex['destcapacity']['dest_capacities'] == [])
ck('flexible array member: classified UNKNOWN_ARRAY_DIMENSION',
   r_flex['fieldcapclass']['classification'].get('UNKNOWN_ARRAY_DIMENSION') == 1)

# --- 5. ADVERSARIAL: arithmetic-macro dimension, mozjpeg-style
# (`#define BUFSIZE (DCTSIZE2*2)+8`) as a STRUCT MEMBER, not a local array.
# Exercises the _fixed_array_capacity arithmetic-folding fix specifically for
# the member path (the local-array path already had it via a different
# producer; the member path did not, until this session's fix).
build(str(HERE / 'raw_adv_arith_macro'), struct_name='JpegBufInfo', member_name='buf',
      member_type_full_name='unsigned char[(64*2)+8]', extent_local_name='len')
r_arith = run('raw_adv_arith_macro', 'out_adv_arith_macro')
dc_arith = r_arith['destcapacity']['dest_capacities']
ck('arithmetic-macro member dimension: capacity resolved via folding', len(dc_arith) == 1)
ck('arithmetic-macro member dimension: capacity_bytes == 136 ((64*2)+8)',
   dc_arith and dc_arith[0]['capacity_bytes'] == 136)

# --- 6. ADVERSARIAL: member name AMBIGUOUS across two DIFFERENT structs with
# DIFFERENT array sizes for the same member name -- must resolve via the
# base identifier's OWN type, not silently pick either one, and must NOT
# conflate the two capacities.
build(str(HERE / 'raw_adv_ambiguous_member'), struct_name='StructA', member_name='buf',
      member_type_full_name='unsigned char[16]',
      extra_members={'StructB': 'unsigned char[512]'}, extent_local_name='len')
r_amb = run('raw_adv_ambiguous_member', 'out_adv_ambiguous_member')
dc_amb = r_amb['destcapacity']['dest_capacities']
ck('ambiguous member name (StructA.buf[16] vs StructB.buf[512]): resolves via base-type scoping',
   len(dc_amb) == 1 and dc_amb[0]['capacity_bytes'] == 16)
ck('ambiguous member name: does NOT conflate with the other struct\'s capacity (512)',
   not (dc_amb and dc_amb[0]['capacity_bytes'] == 512))

print(f'NSS_SSLMAC_CAPACITY_R01={ok}/{total}')
sys.exit(0 if ok == total else 1)

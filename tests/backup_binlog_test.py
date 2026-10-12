"""Synthetic raw MariaDB event guards; no real DB, credentials or network."""
import binascii, copy, hashlib, importlib.util, pathlib, struct, sys, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
FILE='suhoput2-binlog.000001'
def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('binlog'),'Archived ROW byte guard absent')
    import binlog
    return binlog
def event(kind,payload,offset,flags=0,end=None):
    size=19+len(payload)+4
    raw=struct.pack('<IBIIIH',0,kind,2047,size,offset+size if end is None else end,flags)+payload
    return raw+struct.pack('<I',binascii.crc32(raw)&0xffffffff)
def fde(algorithm=1,version=b'10.11.19-MariaDB-log',headers=None):
    post=bytearray(171)
    for kind,length in {2:13,4:8,19:8,23:8,24:8,25:8,30:10,31:10,32:10,161:4,162:19,163:4}.items(): post[kind-1]=length
    if headers:
        for kind,length in headers.items(): post[kind-1]=length
    return struct.pack('<H',4)+version.ljust(50,b'\0')+struct.pack('<I',0)+bytes([19])+bytes(post)+bytes([algorithm])
def table_map(schema=b'suhoput2_stage',table=b'wp_posts',tid=7):
    return tid.to_bytes(6,'little')+b'\0\0'+bytes([len(schema)])+schema+b'\0'+bytes([len(table)])+table+b'\0'+b'\x01\x03\x00\x00'
def rows(tid=7,kind=23,extra=b''):
    head=tid.to_bytes(6,'little')+b'\x01\0'
    if kind in (30,31,32): head+=struct.pack('<H',2+len(extra))+extra
    return head+b'\x01\x01'+(b'\x01' if kind in (24,31) else b'')+b'\0'+struct.pack('<I',42)
def query(sql=b'BEGIN',database=b'suhoput2_stage',status=b''):
    return struct.pack('<IIBHH',1,0,len(database),0,len(status))+status+database+b'\0'+sql
def build(events=None):
    specs=[(15,fde())]+(events if events is not None else [(2,query()),(19,table_map()),(23,rows()),(16,struct.pack('<Q',1))])
    output=b'\xfebin'; offsets=[4]
    for kind,payload in specs:
        output+=event(kind,payload,len(output)); offsets.append(len(output))
    return output,offsets
def data(raw,file=FILE):
    return {file:raw},[{'file':file,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}]
class ByteGuardTests(unittest.TestCase):
    def call(self,raw,start=4,stop=None,file=FILE):
        mapping,descriptors=data(raw,file)
        return subject().validate_chain(mapping,descriptors,{'file':file,'position':start},{'file':file,'position':len(raw) if stop is None else stop})
    def test_valid_scoped_rows_have_exact_sha_and_boundary_report(self):
        raw,boundaries=build(); result=self.call(raw)
        self.assertEqual(result['result'],'PASS'); self.assertEqual(result['selected_row_events'],1)
        self.assertEqual(result['mapped_tables'],['suhoput2_stage.wp_posts'])
        self.assertEqual(result['files'],data(raw)[1]); self.assertEqual(result['stop'],{'file':FILE,'position':len(raw)})
    def test_crc_corruption_rejected_even_with_matching_descriptor_sha(self):
        raw,_=build(); bad=bytearray(raw); bad[-6]^=1
        with self.assertRaises(guards.GuardError): self.call(bytes(bad))
    def test_descriptor_sha_size_unknown_extra_and_missing_files_rejected(self):
        raw,_=build(); mapping,descriptors=data(raw)
        for mutation in ('sha','size','extra','missing','duplicate'):
            m=copy.deepcopy(mapping); d=copy.deepcopy(descriptors)
            if mutation=='sha': d[0]['sha256']='0'*64
            elif mutation=='size': d[0]['size']+=1
            elif mutation=='extra': m['suhoput2-binlog.000002']=raw
            elif mutation=='missing': m.clear()
            elif mutation=='duplicate': d.append(copy.deepcopy(d[0]))
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):
                subject().validate_chain(m,d,{'file':FILE,'position':4},{'file':FILE,'position':len(raw)})
    def test_bad_magic_truncated_header_size_end_position_and_trailing_bytes(self):
        good,_=build()
        bads=[b'NOPE'+good[4:],good[:10],good[:-1],good+b'x']
        first=event(15,fde(),4,end=999)
        bads.append(b'\xfebin'+first)
        short=bytearray(good); struct.pack_into('<I',short,4+9,18); bads.append(bytes(short))
        for raw in bads:
            with self.subTest(size=len(raw)),self.assertRaises(guards.GuardError): self.call(raw)
    def test_fde_requires_mariadb_1011_crc32_header_and_known_post_headers(self):
        for payload in (fde(0),fde(version=b'8.0.41-MySQL'),fde(headers={19:6}),fde()[:56]+b'\x12'+fde()[57:]):
            raw=b'\xfebin'+event(15,payload,4)
            with self.subTest(payload=payload[:4]),self.assertRaises(guards.GuardError): self.call(raw)
        raw,_=build([(2,query())]); raw=raw[4+len(event(15,fde(),4)):]
        with self.assertRaises(guards.GuardError): self.call(b'\xfebin'+raw)
    def test_foreign_schema_prefix_and_table_name_injection_block(self):
        for schema,table in [(b'production',b'wp_posts'),(b'suhoput2_stage',b'other_posts'),(b'suhoput2_stage',b'wp_posts;DROP'),(b'suhoput2_stage\0x',b'wp_posts')]:
            raw,_=build([(2,query()),(19,table_map(schema,table)),(23,rows()),(16,struct.pack('<Q',1))])
            with self.subTest(schema=schema,table=table),self.assertRaises(guards.GuardError): self.call(raw)
    def test_row_reference_requires_current_selected_table_map(self):
        for events in ([(2,query()),(23,rows())],[(2,query()),(19,table_map()),(23,rows(tid=8))],[(2,query()),(19,table_map()),(23,rows()),(16,struct.pack('<Q',1)),(2,query()),(23,rows()),(16,struct.pack('<Q',2))]):
            raw,_=build(events)
            with self.assertRaises(guards.GuardError): self.call(raw)
        raw,boundaries=build()
        with self.assertRaises(guards.GuardError): self.call(raw,start=boundaries[3])
    def test_query_accepts_only_literal_transaction_statements(self):
        for sql in (b'CREATE TABLE wp_x(i INT)',b'INSERT INTO wp_posts VALUES(1)',b'BEGIN;DROP DATABASE production',b'BEGIN /* extra */',b'USE production',b'COMMIT\0DROP',b'/*! COMMIT */'):
            raw,_=build([(2,query(sql))])
            with self.subTest(sql=sql),self.assertRaises(guards.GuardError): self.call(raw)
        for sql in (b'COMMIT',b'ROLLBACK',b'COMMIT;'):
            raw,_=build([(2,query()),(2,query(sql))]); self.assertEqual(self.call(raw)['result'],'PASS')
        raw,_=build([(2,query(database=b'production'))])
        with self.assertRaises(guards.GuardError): self.call(raw)
    def test_unknown_ddl_compressed_encrypted_and_xa_event_codes_block(self):
        for kind in (0,5,6,26,28,33,38,39,40,164,165,166,169,255):
            raw,_=build([(kind,b'unknown')])
            with self.subTest(kind=kind),self.assertRaises(guards.GuardError): self.call(raw)
    def test_replay_start_stop_require_event_and_transaction_boundaries(self):
        raw,boundaries=build()
        for start,stop in ((5,len(raw)),(4,len(raw)-1),(len(raw),4),(4,boundaries[4]),(boundaries[2],len(raw))):
            with self.subTest(start=start,stop=stop),self.assertRaises(guards.GuardError): self.call(raw,start,stop)
        self.assertEqual(self.call(raw,start=boundaries[1])['selected_row_events'],1)
    def test_table_map_and_rows_structural_truncation_block(self):
        for kind,payload in [(19,table_map()[:8]),(19,table_map()[:-1]),(23,rows()[:8]),(30,rows(kind=30,extra=b'x')[:9])]:
            raw,_=build([(2,query()),(kind,payload)])
            with self.subTest(kind=kind),self.assertRaises(guards.GuardError): self.call(raw)
    def test_contiguous_files_reset_table_map_and_validate_rotate_target(self):
        one,_=build([(4,struct.pack('<Q',4)+b'suhoput2-binlog.000002')]); two,_=build()
        m,d=data(one); m2,d2=data(two,'suhoput2-binlog.000002'); m.update(m2); d+=d2
        result=subject().validate_chain(m,d,{'file':FILE,'position':4},{'file':'suhoput2-binlog.000002','position':len(two)})
        self.assertEqual(result['selected_row_events'],1)
        m,d=data(one); m3,d3=data(two,'suhoput2-binlog.000003'); m.update(m3); d+=d3
        with self.assertRaises(guards.GuardError): subject().validate_chain(m,d,{'file':FILE,'position':4},{'file':'suhoput2-binlog.000003','position':len(two)})
        bad,_=build([(4,struct.pack('<Q',4)+b'production-binlog.000002')])
        with self.assertRaises(guards.GuardError): self.call(bad)
    def test_known_benign_mariadb_events_do_not_execute_annotated_sql(self):
        checkpoint=struct.pack('<I',len(FILE))+FILE.encode()
        gtid=struct.pack('<QI',1,0)+b'\x04'+b'\0'*6
        raw,_=build([(163,struct.pack('<I',0)+b'\0\0'),(161,checkpoint),(162,gtid),(160,b'INSERT INTO suhoput2_stage.wp_posts VALUES (42)'),(19,table_map()),(30,rows(kind=30)),(16,struct.pack('<Q',1)),(3,b'')])
        self.assertEqual(self.call(raw)['selected_row_events'],1)
    def test_gtid_ddl_xa_and_standalone_flags_block(self):
        for flag in (1,32,64,128):
            raw,_=build([(162,struct.pack('<QI',1,0)+bytes([flag])+b'\0'*6)])
            with self.subTest(flag=flag),self.assertRaises(guards.GuardError): self.call(raw)
    def test_scope_cannot_be_replaced_with_production(self):
        raw,_=build(); m,d=data(raw)
        with self.assertRaises(guards.GuardError): subject().validate_chain(m,d,{'file':FILE,'position':4},{'file':FILE,'position':len(raw)},schema='production',prefix='wp_')
    def test_query_status_strings_cannot_inject_native_generated_session_sql(self):
        for timezone in (b"UTC'; DROP DATABASE production; -- ",b'UTC\\',b'UTC\nDROP',b'UTC\0x',b'UTC;SELECT 1'):
            status=b'\x05'+bytes([len(timezone)])+timezone
            raw,_=build([(2,query(status=status)),(2,query(b'COMMIT'))])
            with self.subTest(timezone=timezone),self.assertRaises(guards.GuardError): self.call(raw)
    def test_query_status_unknown_duplicate_and_truncated_items_block(self):
        for status in (b'\xff',b'\x00\x01',b'\x05',b'\x05\x05UTC',b'\x00'+b'\0'*4+b'\x00'+b'\0'*4,b'\x0b\x01u\x01h',b'\x82'+b'\0'*10):
            raw,_=build([(2,query(status=status)),(2,query(b'COMMIT'))])
            with self.subTest(status=status),self.assertRaises(guards.GuardError): self.call(raw)
    def test_query_status_numeric_and_closed_timezone_values_are_safe(self):
        fixed=b'\x00'+struct.pack('<I',0)+b'\x01'+struct.pack('<Q',0)+b'\x03'+struct.pack('<HH',1,1)+b'\x04'+struct.pack('<HHH',45,45,45)+b'\x07'+struct.pack('<H',0)+b'\x08'+struct.pack('<H',45)+b'\x80'+b'\0'*3+b'\x81'+struct.pack('<Q',1)
        for timezone in (b'SYSTEM',b'UTC',b'Europe/Moscow',b'+00:00',b'-03:30'):
            status=fixed+b'\x05'+bytes([len(timezone)])+timezone
            raw,_=build([(2,query(status=status)),(2,query(b'COMMIT'))])
            self.assertEqual(self.call(raw)['result'],'PASS')

    def test_native_empty_gtid_list_has_exact_two_zero_padding_bytes(self):
        raw,_=build([(163,struct.pack('<I',0)+b'\0\0')])
        result=self.call(raw)
        self.assertEqual(result['result'],'PASS'); self.assertEqual(result['selected_row_events'],0)
    def test_empty_gtid_padding_count_flags_and_payload_length_are_strict(self):
        for body in (struct.pack('<I',0),struct.pack('<I',0)+b'\0',struct.pack('<I',0)+b'\x01\0',struct.pack('<I',0)+b'\0\x01',struct.pack('<I',0)+b'\0'*3,struct.pack('<I',1)+b'\0\0',struct.pack('<I',1<<28)+b'\0\0',struct.pack('<I',1<<29)+b'\0\0',struct.pack('<I',1<<31)+b'\0\0'):
            raw,_=build([(163,body)])
            with self.subTest(body=body),self.assertRaises(guards.GuardError): self.call(raw)
    def test_populated_native_gtid_list_has_exact_sixteen_byte_records(self):
        body=struct.pack('<I',1)+struct.pack('<IIQ',0,2047,1)
        raw,_=build([(163,body)])
        self.assertEqual(self.call(raw)['result'],'PASS')
        for wrong in (body[:-1],body+b'\0',struct.pack('<I',2)+body[4:]):
            raw,_=build([(163,wrong)])
            with self.assertRaises(guards.GuardError): self.call(raw)

if __name__=='__main__': unittest.main()

"""Commissioned capture bounds must reject growth before upload authority."""
import pathlib,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import budget,guards,worker,maintenance,backup_catalog,restic_adapter

class CaptureBudgetTests(unittest.TestCase):
    def case(self):
        root=pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        w=worker.Worker.__new__(worker.Worker);w.root=root;w.c={'retention_readiness_policy':'native-v2'}
        (root/'receipts').mkdir();(root/'receipts/commissioning-budget.json').write_bytes(b'protected report read by real loader')
        return w
    def test_payload_bound_counts_uncompressed_files_and_authenticates_current_forecast(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}) as loader:
            w.check_capture_budget({'kind':'hourly','files':[{'bytes':384*1024-4096}]})
            loader.assert_called_once_with(w)
            with self.assertRaisesRegex(guards.GuardError,'Capture exceeds commissioned'):
                w.check_capture_budget({'kind':'hourly','files':[{'bytes':1024**2},{'bytes':1}]})
    def test_every_capture_kind_has_its_own_total_raw_bound(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            for kind,limit in worker.CAPTURE_LIMITS.items():
                with self.subTest(kind=kind):
                    # Binlog also has a tighter native metadata bound; a huge
                    # content-ID array must reject even below its raw ceiling.
                    accepted=min(limit,2*1024**2) if kind=='binlog' else limit
                    name='logs/suhoput2-binlog.000001' if kind=='binlog' else ('wordpress/fixed' if kind in ('full','pre-update') else 'db.sql')
                    w.check_capture_budget({'kind':kind,'files':[{'path':name,'bytes':accepted-4096}]})
                    with self.assertRaises(guards.GuardError):w.check_capture_budget({'kind':kind,'files':[{'bytes':limit+1}]})
    def test_expired_or_changed_forecast_blocks_even_a_small_capture(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',side_effect=guards.GuardError('Cost configuration changed')):
            with self.assertRaisesRegex(guards.GuardError,'Cost configuration changed'):
                w.check_capture_budget({'kind':'hourly','files':[{'bytes':1}]})
    def test_initial_manual_controls_without_report_do_not_claim_budget_admission(self):
        w=self.case();(w.root/'receipts/commissioning-budget.json').unlink()
        with mock.patch.object(budget,'load_commissioning_budget') as loader:
            w.check_capture_budget({'kind':'full','files':[{'bytes':256*1024**2+1}]});loader.assert_not_called()
    def test_unknown_kind_or_invalid_raw_size_cannot_bypass_bound(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            for value in [{'kind':'other','files':[]},{'kind':'hourly','files':[{'bytes':-1}]},{'kind':'hourly','files':[{'bytes':True}]}]:
                with self.assertRaises(guards.GuardError):w.check_capture_budget(value)
    def test_missing_report_with_surviving_origin_does_not_return_to_initial_calibration(self):
        w=self.case();(w.root/'receipts/commissioning-budget.json').unlink();(w.root/'receipts/commissioning-budget.origin.json').write_bytes(b'original protected origin')
        with mock.patch.object(budget,'load_commissioning_budget',side_effect=guards.GuardError('Missing protected report')):
            with self.assertRaisesRegex(guards.GuardError,'Missing protected report'):w.check_capture_budget({'kind':'hourly','files':[]})
    def test_upload_over_bound_never_creates_native_adapter_or_capture_authority(self):
        import json
        w=self.case();w.catalog_deadline=lambda lane:None
        payload=w.root/'spool/base-payload';payload.mkdir(parents=True)
        (payload/'manifest.json').write_text(json.dumps({'kind':'hourly','files':[{'bytes':1024**2+1}]}))
        (payload/'manifest.json').chmod(0o600)
        with mock.patch.object(maintenance,'require_clear'),mock.patch.object(backup_catalog,'ArchiveCatalog'), \
             mock.patch.object(worker,'verify_payload'),mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}), \
             mock.patch.object(restic_adapter,'ResticAdapter') as adapter,mock.patch.object(w,'capture_intent') as capture:
            with self.assertRaisesRegex(guards.GuardError,'Capture exceeds commissioned'):w.upload('base',payload)
            adapter.assert_not_called();capture.assert_not_called()
        self.assertFalse((w.root/'receipts/capture-base.json').exists());self.assertTrue(payload.exists())
    def test_manifest_bytes_are_part_of_total_raw_capture_bound(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            with self.assertRaisesRegex(guards.GuardError,'Capture exceeds commissioned'):
                w.check_capture_budget({'kind':'hourly','files':[{'path':'db.sql','bytes':1024**2}]})
    def test_many_empty_files_cannot_hide_large_manifest_and_native_metadata(self):
        w=self.case();manifest={'kind':'hourly','files':[{'path':'uploads/'+str(n)+'.txt','bytes':0,'sha256':'a'*64} for n in range(10000)]}
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            with self.assertRaises(guards.GuardError):w.check_capture_budget(manifest)
    def test_fulls_share_the_variable_database_and_media_bound(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            with self.assertRaisesRegex(guards.GuardError,'Dynamic base'):
                w.check_capture_budget({'kind':'full','files':[{'path':'wordpress/wp-includes/fixed','bytes':168*1024**2},{'path':'db.sql','bytes':16*1024**2}]})
    def test_actual_empty_directories_are_counted_before_any_native_upload(self):
        import json
        w=self.case();payload=w.root/'spool/base-payload';payload.mkdir(parents=True)
        manifest={'kind':'hourly','files':[]};(payload/'manifest.json').write_text(json.dumps(manifest))
        (payload/'manifest.json').chmod(0o600)
        for number in range(150):(payload/('empty-'+str(number))).mkdir()
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'result':'PASS'}):
            with self.assertRaisesRegex(guards.GuardError,'native metadata'):w.check_capture_budget(manifest,payload)
    def test_binlog_manifest_and_nonlog_marker_have_a_shared_bound(self):
        w=self.case()
        with self.assertRaisesRegex(guards.GuardError,'Binlog control bytes'):
            w.validate_capture_geometry({'kind':'binlog','files':[{'path':'.capture.json','bytes':2048},{'path':'logs/suhoput2-binlog.000001','bytes':100}]})
    def test_native_name_bound_handles_HTML_and_double_JSON_escaping(self):
        w=self.case()
        small=w.validate_capture_geometry({'kind':'hourly','files':[{'path':'uploads/a','bytes':0}]})
        escaped=w.validate_capture_geometry({'kind':'hourly','files':[{'path':'uploads/<\\\"&>','bytes':0}]})
        self.assertEqual(escaped['native_metadata_bound_bytes']-small['native_metadata_bound_bytes'],8*4)
    def test_pure_calibration_does_not_load_or_admit_a_budget(self):
        w=self.case()
        with mock.patch.object(budget,'load_commissioning_budget') as load:
            value=w.validate_capture_geometry({'kind':'hourly','files':[{'path':'db.sql','bytes':100}]})
            self.assertGreater(value['raw_bytes'],100);load.assert_not_called()
    def test_changed_application_identity_blocks_small_real_capture(self):
        import json
        w=self.case();p=w.root/'spool/base-payload';p.mkdir(parents=True)
        m={'kind':'hourly','files':[],'application_sha256':'b'*64,'configuration_sha256':'c'*64}
        (p/'manifest.json').write_text(json.dumps(m));(p/'manifest.json').chmod(0o600)
        report={'capture_policy':{'application_identity':{'application_sha256':'a'*64,'configuration_sha256':'c'*64}}}
        with mock.patch.object(budget,'load_commissioning_budget',return_value=report),mock.patch.object(w,'validate_capture_geometry',return_value={'raw_bytes':1}) as geometry:
            with self.assertRaisesRegex(guards.GuardError,'application identity changed'):w.check_capture_budget(m,p)
            geometry.assert_called_once_with(m,p,fixed_helpers=None)
    def test_full_public_helpers_are_fixed_only_under_exact_complete_authenticated_pins(self):
        w=self.case();pins={name:{'bytes':32768,'sha256':'a'*64} for name in worker.PUBLIC_HELPERS}
        files=[{'path':'configuration/backup-public/'+name,**value} for name,value in pins.items()]
        manifest={'kind':'full','files':files+[{'path':'db.sql','bytes':300000}]}
        with self.assertRaisesRegex(guards.GuardError,'recovery helper identity'):w.validate_capture_geometry(manifest)
        result=w.validate_capture_geometry(manifest,fixed_helpers=pins)
        self.assertEqual(result['dynamic_base_bytes'],300000)
        changed={name:dict(value) for name,value in pins.items()};changed['worker.py']['sha256']='b'*64
        with self.assertRaisesRegex(guards.GuardError,'recovery helper identity'):w.validate_capture_geometry(manifest,fixed_helpers=changed)
        with self.assertRaisesRegex(guards.GuardError,'recovery helper identity'):w.validate_capture_geometry({**manifest,'files':files[:-1]},fixed_helpers=pins)
    def test_unpinned_extra_full_bytes_do_not_become_fixed_application_data(self):
        w=self.case()
        with self.assertRaisesRegex(guards.GuardError,'Dynamic base'):
            w.validate_capture_geometry({'kind':'full','files':[{'path':'unknown-extra','bytes':384*1024+1}]})
    def test_rolling_source_binlog_bound_counts_active_and_recent_closed_files(self):
        import os,time
        w=self.case();w.db_volume=w.root/'source';w.db_volume.mkdir()
        for n,size in ((1,111),(2,222),(3,333)):(w.db_volume/('suhoput2-binlog.'+str(n).zfill(6))).write_bytes(b'x'*size)
        old=w.db_volume/'suhoput2-binlog.000001';os.utime(old,(time.time()-86401,)*2)
        (w.db_volume/'suhoput2-binlog.index').write_bytes(b'not log data')
        self.assertEqual(w.recent_source_binlog_bytes(),555)
    def test_small_minute_capture_cannot_bypass_large_daily_source_growth(self):
        w=self.case();p=w.root/'spool/binlog-payload';m={'kind':'binlog','files':[]}
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'capture_policy':{}}), \
             mock.patch.object(w,'validate_capture_geometry',return_value={'raw_bytes':1}), \
             mock.patch.object(w,'recent_source_binlog_bytes',return_value=2*1024**2+1):
            with self.assertRaisesRegex(guards.GuardError,'daily bound'):w.check_capture_budget(m,p)
    def test_aged_backlog_cannot_bypass_captured_or_confirmed_day_bound(self):
        w=self.case();p=w.root/'spool/binlog-payload'
        with mock.patch.object(budget,'load_commissioning_budget',return_value={'capture_policy':{}}), \
             mock.patch.object(w,'validate_capture_geometry',return_value={'manifest_sha256':'a'*64}), \
             mock.patch.object(w,'recent_source_binlog_bytes',return_value=0), \
             mock.patch.object(w,'recent_confirmed_binlog_bytes',return_value=(0,False)) as confirmed:
            m={'kind':'binlog','files':[{'path':'logs/suhoput2-binlog.000001','bytes':3*1024**2}]}
            with self.assertRaisesRegex(guards.GuardError,'daily bound'):w.check_capture_budget(m,p)
            m['files'][0]['bytes']=1000000;confirmed.return_value=(1500000,False)
            with self.assertRaisesRegex(guards.GuardError,'daily bound'):w.check_capture_budget(m,p)
            confirmed.return_value=(1500000,True);w.check_capture_budget(m,p)
    def test_restore_wire_bound_limits_tiny_variable_files(self):
        w=self.case()
        with self.assertRaisesRegex(guards.GuardError,'file count'):
            w.validate_capture_geometry({'kind':'hourly','files':[{'path':'uploads/'+str(n),'bytes':1} for n in range(23)]})
    def test_full_media_duplicates_match_before_applying_fixed_pack_wire_bound(self):
        w=self.case();files=[{'path':'uploads/p.jpg','bytes':5,'sha256':'a'*64},{'path':'wordpress/wp-content/uploads/p.jpg','bytes':5,'sha256':'a'*64}]
        w.validate_capture_geometry({'kind':'full','files':files})
        files[1]['sha256']='b'*64
        with self.assertRaisesRegex(guards.GuardError,'media copies differ'):w.validate_capture_geometry({'kind':'full','files':files})

    def test_small_unpaired_full_file_cannot_expand_restore_pack_selection(self):
        w=self.case()
        with self.assertRaisesRegex(guards.GuardError,'Unknown full variable file'):
            w.validate_capture_geometry({'kind':'full','files':[{'path':'other-small-file','bytes':1}]})

if __name__=='__main__':unittest.main()

"""Read-only native metadata cache admission; synthetic files and S3 listings."""
import contextlib,copy,hashlib,json,os,pathlib,sys,tempfile,types,unittest
from unittest import mock
from xml.sax.saxutils import escape
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import budget,guards,retention_restore,runtime,storage


class MetadataCacheTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=pathlib.Path(tmp.name);self.root.chmod(0o700)
        self.rid='a'*64;self.gen='b'*32;self.events=[];self.calls=[];self.listings=[]
        self.w=types.SimpleNamespace(root=self.root,native=object(),source={'root':str(self.root),'generation':self.gen},
            c={'generation':self.gen,'code_sha':'f'*40,'retention_readiness_policy':'native-v2','endpoint':'https://s3.example.test',
               'bucket':'test-bucket','repositories':{'base':guards.repository_url('https://s3.example.test','test-bucket','base')}},restic=self.native)
        (self.root/'receipts').mkdir(mode=0o700);runtime.atomic_json(self.root/'receipts/init-base.json',{'generation':self.gen,'repository_id':self.rid})
        self.cache=self.root/'cache/base'/self.rid;self.cache.mkdir(mode=0o700,parents=True);(self.cache/'version').write_bytes(b'1');(self.cache/'version').chmod(0o600)
        self.pack=self.cached('data',b'tree pack cipher'+b'x'*128)
        self.index=self.cached('index',b'index cipher'+b'y'*64)
        self.indexes={self.index:(self.cache/'index'/self.index[:2]/self.index).stat().st_size}
        self.packs={self.pack:(self.cache/'data'/self.pack[:2]/self.pack).stat().st_size}
        self.docs={self.index:{'packs':[{'id':self.pack,'blobs':[{'id':'c'*64,'type':'tree','offset':0,'length':64}]}]}}
        self.reader_patch=mock.patch.object(storage,'S3Reader',side_effect=lambda *a,**kw:self.listing)
        self.reader_patch.start();self.addCleanup(self.reader_patch.stop)

    def cached(self,kind,raw):
        sid=hashlib.sha256(raw).hexdigest();path=self.cache/kind/sid[:2]/sid;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(0o600);return sid

    def path(self,kind,sid):return self.cache/kind/sid[:2]/sid

    def listing(self,query):
        self.events.append('list');self.listings.append(copy.deepcopy(query));prefix=storage.PREFIX+'base/'
        rows=[(prefix+'index/'+sid,size) for sid,size in self.indexes.items()]+[(prefix+'data/'+sid[:2]+'/'+sid,size) for sid,size in self.packs.items()]+[(prefix+'keys/'+'d'*64,64)]
        return ('<ListBucketResult><Name>test-bucket</Name><Prefix>'+prefix+'</Prefix><IsTruncated>false</IsTruncated>'+''.join(
            '<Contents><Key>'+escape(key)+'</Key><Size>'+str(size)+'</Size></Contents>' for key,size in rows)+'</ListBucketResult>').encode()

    def native(self,lane,args,**kwargs):
        self.events.append('config' if args[2:]==['cat','config'] else 'cat');self.calls.append((lane,args,kwargs))
        if args[2:]==['cat','config']:return json.dumps({'id':self.rid,'version':2}).encode()
        self.assertEqual(lane,'base');self.assertEqual(args[:4],['--repo',self.w.c['repositories']['base'],'cat','index'])
        return json.dumps(self.docs[args[4]]).encode()

    def subject(self):
        fn=getattr(retention_restore,'metadata_cache_preflight',None)
        self.assertTrue(callable(fn),'Missing read-only metadata cache preflight')
        return fn(self.w,self.rid)

    def commission(self):
        runtime.atomic_json(self.root/'receipts/commissioning-budget.json',{});runtime.atomic_json(self.root/'receipts/commissioning-budget.origin.json',{})

    def test_complete_manual_control_returns_readonly_proof_without_budget_admission(self):
        with mock.patch.object(budget,'load_commissioning_budget') as auth:proof=self.subject()
        auth.assert_not_called();self.assertEqual(proof['result'],'READ_ONLY_WARM_BASE_METADATA_CONTROL');self.assertFalse(proof['admission'])
        self.assertEqual(proof['repository_id'],self.rid);self.assertEqual(proof['index_count'],1);self.assertEqual(proof['active_tree_pack_count'],1)
        self.assertEqual(proof['source'],self.w.source);self.assertEqual(proof['code_sha'],self.w.c['code_sha'])
        self.assertEqual(self.events,['list','config','cat','list']);self.assertEqual(self.listings[0]['prefix'],storage.PREFIX+'base/')

    def test_commissioned_budget_authentication_precedes_any_paid_or_native_read(self):
        self.commission();failure=budget.BudgetError('Expired authenticated budget')
        with mock.patch.object(budget,'load_commissioning_budget',side_effect=failure),self.assertRaises(budget.BudgetError) as caught:self.subject()
        self.assertIs(caught.exception,failure);self.assertEqual(self.events,[])
        (self.root/'receipts/commissioning-budget.json').unlink()
        with mock.patch.object(budget,'load_commissioning_budget',side_effect=failure) as auth,self.assertRaises(budget.BudgetError):self.subject()
        auth.assert_called_once_with(self.w);self.assertEqual(self.events,[])

    def test_missing_one_of_all_indices_blocks_before_first_native_cat(self):
        sid=self.cached('index',b'other index cipher'+b'z'*64);self.indexes[sid]=self.path('index',sid).stat().st_size;self.path('index',sid).unlink()
        with self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(self.calls,[])

    def test_missing_tree_pack_blocks_and_never_hydrates_cache(self):
        self.path('data',self.pack).unlink()
        with self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(len(self.calls),2);self.assertFalse(self.path('data',self.pack).exists())

    def test_corrupt_cipher_size_or_digest_blocks(self):
        for kind,sid in [('index',self.index),('data',self.pack)]:
            path=self.path(kind,sid);raw=path.read_bytes();path.write_bytes(b'!'*len(raw))
            with self.subTest(kind=kind),self.assertRaisesRegex(guards.GuardError,'ciphertext'):self.subject()
            path.write_bytes(raw)
        self.indexes[self.index]+=1
        with self.assertRaises(guards.GuardError):self.subject()

    def test_symlink_or_hardlinked_cache_cipher_cannot_authorize_native_cat(self):
        path=self.path('index',self.index);raw=path.read_bytes();path.unlink();target=self.root/'cipher';target.write_bytes(raw);target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(self.calls,[]);path.unlink();os.link(target,path)
        with self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(self.calls,[])

    def test_symlink_cache_ancestor_blocks(self):
        parent=self.cache/'index'/self.index[:2];target=self.root/'index-files';parent.rename(target);parent.symlink_to(target,target_is_directory=True)
        with self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(self.calls,[])

    def test_foreign_repository_id_or_config_namespace_blocks_before_listing(self):
        for mutation in ('id','url','generation'):
            before=copy.deepcopy(self.w.c)
            if mutation=='url':self.w.c['repositories']['base']+='-foreign'
            elif mutation=='generation':self.w.c['generation']='e'*32
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):
                if mutation=='id':
                    fn=getattr(retention_restore,'metadata_cache_preflight',None);self.assertTrue(callable(fn));fn(self.w,'e'*64)
                else:self.subject()
            self.w.c=before
        self.assertEqual(self.events,[])

    def test_index_count_or_cipher_total_bounds_block_before_cat(self):
        for count,total in [(65,65*64),(1,16*1024**2+1)]:
            self.indexes={format(n,'064x'):(total if count==1 else 64) for n in range(count)}
            with self.subTest(count=count),self.assertRaises(guards.GuardError):self.subject()
        self.assertEqual(self.calls,[])

    def test_native_decrypted_index_requires_exact_typed_pack_and_blob_schema(self):
        original=copy.deepcopy(self.docs[self.index])
        for mutation in ('foreign-pack','type','offset','fields','duplicate','supersedes'):
            value=copy.deepcopy(original);pack=value['packs'][0];blob=pack['blobs'][0]
            if mutation=='foreign-pack':pack['id']='e'*64
            elif mutation=='type':blob['type']='unknown'
            elif mutation=='offset':blob['offset']=self.packs[self.pack]
            elif mutation=='fields':blob['authority']=True
            elif mutation=='duplicate':value['packs'].append(copy.deepcopy(pack))
            else:value['supersedes']=['e'*64]
            self.docs[self.index]=value
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):self.subject()

    def test_second_listing_index_drift_blocks(self):
        initial=self.listing;count=[0]
        def drift(query):
            count[0]+=1
            if count[0]==2:self.indexes[self.index]+=1
            return initial(query)
        with mock.patch.object(storage,'S3Reader',side_effect=lambda *a,**k:drift),self.assertRaisesRegex(guards.GuardError,'changed'):self.subject()

    def test_actual_native_repository_drift_blocks_before_cat_index(self):
        def changed(lane,args,**kwargs):
            self.calls.append((lane,args,kwargs));return json.dumps({'id':'e'*64,'version':2}).encode()
        self.w.restic=changed
        with self.assertRaisesRegex(guards.GuardError,'repository'):self.subject()
        self.assertEqual([row[1][2:] for row in self.calls],[['cat','config']])

    def test_listing_page_quota_blocks_before_ninth_network_request(self):
        count=[0]
        def pages(query):
            count[0]+=1
            return ('<ListBucketResult><Name>test-bucket</Name><Prefix>'+storage.PREFIX+'base/</Prefix><IsTruncated>true</IsTruncated><NextContinuationToken>'+str(count[0])+'</NextContinuationToken></ListBucketResult>').encode()
        with mock.patch.object(storage,'S3Reader',return_value=pages),self.assertRaisesRegex(guards.GuardError,'listing request bound'):self.subject()
        self.assertEqual(count,[8]);self.assertEqual(self.calls,[])

    def test_native_cache_version_has_exact_bytes_and_cache_files_are_root_owned(self):
        version=self.cache/'version';version.write_bytes(b'1\n')
        with self.assertRaisesRegex(guards.GuardError,'version'):self.subject()
        self.assertEqual(self.events,[]);version.write_bytes(b'1')
        original=pathlib.Path.lstat;target=self.path('index',self.index)
        def foreign_owner(path):
            info=original(path)
            if path==target:return types.SimpleNamespace(st_mode=info.st_mode,st_uid=1000,st_nlink=info.st_nlink,st_size=info.st_size)
            return info
        with mock.patch.object(pathlib.Path,'lstat',foreign_owner),self.assertRaisesRegex(guards.GuardError,'ciphertext'):self.subject()
        self.assertEqual(self.calls,[])

    def test_native_index_call_cannot_change_already_sealed_index_ciphertext(self):
        original=self.native
        def changed(lane,args,**kwargs):
            raw=original(lane,args,**kwargs)
            if args[2:4]==['cat','index']:
                path=self.path('index',self.index);path.write_bytes(b'!'*path.stat().st_size)
            return raw
        self.w.restic=changed
        with self.assertRaisesRegex(guards.GuardError,'ciphertext'):self.subject()

    def test_foreign_s3_listing_scope_blocks_before_native_reads(self):
        original=self.listing
        def foreign(query):return original(query).replace(b'<Name>test-bucket</Name>',b'<Name>foreign-bucket</Name>')
        with mock.patch.object(storage,'S3Reader',return_value=foreign),self.assertRaisesRegex(guards.GuardError,'scope'):self.subject()
        self.assertEqual(self.calls,[])

    def test_commissioned_restore_gates_after_prepare_before_intent_target_or_sql(self):
        self.commission();self.path('data',self.pack).unlink();recovery=object.__new__(retention_restore.RetentionRecovery)
        recovery.w=self.w;recovery.lock=self.root/'restore.lock';recovery.intent=self.root/'restore.intent';recovery.root=self.root/'target'
        self.w.gate=lambda:self.events.append('gate')
        def prepare(reader):self.events.append('prepare');recovery.inventory={'repositories':{'base':self.rid}}
        recovery.prepare=prepare
        recovery.plan={'profile':'tip','token':'e'*32}
        catalog=types.SimpleNamespace(open_reader=lambda:contextlib.nullcontext(object()))
        with mock.patch.object(budget,'load_commissioning_budget',return_value={}),mock.patch.object(runtime,'lane_lock',return_value=contextlib.nullcontext()), \
             mock.patch.object(retention_restore.backup_catalog,'ArchiveCatalog',return_value=catalog), \
             mock.patch.object(retention_restore,'objects_absent',side_effect=AssertionError('Targets consulted before metadata preflight')) as absent,self.assertRaises(guards.GuardError):recovery.run()
        absent.assert_not_called();self.assertFalse(recovery.intent.exists());self.assertFalse(recovery.root.exists())
        self.assertEqual(self.events[:2],['gate','prepare']);self.assertEqual(len(self.calls),2)

    def test_commissioned_restore_authenticates_before_prepare_paid_metadata_or_integrity(self):
        self.commission();recovery=object.__new__(retention_restore.RetentionRecovery);recovery.w=self.w
        recovery.lock=self.root/'restore.lock';self.w.gate=lambda:None
        recovery.inventory={'repositories':{'base':self.rid}};recovery.prepare=mock.Mock()
        catalog=types.SimpleNamespace(open_reader=lambda:contextlib.nullcontext(object()))
        failure=budget.BudgetError('Expired commissioning report')
        with mock.patch.object(budget,'load_commissioning_budget',side_effect=failure),mock.patch.object(runtime,'lane_lock',return_value=contextlib.nullcontext()), \
             mock.patch.object(retention_restore.backup_catalog,'ArchiveCatalog',return_value=catalog),self.assertRaises(budget.BudgetError):recovery.run()
        recovery.prepare.assert_not_called();self.assertEqual(self.events,[])


if __name__=='__main__':unittest.main()

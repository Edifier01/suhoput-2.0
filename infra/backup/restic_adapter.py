"""Restic manifest proofs; the supplied runner owns protected credentials.

No upload is acknowledged from a success exit code or snapshot tags alone.
Restic must authenticate and return the archived manifest bytes as well.
"""
import hashlib
import json
import pathlib
from urllib.parse import urlsplit
import guards,runtime,backup_catalog

def strict_json(raw):
    guards.require(isinstance(raw,bytes) and len(raw)<=64*1024*1024,'Native JSON oversized')
    return json.loads(raw,object_pairs_hook=runtime.no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

def verify_tree_listing(listing,sid,payload_root,native_metadata,raw_manifest):
    """Bind the actual native ls header/tree and every file to raw manifest bytes."""
    metadata=backup_catalog.decode(raw_manifest)
    native,_,_=backup_catalog.native_identity(native_metadata,sid,payload_root,metadata['generation'])
    expected={payload_root+'/manifest.json':len(raw_manifest)}
    for item in metadata['files']:
        name=guards.media_path(item['path']);guards.hex_id(item['sha256'],64)
        guards.require(type(item['bytes']) is int and item['bytes']>=0,'Malformed archive file size')
        path=payload_root+'/'+name;guards.require(path not in expected,'Duplicate archive file');expected[path]=item['bytes']
    guards.require(isinstance(listing,bytes) and len(listing)<=64*1024*1024,'Archive listing oversized')
    nodes=[strict_json(line) for line in listing.splitlines() if line.strip()]
    headers=[x for x in nodes if x.get('message_type')=='snapshot']
    guards.require(len(headers)==1 and headers[0].get('id')==sid and
                   all(headers[0].get(key)==native[key] for key in ('tree','paths','time','tags')),
                   'Actual native archive tree identity mismatch')
    actual={};seen=set()
    for node in nodes:
        if node.get('message_type')=='snapshot':continue
        path=node.get('path')
        guards.require(node.get('message_type')=='node' and node.get('type') in ('file','dir') and isinstance(path,str) and
                       (path==payload_root or path.startswith(payload_root+'/')) and path not in seen,
                       'Unknown or duplicate archive node');seen.add(path)
        if node['type']=='file':
            guards.require(type(node['size']) is int and node['size']>=0,'Invalid native file size');actual[path]=node['size']
    guards.require(actual==expected,'Partial or changed snapshot tree');return native


def verify_restored_tree(target,payload_root,metadata,raw_manifest,inventory):
    """Compare every native-restored byte, including outside the payload root.

    Restic 0.19.1 ls always lists repository snapshots, even with a full SID.
    Exact-SID restore authenticates that snapshot without that enumeration.
    The caller also binds its native cat snapshot identity before restoring.
    inventory rejects symlinks, hardlinks and special files and hashes all files.
    """
    scope=pathlib.Path(payload_root);prefix=scope.relative_to(scope.anchor).as_posix()
    guards.require(scope.is_absolute() and '..' not in scope.parts,'Canonical restored payload scope required')
    expected={prefix+'/manifest.json':{'bytes':len(raw_manifest),'sha256':hashlib.sha256(raw_manifest).hexdigest()}}
    for item in metadata['files']:
        name=guards.media_path(item['path']);guards.hex_id(item['sha256'],64)
        guards.require(type(item['bytes']) is int and item['bytes']>=0,'Invalid restored file size')
        key=prefix+'/'+name;guards.require(key not in expected,'Duplicate restored manifest file')
        expected[key]={'bytes':item['bytes'],'sha256':item['sha256']}
    actual=inventory(target)
    guards.require(isinstance(actual,list) and all(isinstance(row,dict) and set(row)=={'path','bytes','sha256'} and
                   isinstance(row['path'],str) for row in actual),'Malformed restored inventory')
    # Worker inventories retain Path component order in historical manifests;
    # e.g. widgets/file.js precedes widgets.js. Compare the same path order on
    # both sides without changing manifest order or collapsing duplicate rows.
    guards.require(sorted(actual,key=lambda row:row['path'])==[{'path':key,**expected[key]} for key in sorted(expected)],
                   'Partial, changed or foreign restored tree')
    # Native absolute-path restore legitimately creates the scope's ancestors;
    # unrelated empty directories outside the payload are still unexpected.
    for path in target.rglob('*'):
        if path.is_dir():
            name=path.relative_to(target).as_posix()
            guards.require(name==prefix or name.startswith(prefix+'/') or prefix.startswith(name+'/'),'Foreign restored directory')
    return target/scope.relative_to(scope.anchor)


def repository_scope(value):
    guards.require(isinstance(value, str) and value.startswith('s3:'), 'S3 repository required')
    parsed = urlsplit(value[3:])
    parts = parsed.path.split('/')
    guards.require(len(parts) == 6 and parts[0] == ''
                   and parts[2:5] == ['suhoput2', 'stage-b', 'repositories'],
                   'Repository prefix mismatch')
    # Expected path is /bucket/suhoput2/stage-b/repositories/lane.
    expected = guards.repository_url(parsed.scheme + '://' + parsed.netloc, parts[1], parts[-1])
    guards.require(value == expected, 'Repository scope mismatch')
    return value


class ResticAdapter:
    def __init__(self, repository, generation, payload_root, *, runner, verify_archive=None):
        self.repository = repository_scope(repository)
        self.generation = guards.hex_id(generation, 32)
        guards.require(isinstance(payload_root, str) and payload_root.startswith('/')
                       and '\\' not in payload_root and '\x00' not in payload_root
                       and '..' not in pathlib.PurePosixPath(payload_root).parts
                       and str(pathlib.PurePosixPath(payload_root)) == payload_root,
                       'Absolute canonical payload path required')
        self.payload_root = payload_root
        guards.require(callable(runner), 'Protected native runner required')
        self.run = lambda args: runner(['--repo', self.repository, *args])
        self.hints = {};self.verify_archive=verify_archive

    def find(self, token):
        guards.hex_id(token, 32)
        try:
            if token in self.hints:
                sid = self.hints[token]
                row = strict_json(self.run(['cat', 'snapshot', sid]))
                guards.require(isinstance(row, dict), 'Authenticated snapshot required')
                rows = [{**row, 'id': sid}]
            else:
                # Rare unknown-response recovery only. Native tag filtering
                # decrypts the inventory; this is not the normal minute path.
                rows = strict_json(self.run(['snapshots', '--json', '--tag', 'token:' + token]))
            guards.require(isinstance(rows, list), 'Snapshot list required')
            matches = []
            for row in rows:
                tags = row['tags']
                guards.require(isinstance(tags, list) and all(isinstance(x, str) for x in tags)
                               and len(tags) == len(set(tags)), 'Malformed snapshot tags')
                for prefix, expected in [('generation:', self.generation), ('token:', token)]:
                    values = [x[len(prefix):] for x in tags if x.startswith(prefix)]
                    guards.require(values == [expected], 'Snapshot identity mismatch')
                digests = [x[len('manifest-sha:'):] for x in tags if x.startswith('manifest-sha:')]
                guards.require('task047' in tags and len(digests) == 1, 'Unrelated snapshot')
                digest = guards.hex_id(digests[0], 64)
                sid = guards.hex_id(row['id'], 64)
                body = self.run(['dump', sid, self.payload_root + '/manifest.json'])
                guards.require(isinstance(body, bytes) and len(body) <= 64 * 1024 * 1024,
                               'Manifest bytes required')
                guards.require(hashlib.sha256(body).hexdigest() == digest, 'Archived manifest mismatch')
                metadata=backup_catalog.decode(body);guards.require(metadata.get('generation')==self.generation and isinstance(metadata.get('files'),list),'Unknown archived manifest format')
                backup_catalog.native_identity(row,sid,self.payload_root,self.generation)
                guards.require(callable(self.verify_archive) and self.verify_archive(sid,metadata,native_metadata=row,raw_manifest=body) is True,'Actual archived bytes verifier required')
                matches.append({'id': sid, 'token': token, 'generation': self.generation,
                                'manifest_sha256': digest})
            return matches
        except (KeyError, TypeError, ValueError,AttributeError,UnicodeError,RecursionError) as error:
            raise guards.GuardError('Invalid remote manifest proof') from error

    def put(self, payload, pending):
        guards.require(str(payload) == self.payload_root and pending['generation'] == self.generation,
                       'Upload scope mismatch')
        token = guards.hex_id(pending['token'], 32)
        digest = guards.hex_id(pending['manifest_sha256'], 64)
        manifest = pathlib.Path(payload) / 'manifest.json'
        guards.require(not manifest.is_symlink() and manifest.is_file()
                       and hashlib.sha256(manifest.read_bytes()).hexdigest() == digest,
                       'Upload manifest changed')
        args=['backup', self.payload_root, '--json', '--host', 'task047-stage-b',
                  '--tag', 'task047', '--tag', 'generation:' + self.generation,
                  '--tag', 'token:' + token, '--tag', 'manifest-sha:' + digest]
        if 'parent_id' in pending:
            args.extend(['--parent', guards.hex_id(pending['parent_id'], 64)])
        output=self.run(args)
        try:
            rows=[json.loads(line) for line in output.splitlines() if line.strip()]
            summaries=[x for x in rows if isinstance(x,dict) and x.get('message_type')=='summary']
            guards.require(len(summaries)==1,'Unknown backup result')
            # The response ID is a lookup hint, never upload confirmation.
            self.hints[token]=guards.hex_id(summaries[0]['snapshot_id'],64)
        except (ValueError,TypeError,KeyError,AttributeError) as error:
            raise guards.GuardError('Unknown backup result; reconcile, no automatic retry') from error

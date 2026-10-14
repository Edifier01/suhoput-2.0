"""Read records from native complete-insert/single-row MariaDB dump bytes.
Unsupported SQL row grammar fails closed; no SQL execution or WP bootstrap.
"""
import re
import guards
ESC={ord('0'):b'\0',ord('b'):b'\b',ord('n'):b'\n',ord('r'):b'\r',ord('t'):b'\t',ord('Z'):b'\x1a',ord('\\'):b'\\',ord("'"):b"'",ord('"'):b'"'}
def values(raw):
    result=[];i=0;n=len(raw)
    while i<n:
        while i<n and raw[i] in b' \t':i+=1
        guards.require(i<n,'Incomplete SQL row')
        if raw[i]==39:
            i+=1;out=bytearray();closed=False
            while i<n:
                c=raw[i];i+=1
                if c==39:
                    if i<n and raw[i]==39:out.append(39);i+=1;continue
                    closed=True;break
                if c==92:
                    guards.require(i<n and raw[i] in ESC,'Unknown SQL escape');out.extend(ESC[raw[i]]);i+=1
                else:out.append(c)
            guards.require(closed,'Truncated SQL string');value=bytes(out)
        else:
            start=i
            while i<n and raw[i]!=44:i+=1
            item=raw[start:i].strip()
            if item==b'NULL':value=None
            elif re.fullmatch(rb'0x(?:[a-fA-F0-9]{2})+',item):value=bytes.fromhex(item[2:].decode())
            else:
                guards.require(re.fullmatch(rb'-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',item),'Unsupported SQL value');value=item
        result.append(value)
        while i<n and raw[i] in b' \t':i+=1
        if i<n:guards.require(raw[i]==44 and i+1<n,'Malformed SQL separator');i+=1
    guards.require(result,'Empty SQL row');return result

def records(data):
    guards.require(isinstance(data,bytes) and len(data)<=256*1024*1024,'Dump oversized')
    catalog={};active=None;posts=[];meta=[];texts=[]
    for line in data.splitlines():
        if line.startswith(b'CREATE TABLE '):
            m=re.fullmatch(rb'CREATE TABLE `([A-Za-z0-9_]+)` \(',line);guards.require(m and active is None,'Unknown table DDL');active=m[1].decode();guards.require(active not in catalog,'Duplicate table');catalog[active]=[]
        elif active:
            if line.startswith(b') ENGINE='):
                guards.require(line.startswith(b') ENGINE=InnoDB ') and catalog[active],'Nontransactional or unknown table');active=None
            elif line.startswith(b'  `'):
                m=re.match(rb'  `([A-Za-z0-9_]+)` ',line);guards.require(m,'Unknown column');name=m[1].decode();guards.require(name not in catalog[active],'Duplicate column');catalog[active].append(name)
        elif line.startswith((b'INSERT ',b'REPLACE ')):
            m=re.fullmatch(rb'INSERT INTO `([A-Za-z0-9_]+)` \((.*?)\) VALUES \((.*)\);',line);guards.require(m,'Unsupported dump row')
            table=m[1].decode();guards.require(table in catalog,'Unknown row table')
            columns=re.findall(rb'`([A-Za-z0-9_]+)`',m[2]);guards.require(b', '.join(b'`'+c+b'`' for c in columns)==m[2] and [c.decode() for c in columns]==catalog[table],'Incomplete or reordered columns')
            rowvalues=values(m[3]);guards.require(len(rowvalues)==len(columns),'Row field count mismatch');row=dict(zip((c.decode() for c in columns),rowvalues))
            def text(key):
                guards.require(isinstance(row.get(key),bytes),'Required media field null')
                try:return row[key].decode('utf8')
                except UnicodeError:raise guards.GuardError('Invalid media UTF8')
            if table=='wp_posts':posts.append({'ID':text('ID'),'post_type':text('post_type')})
            if table=='wp_postmeta' and row.get('meta_key') in (b'_wp_attached_file',b'_wp_attachment_metadata',b'_wp_attachment_backup_sizes',b'_thumbnail_id',b'_product_image_gallery'):
                meta.append({key:text(key) for key in ('post_id','meta_key','meta_value')})
            for value in rowvalues:
                if isinstance(value,bytes) and b'uploads' in value:
                    try:texts.append(value.decode('utf8'))
                    except UnicodeError:raise guards.GuardError('Unsupported binary uploads reference')
            if table=='wp_options' and row.get('option_name') in (b'upload_path',b'upload_url_path'):
                value=text('option_value');guards.require(value=='' or (row['option_name']==b'upload_path' and value=='wp-content/uploads'),'Nonstandard uploads root')
    guards.require(active is None and all(x in catalog for x in ('wp_posts','wp_postmeta','wp_options')),'Incomplete dump catalog')
    return {'posts':posts,'meta':meta,'texts':texts,'tables':len(catalog),'catalog':catalog}
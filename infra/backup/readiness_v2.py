"""Fixed native-v2 readiness from protected producers, never caller PASS flags.

The four current recovery receipts keep their exact native cohort/origin checks.
The original commissioning forecast keeps its own cost configuration and expiry;
a protected monitor observation independently proves current visible workload.
Call revalidate_budget before each effect phase. It performs no S3/network I/O.
"""
import budget, guards, retention_apply, retention_native, runtime, storage
from worker import private_path, protected_directory, sha

CURRENT_PROOFS=frozenset(('audit','anchor','tip','owner'))


def _live(worker, report, at):
    observation=storage.load_live_observation(worker,report)
    budget.commissioning_live_applicable(report,observation,now=at)

def _integrity(worker,evidence,at):
    import integrity
    for name,field in (('audit','check_mode'),('owner','integrity_check_mode')):
        document=evidence[name]['document']
        if document.get(field)==integrity.MODE:integrity.revalidate(worker,document['full_remote_integrity'],at=at)


def load_evidence(worker, inventory, *, at):
    """Load the fixed v2 producer set; the caller selects native-v2 explicitly."""
    try:
        retention_apply._time(at)
        guards.require(inventory['generation']==worker.c['generation'] and
                       all(m['source']==worker.source for m in inventory['manifests'].values()),
                       'Native-v2 inventory source differs')
        result={};directory=protected_directory(worker.root/'receipts/retention-proofs')
        for name in sorted(CURRENT_PROOFS):
            path=private_path(worker.root/'receipts'/retention_native.RECEIPTS[name])
            raw=path.read_bytes();document=runtime.load_json(path)
            origin=runtime.load_json(private_path(directory/(name+'.origin.json')))
            retention_native.verify_origin(name,raw,document,origin,worker.c['code_sha'],inventory)
            guards.require(origin.get('producer_sha256')==sha(private_path(worker.bin/retention_native.producer_for(name,document))),
                           'Installed native-v2 recovery producer differs')
            result[name]={'document':document,'sha256':retention_apply.document_digest(document)}
        report=budget.load_commissioning_budget(worker,now=at)
        _live(worker,report,at)
        _integrity(worker,result,at)
        result['budget']={'document':report,'sha256':retention_apply.document_digest(report)}
        return result
    except (OSError,KeyError,TypeError,ValueError) as error:
        raise guards.GuardError('Protected native-v2 readiness unavailable or changed') from error


def revalidate_budget(worker, evidence, *, at):
    """Recheck config/expiry/live observation and the exact frozen forecast hash."""
    try:
        retention_apply._time(at)
        guards.require(set(evidence)==retention_apply.NATIVE_V2_EVIDENCE_TYPES,'Complete native-v2 proofs required')
        report=budget.load_commissioning_budget(worker,now=at)
        item=evidence['budget'];expected=retention_apply.document_digest(report)
        guards.require(item['sha256']==expected and retention_apply.document_digest(item['document'])==expected,
                       'Commissioning forecast changed after plan')
        _live(worker,report,at)
        _integrity(worker,evidence,at)
        return True
    except (OSError,KeyError,TypeError,ValueError) as error:
        raise guards.GuardError('Native-v2 budget no longer applicable') from error

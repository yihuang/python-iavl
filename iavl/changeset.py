from cprotobuf import Field, ProtoEntity

from .diff import ChangeSet




def write_changeset(fp, version: int, changeset: ChangeSet):
    """
    file format:

    version: int32
    count: int32
    kvpairs: length prefix protobuf message
    """
    fp.write(version.to_bytes("4", "little"))
    fp.write(len(changeset).to_bytes("4", "little"))

    pair = KVPair()
    for item in changeset:

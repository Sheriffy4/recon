from enum import Enum
from typing import Dict, Any

class TechniqueType(Enum):
    FAKEDDISORDER = "fakeddisorder"
    MULTISPLIT = "multisplit"
    SEQOVL = "seqovl"
    BADSUM_RACE = "badsum_race"
    MD5SIG_RACE = "md5sig_race"
    FAKE = "fake"
    TLSREC_SPLIT = "tlsrec_split"
    WSSIZE_LIMIT = "wssize_limit"

TechniqueParams = Dict[str, Any]

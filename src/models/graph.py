from py2neo import Graph, Node, Relationship
from py2neo.ogm import Model, Property, RelatedFrom, RelatedTo, Repository

import models.conf

def connect(db=None):
    config = models.conf.get()
    auth_str = config['services']['neo4j']['environment']['NEO4J_AUTH']
    graph = Graph(models.conf.neo_url, auth=tuple(auth_str.split('/')), name=db)
    repo = Repository(models.conf.neo_url, auth=tuple(auth_str.split('/')), name=db)
    return graph, repo

DATA_DEP = Relationship.type("DATA_DEP")
CTRL_DEP = Relationship.type("CTRL_DEP")
CONTAIN = Relationship.type("CONTAIN")
COME_FROM = Relationship.type("COME_FROM")
CALLBACK = Relationship.type("CALLBACK")
POINT_TO = Relationship.type("POINT_TO")
REFER_TO = Relationship.type("REFER_TO")
CALL_TO = Relationship.type("CALL_TO")
USE = Relationship.type("USE")
USED_BY = Relationship.type("USED_BY")

class Operand(Model):
    binary = Property()
    func = Property()


class Statement(Model):
    __primarylabel__ = "Statement"
    __primarykey__ = "location"

    cate = Property()
    location = Property()
    func = Property()
    binary = Property()
    block = Property()
    preds = RelatedTo("Statement", "PREV")
    succs = RelatedTo("Statement", "NEXT")


class Func(Model):
    __primarylabel__ = "Function"
    __primarykey__ = "name"

    name = Property()
    binary = Property()
    summary = Property()
    argidx_size = Property()
    retvaridx = Property()
    entry_ea = Property()

    start = RelatedTo(Operand, 'START')


class gEnd(Statement):
    __primarylabel__ = "Statement"


class gAssign(Statement):
    __primarylabel__ = "Statement"

    source = RelatedTo(Operand, "ASSIGN_FROM")
    dest = RelatedTo(Operand, "ASSIGN_TO")


class gRet(Operand):
    __primarykey__ = "callsite"

    callsite = Property()
    ret_type = Property()
    call_name = Property()
    deps = RelatedFrom(Operand, "DEP_ON")


class gClazz(Operand):
    __primarykey__ = "name"
    
    name = Property()


class gMsg(Statement):
    __primarylabel__ = "Statement"

    name = Property()
    recv_type = Property()
    ret_type = Property()
    clazz = Property()
    selector = Property()

    callee = RelatedTo(Func, "CALL_TO")
    recv = RelatedTo(Operand, "RECEIVER")
    args = RelatedTo(Operand, "USE")
    ret = RelatedTo(gRet, "RET")


class gCall(Statement):
    __primarylabel__ = "Statement"

    name = Property()
    ret_type = Property()

    callee = RelatedTo(Func, "CALL_TO")
    args = RelatedTo(Operand, "USE")
    ret = RelatedTo(gRet, "RET")


class gJmp(Statement):
    __primarylabel__ = "Statement"
    
    dest = Property()
    is_goto = Property()
    func_dep = Property()   # Just an tmp list used to point to gRet

    jmp_to = RelatedTo(Statement, "JUMP_TO")
    conditions = RelatedTo(Operand, "DEP_ON")


class gArith(Statement):
    __primarylabel__ = "Statement"
    
    tp = Property() # Support +,-,*; TODO:more

    source = RelatedTo(Operand, "ASSIGN_FROM")
    dest = RelatedTo(Operand, "ASSIGN_TO")


class gUnhandled(Statement):
    __primarylabel__ = "Statement"

    raw = Property()


class gLocalVar(Operand):
    __primarykey__ = "vid"

    vid = Property()
    name = Property()
    local_type = Property()
    alias = RelatedTo(Operand, "POINT_TO")


# Also has "CONTAIN" relations like stkblk
class gMemObj(Operand):
    __primarykey__ = "vid"

    vid = Property()
    local_type = Property()
    base = RelatedTo(Operand, "REFER_TO")
    off = RelatedTo(Operand, "Offset_Of")


class gStkBlk(Operand):
    __primarykey__ = "layout"

    layout = Property()
    
    lvars = RelatedTo(Operand, "CONTAIN")


class gBlkRef(Operand):
    __primarykey__ = "loc"
    
    loc = Property() # function name + stkoff of the struct
    flags = Property()
    size = Property()
    value = RelatedTo(Operand, "BYREF")

class gConst(Operand):
    __primarykey__ = "value" # {fname}${value}

    value = Property()


class gGlobalLiteral(Operand):
    __primarykey__ = "ea"

    ea = Property()
    name = Property()
    value = Property() # such as string value
    
    
class gSelector(Operand):
    __primarykey__ = "value"
    
    value = Property() # the select string


class gTmp(Operand):
    __primarykey__ = "loc" # the location where the tmp value is defined
    
    loc = Property()


cate2model = {
    'MsgSend':      gMsg,
    'Assignment':   gAssign,
    'Arithmetic':   gArith,
    'Call':         gCall,
    'Jump':         gJmp,
    'End':          gEnd
}
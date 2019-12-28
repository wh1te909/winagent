from peewee import *

db = SqliteDatabase("C:\\Program Files\\TacticalAgent\\winagent\\agentdb.db")


class AgentStorage(Model):
    server = CharField()
    agentid = CharField()
    client = CharField()
    site = CharField()
    agent_type = CharField()
    description = CharField()
    mesh_node_id = CharField()
    token = CharField()
    version = CharField()

    class Meta:
        database = db

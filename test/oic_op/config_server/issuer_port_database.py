import os
import os.path
from sqlite3 import dbapi2 as sqlite
import UserDict
import sys


class MySqllite3Dict(UserDict.DictMixin):
    def __init__(self, dict_path):
        self.dict_path = dict_path

    def connect(self):
        con = None
        if not os.path.isfile(self.dict_path):
            con = sqlite.connect(self.dict_path)
            con.execute("create table data (key PRIMARY KEY,value)")
        else:
            con = sqlite.connect(self.dict_path)
        return con

    def __getitem__(self, key):
        con = self.connect()
        row = con.execute("select value from data where key=?", (key,)).fetchone()
        if not row:
            raise KeyError
        item = row[0]
        con.close()
        return item

    def __setitem__(self, key, item):
        con = self.connect()
        if con.execute("select key from data where key=?", (key,)).fetchone():
            con.execute("update data set value=? where key=?", (item, key))
        else:
            con.execute("insert into data (key,value) values (?,?)", (key, item))
        con.commit()
        con.close()

    def __delitem__(self, key):
        con = self.connect()
        if con.execute("select key from data where key=?", (key,)).fetchone():
            con.execute("delete from data where key=?", (key,))
            con.commit()
        else:
            con.close()
            raise KeyError
        con.close()

    def keys(self):
        con = self.connect()
        keys = [row[0] for row in con.execute("select key from data").fetchall()]
        con.close()
        return keys

    def values(self):
        con = self.connect()
        values = [row[0] for row in con.execute("select value from data").fetchall()]
        con.close()
        return values

    def clear_database(self):
        con = self.connect()
        con.execute("delete from data")
        con.commit()
        con.close()



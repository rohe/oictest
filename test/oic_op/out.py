["Traceback (most recent call last):\n",
 "  File \"/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/oictest-0.0.1-py2.7.egg/oictest/base.py\", line 289, in run_sequence\n    content, trace, location=url)\n"
    ,
 "  File \"/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/oictest-0.0.1-py2.7.egg/oictest/base.py\", line 128, in do_operation\n    url, response, content = func(client, response, content, **_args)\n"
    ,
 "  File \"/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/oictest-0.0.1-py2.7.egg/oictest/opfunc.py\", line 248, in select_form\n    form = pick_form(response, content, _url, **kwargs)\n"
    ,
 "  File \"/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/oictest-0.0.1-py2.7.egg/oictest/opfunc.py\", line 130, in pick_form\n    forms = ParseResponse(response)\n"
    ,
 "  File \"build/bdist.macosx-10.6-intel/egg/mechanize/_form.py\", line 945, in ParseResponse\n    return _ParseFileEx(response, response.geturl(), *args, **kwds)[1:]\n"
    ,
 "  File \"build/bdist.macosx-10.6-intel/egg/mechanize/_form.py\", line 981, in _ParseFileEx\n    fp.feed(data)\n"
    ,
 "  File \"build/bdist.macosx-10.6-intel/egg/mechanize/_form.py\", line 758, in feed\n    _sgmllib_copy.SGMLParser.feed(self, data)\n"
    ,
 "  File \"build/bdist.macosx-10.6-intel/egg/mechanize/_sgmllib_copy.py\", line 109, in feed\n    self.rawdata = self.rawdata + data\n"
    , "TypeError: cannot concatenate 'str' and 'NoneType' objects\n"]
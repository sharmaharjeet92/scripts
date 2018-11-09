from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort
import os
from collections import OrderedDict
import requests

app = Flask(__name__)


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('bla.html')
    else:
        return "Hello Harjeet"

@app.route('/out', methods=['POST'])
def do_admin_login():
    Host = request.form['path']
    meth=request.form['m']
    H1 = request.form['h1']
    H2 = request.form['h2']
    H3 = request.form['h3']
    H4 = request.form['h4']
    H5 = request.form['h5']
    H6 = request.form['h6']
    H7 = request.form['h7']
    data = request.form['d']

    session = requests.Session()
    if len(H1) > 0:
        var1 = H1.split(': ')
        k1 = var1[0]
        v1 = var1[1]
        session.headers = OrderedDict([(k1, v1), ])

    else:
        pass

    if len(H2) > 0:
        var2 = H2.split(': ')
        k2 = var2[0]
        v2 = var2[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2), ])

    else:
        pass

    if len(H3) > 0:
        var3 = H3.split(': ')
        k3 = var3[0]
        v3 = var3[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2),(k3, v3)])

    else:
        pass

    if len(H4) > 0:
        var4 = H4.split(': ')
        k4 = var4[0]
        v4 = var4[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2), (k3, v3),(k4, v4),])

    else:
        pass

    if len(H5) > 0:
        var5 = H5.split(': ')
        k5 = var5[0]
        v5 = var5[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2), (k3, v3), (k4, v4),(k5, v5)])

    else:
        pass

    if len(H6) > 0:
        var6 = H6.split(': ')
        k6 = var6[0]
        v6 = var6[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2), (k3, v3), (k4, v4), (k5, v5),(k6, v6)])

    else:
        pass

    if len(H7) > 0:
        var7 = H7.split(': ')
        k7 = var7[0]
        v7 = var7[1]
        session.headers = OrderedDict([(k1, v1), ])
        custom_headers = OrderedDict([(k2, v2), (k3, v3), (k4, v4), (k5, v5), (k6, v6),(k7, v7)])

    else:
        pass

    if meth == 'GET':
        req = requests.Request('GET',Host, headers=custom_headers)
        prep = session.prepare_request(req)
        resp = session.send(prep)
        return render_template('test.html', val1=resp.status_code,val2=resp.request.headers,val3=resp.headers)

    else:
        req = requests.Request('POST',Host, headers=custom_headers,data=data)
        prep = session.prepare_request(req)
        resp = session.send(prep)
        return render_template('test.html', val1=resp.status_code,val2=resp.request.headers,val3=resp.headers)



if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True, host='127.0.0.1', port=4000)

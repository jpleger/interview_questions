# Original source: https://github.com/videvelopers/Vulnerable-Flask-App/blob/main/vulnerable-flask-app-linux.py
# GPL v3 License

from flask import Flask, jsonify, render_template_string, request, Response, make_response
import subprocess
from werkzeug.datastructures import Headers
from werkzeug.utils import secure_filename
import sqlite3
import os
import tempfile
import logging
import pickle
import base64

# Directory name for script
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# Database path for sqlite3 DB
DB_FILENAME = tempfile.mktemp(suffix=".db", prefix="pyinterview")
# Create a temporary file for the logfile
LOG_FILENAME = tempfile.mktemp(suffix=".log", prefix="pyinterview")

# Instantiate the flask app
app = Flask(__name__)

# Start Python Interview App
app.config['UPLOAD_FOLDER']='uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
DEBUG = True

@app.route("/")
def index():
    """Main page, this just returns a list of endpoints."""
    endpoints = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            endpoints.append((rule.rule, app.view_functions[rule.endpoint].__doc__))
    template = '''
    <h1>Endpoints</h1>
    <ul>
    {% for endpoint in endpoints %}
        <li>{{ endpoint[0] }} - {{ endpoint[1] }}</li>
    {% endfor %}
    </ul>
    '''

    return render_template_string(template, endpoints=endpoints)

@app.route('/initdb')
def initdb():
    """Initialize the database"""
    con = sqlite3.connect(DB_FILENAME)
    cur = con.cursor()
    cur.execute("create table users (username text, password text, admin integer)")
    con.commit()
    con.close()
    return jsonify(data="Database initialized"), 200


@app.route('/ping')
def ping():
    """Simple health check endpoint, take the hostname from the request and ping it"""
    server_name = request.base_url.split(':')[1]
    server_name = server_name.replace("//", "")
    command = 'ping -c 2 %s' % server_name
    ping_result = subprocess.run(command, shell=True, capture_output=True).stdout.decode('utf-8')
    return jsonify(command=command, data=ping_result), 200


@app.route('/users/')
def get_users():
    """Return list of all users"""
    con = sqlite3.connect(DB_FILENAME)
    cur = con.cursor()
    cur.execute("select username from users")
    data = str(cur.fetchall())
    logging.debug(data)
    con.close()
    return jsonify(data=data), 200

@app.route('/user/<string:name>')
def get_user(name=None):
    """Return user details"""
    con = sqlite3.connect(DB_FILENAME)
    cur = con.cursor()
    cur.execute("select * from users where username = '%s'" % name)
    data = str(cur.fetchall())
    logging.debug(data)
    con.close()
    return jsonify(data=data), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = request.form.get('admin')
        con = sqlite3.connect(DB_FILENAME)
        cur = con.cursor()
        cur.execute("insert into users (username, password, admin) values ('%s', '%s', '%s')" % (username, password, admin))
        con.commit()
        con.close()
        return jsonify(data="User added"), 200
    else:
        return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="text" name="admin" hidden value="0">
            <input type="submit">
        </form>
        '''

@app.route("/welcome_admin/<string:name>")
def welcome(name):
    """Used to welcome new admin users, via email"""
    data="Welcome " + name
    return data, 200


@app.route("/welcome_user")
def welcome_user():
    """Used to welcome new users, via email"""
    if request.args.get('name'):
        name = request.args.get('name')
        template = f'''<div>
        <h1>Hello</h1>
        {name} to the awesome site!
</div>
'''
        import logging
        logging.basicConfig(filename=LOG_FILENAME, filemode='w', level=logging.DEBUG)
        logging.debug(str(template))
        return render_template_string(template)

@app.route("/get_log/")
def get_log():
    try:
        command = "cat restapi.log"
        data = subprocess.check_output(command, shell=True)
        return data
    except:
        return jsonify(data="Command didn't run"), 200


@app.route("/read_file")
def read_file():
    filename = request.args.get('filename')
    file = open(filename, "r")
    data = file.read()
    file.close()
    import logging
    logging.basicConfig(filename=LOG_FILENAME, filemode='w', level=logging.DEBUG)
    logging.debug(str(data))
    return jsonify(data=data),200

@app.route("/deserialization/")
def deserialization():
    try:
        import socket, pickle
        HOST = "0.0.0.0"
        PORT = 8001
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            connection, address = s.accept()
            with connection:
                received_data = connection.recv(1024)
                data=pickle.loads(received_data)
                return str(data)
    except:
        return jsonify(data="You must connect 8001 port"), 200


@app.route("/get_admin_mail/<string:control>")
def get_admin_mail(control):
    if control=="admin":
        data="admin@cybersecurity.intra"
        import logging
        logging.basicConfig(filename=LOG_FILENAME, filemode='w', level=logging.DEBUG)
        logging.debug(data)
        return jsonify(data=data),200
    else:
        return jsonify(data="Control didn't set admin"), 200

@app.route("/run_file")
def run_file():
    try:
        filename=request.args.get("filename")
        command="/bin/bash "+filename
        data=subprocess.check_output(command,shell=True)
        return data
    except:
        return jsonify(data="File failed to run"), 200

@app.route("/create_file")
def create_file():
    try:
        filename=request.args.get("filename")
        text=request.args.get("text")
        file=open(filename,"w")
        file.write(text)
        file.close()
        return jsonify(data="File created"), 200
    except:
        return jsonify(data="File didn't create"), 200


connection = {}
max_con = 50

def factorial(number):
    if number == 1:
        return 1
    else:
        return number * factorial(number - 1)


@app.route('/factorial/<int:n>')
def factroial(n:int):
    if request.remote_addr in connection:
        if connection[request.remote_addr] > 2:
            return jsonify(data="Too many req."), 403
        connection[request.remote_addr] += 1
    else:
        connection[request.remote_addr] = 1
    result=factorial(n)
    if connection[request.remote_addr] == 1:
        del connection[request.remote_addr]
    else:
        connection[request.remote_addr] -= 1
    return jsonify(data=result), 200

@app.route('/login',methods=["GET", "POST"])
def login():
    """Login endpoint, used to login"""
    username = request.form.get("username")
    password = request.form.get("password")
    con = sqlite3.connect(DB_FILENAME)
    cur = con.cursor()
    if username and password:
        cur.execute("select * from users where username = '%s' and password = '%s'" % (username, password))
        data = cur.fetchall()
        if len(data) == 0:
            response = make_response(render_template_string("Login failed!"))
            response.status_code = 403
            response.set_cookie("login", "false")
            response.set_cookie("username", username)
            return response
        else:
            response = make_response(render_template_string("Login successful"))
            response.set_cookie("login", "true")
            response.set_cookie("username", username)
            return response
    con.close()
    return render_template_string('''<form method="post">
                                  <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <input type="submit">'''), 200


@app.route('/backup_login',methods=["GET"])
def backup_login():
    """Backup login endpoint, used to do admin tasks"""
    username = request.args.get("username")
    password = request.args.get("password")
    if "admin" in username and "Sup3rS3cr3t" in password:
        response = make_response(render_template_string("Login successful"))
        response.set_cookie("admin", "true")
        return response
    else:
        response = make_response(render_template_string("Login Failed"))
        response.set_cookie("admin", "false")
        response.status_code = 403
        return response

@app.route('/change_password',methods=["GET"])
def change_password():
    """Change password endpoint, used to change password"""
    username = request.args["username"]
    old_password = request.args.get("old_password", None)
    new_password = request.args.get("new_password")
    con = sqlite3.connect(DB_FILENAME)
    cur = con.cursor()
    if request.cookies.get("admin") == "true":
        cur.execute("update users set password = '%s' where username = '%s'" % (new_password, username))
        con.commit()
        return jsonify(data="Password changed"), 200
    # Check user/password in database
    cur.execute("select * from users where username = '%s' and password = '%s'" % (username, old_password))
    data = cur.fetchall()
    if len(data) == 0:        
        return jsonify(data="Password change failed"), 403
    cur.execute("update users set password = '%s' where username = '%s'" % (new_password, username))
    con.close()
    return jsonify(data="Password changed"), 200


@app.route('/set_header')
def set_header():
    """Add a custom header to responses, store as a pickled cookie"""
    parsed_headers = {}
    custom_headers = request.cookies.get("custom_headers", '')
    if custom_headers:
        # Decode the headers from the cookie
        parsed_headers = base64.b64decode(custom_headers)
        parsed_headers = pickle.loads(custom_headers)
    header_name = request.args.get("header_name")
    header_value = request.args.get("header_value")
    parsed_headers[header_name] = header_value
    response = make_response(render_template_string("Header set"))
    response.set_cookie("custom_headers", base64.b64encode(pickle.dumps(parsed_headers)))
    response.set_data()
    return response

@app.route('/get_headers')
def get_headers():
    """Get headers from request"""
    parsed_headers = {}
    custom_headers = request.cookies.get("custom_headers", '')
    if custom_headers:
        # Decode the headers from the cookie
        parsed_headers = base64.b64decode(custom_headers)
        parsed_headers = pickle.loads(custom_headers)
    headers = request.headers
    headers = Headers()
    headers.extend(parsed_headers)
    response = make_response(render_template_string("{% for header, value in parsed_headers.items() %}{{ header }}{{ value }}{% endfor %}"))
    response.headers = headers
    return jsonify(data=str(headers)), 200


@app.route('/logs')
def ImproperOutputNeutralizationforLogs():
    data = request.args.get('data')
    import logging
    logging.basicConfig(filename=LOG_FILENAME, filemode='w', level=logging.DEBUG)
    logging.debug(data)
    return jsonify(data="Logging ok"), 200


@app.route("/user_pass_control")
def user_pass_control():
    import re
    username=request.form.get("username")
    password=request.form.get("password")
    if re.search(username,password):
        return jsonify(data="Password include username"), 200
    else:
        return jsonify(data="Password doesn't include username"), 200




@app.route('/upload', methods = ['GET','POST'])
def uploadfile():
   import os
   if request.method == 'POST':
      f = request.files['file']
      filename=secure_filename(f.filename)
      f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
      return 'File uploaded successfully'
   else:
      return '''
<html>
   <body>
      <form  method = "POST"  enctype = "multipart/form-data">
         <input type = "file" name = "file" />
         <input type = "submit"/>
      </form>   
   </body>
</html>


      '''

def main():
    app.run(host="127.0.0.1", port=8081, debug=DEBUG)


if __name__ == '__main__':
    main()

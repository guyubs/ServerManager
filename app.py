import json
import paramiko
import pyodbc
import random
import socket
import os
import win32api
import win32con

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from datetime import datetime
from flask_caching import Cache

app = Flask(__name__)
app.secret_key = "secret key"  # 设置 secret key 以启用 flash 消息

ssh_conn = None
connected_clients = []

global connected_servers
global failed_servers

############
# 数据库配置
############
# Connect to SQL Server Express using Windows authentication
server = 'localhost'
database = 'ServerManager'
conn = pyodbc.connect('Driver={SQL Server};Server=' + server + ';Database=' + database + ';Trusted_Connection=yes;')

# 读取数据库信息
cursor = conn.cursor()

# 检查数据库中是否存在users表。若没有则创建。
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='users'")
if not cursor.fetchone():
    cursor.execute("CREATE TABLE users "
                   "(id int PRIMARY KEY IDENTITY(1,1), "
                   "username varchar(255), "
                   "password varchar(255), "
                   "email varchar(255))")
    conn.commit()

# 检查数据库中是否存在 ServerInfo 表。若没有则创建。
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='ServerInfo'")
if not cursor.fetchone():
    cursor.execute("CREATE TABLE ServerInfo "
                   "(id int PRIMARY KEY IDENTITY(1,1), "
                   "hostname varchar(255), "
                   "username varchar(255), "
                   "password varchar(255), "
                   "ip_address varchar(255), "
                   "operating_system varchar(255), "
                   "os_version varchar(255), "
                   "applications text, "
                   "hardware_configuration text, "
                   "security_settings text, "
                   "logs_and_monitoring text, "
                   "backup_and_recovery text, "
                   "note text)")
    conn.commit()

# 检查数据库中是否存在operations表。若没有则创建。
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='operations'")
if not cursor.fetchone():
    cursor.execute("CREATE TABLE operations "
                   "(id int PRIMARY KEY IDENTITY(1,1), "
                   "username varchar(255), "
                   "hostname varchar(255), "
                   "ip_address varchar(255), "
                   "operation text, "
                   "timestamp datetime DEFAULT GETDATE())")
    conn.commit()

# 检查数据库中是否存在files表。若没有则创建。
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='files'")
if not cursor.fetchone():
    cursor.execute("CREATE TABLE files "
                   "(id int PRIMARY KEY IDENTITY(1,1), "
                   "editor varchar(255), "
                   "hostname varchar(255), "
                   "username varchar(255), "
                   "password varchar(255), "
                   "ip_address varchar(255), "
                   "FilePath VARCHAR(255), "
                   "Content NVARCHAR(MAX), "
                   "timestamp datetime DEFAULT GETDATE())")
    conn.commit()


# 检查数据库中是否存在port_forwarding_rules表。若没有则创建。
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='port_forwarding_rules'")
if not cursor.fetchone():
    cursor.execute("CREATE TABLE port_forwarding_rules "
                   "(id int PRIMARY KEY IDENTITY(1,1), "
                   "editor varchar(255), "
                   "hostname varchar(255), "
                   "username varchar(255), "
                   "password varchar(255), "
                   "ip_address varchar(255), "
                   "remote_port varchar(255), "
                   "local_port varchar(255), "
                   "Content NVARCHAR(MAX), "
                   "timestamp datetime DEFAULT GETDATE())")
    conn.commit()

############
# 发送邮件配置
############
email_sender = 'servermanagerapp@gmail.com'
app_pw = 'belglusudxubkhdo'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = email_sender  # 电子邮件地址
app.config['MAIL_PASSWORD'] = app_pw  # 电子邮第三方app件密码，不是电子邮件密码，需要在邮箱设置。
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


# create a function to send verification code email
@app.route('/send_verification_code', methods=['POST'])
def send_verification_code():
    code = str(random.randint(10000, 99999))
    sender = app.config['MAIL_USERNAME']
    recipient = request.form.get('email')
    session['email'] = recipient  # 保存recipient，用户在用户点击注册时校对邮箱是否被修改。
    session['code'] = code
    subject = '您的验证码'
    body = f'您的验证码为: {code}'
    msg = Message(subject=subject, body=body, sender=sender, recipients=[recipient])
    mail.send(msg)
    flash('验证码已发送至您的邮箱。')
    return redirect(url_for('register'))


###################################
# 用户登录，注册，编辑，退出等
###################################
@app.route('/')
def index():
    # 如果已登录，则跳转到 panel 页面
    if 'username' in session:
        return redirect(url_for('panel'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        if user:
            session['username'] = user.username
            return redirect(url_for('panel'))
        # 如果用户不存在或密码错误，则显示错误消息
        flash('用户名或密码错误')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']
        verification_code = request.form["verification_code"]
        # 检查用户名是否已被注册
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            flash('该用户名已被注册')
            return redirect(url_for('register'))
        # 检查邮箱是否已被注册
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        if cursor.fetchone():
            flash('该email已被注册')
            return redirect(url_for('register'))
        # 检查验证码
        if verification_code != session['code']:
            flash('验证码错误')
            return redirect(url_for('register'))
        # 检查验证邮箱和输入邮箱是否相符
        if email != session['email']:
            flash('验证邮箱和注册邮箱不符')
            return redirect(url_for('register'))
        # 检查两次输入的密码是否相同
        if password1 != password2:
            flash('两次输入的密码不一致')
            return redirect(url_for('register'))
        if username == '' or password1 == '' or email == '':
            flash('注册资料不能为空')
            return redirect(url_for('register'))
        # 将新用户信息添加到 users 表
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                       (username, password1, email))
        conn.commit()
        # 注册成功，显示成功消息
        flash('注册成功，请登录')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    # 从会话中删除用户名并返回主页
    session.pop('username', None)
    flash('您已成功退出')
    return redirect(url_for('index'))


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    # 如果未登录，则跳转到登录页面
    if 'username' not in session:
        return redirect(url_for('login'))

    # 获取当前用户的信息
    cursor.execute("SELECT * FROM users WHERE username=?", (session['username'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        # 获取用户提交的表单数据
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']

        # 检查两次输入的密码是否相同
        if password1 != password2:
            flash('两次输入的密码不一致')
            return redirect(url_for('edit'))

        if password1 == '':
            flash('密码不能为空')
            return redirect(url_for('edit'))

        # 检查新email是否已被注册
        cursor.execute("SELECT * FROM users WHERE email=? AND id!=?", (email, user.id))
        if cursor.fetchone():
            flash('该email已被注册')
            return redirect(url_for('edit'))

        # 更新用户信息
        cursor.execute("UPDATE users SET password=?, email=? WHERE id=?", (password1, email, user.id))
        conn.commit()

        # 更新 session 中的用户信息
        session['email'] = email

        # 显示成功消息
        flash('用户信息已更新')
        return redirect(url_for('panel'))

    # 渲染 edit.html 页面，并传递当前用户的信息
    return render_template('edit.html', user=user)


###################################
# 登录后的Panel
###################################
@app.route('/panel')
def panel():
    # 如果未登录，则跳转到登录页面
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('panel.html', username=session['username'])


###################################
# 服务器管理界面。
###################################
@app.route('/manage_server', methods=['GET', 'POST'])
def manage_server():
    cursor = conn.cursor()

    # 获取 ServerInfo 表中的所有数据
    cursor.execute("SELECT * FROM ServerInfo")
    data = cursor.fetchall()

    return render_template('manage_server.html', data=data)


###################################
# 编辑服务器信息
###################################
@app.route('/add_server', methods=['GET', 'POST'])
def add_server():
    cursor = conn.cursor()

    if request.method == 'POST':
        # 获取 POST 请求中的表单数据
        hostname = request.form['hostname']
        username = request.form['username']
        password = request.form['password']
        ip_address = request.form['ip_address']
        operating_system = request.form['operating_system']
        os_version = request.form['os_version']
        applications = request.form['applications']
        hardware_configuration = request.form['hardware_configuration']
        security_settings = request.form['security_settings']
        logs_and_monitoring = request.form['logs_and_monitoring']
        backup_and_recovery = request.form['backup_and_recovery']
        note = request.form['note']

        # 将数据插入到 ServerInfo 表中
        cursor.execute("INSERT INTO ServerInfo (hostname, username, password, ip_address, "
                       "operating_system, os_version, applications, hardware_configuration, "
                       "security_settings, logs_and_monitoring, backup_and_recovery, note) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (hostname, username, password, ip_address, operating_system, os_version,
                        applications, hardware_configuration, security_settings,
                        logs_and_monitoring, backup_and_recovery, note))
        conn.commit()

        # 显示成功消息
        flash('服务器已添加！')

    return render_template('add_server.html')


@app.route('/server_delete/<int:server_id>', methods=['POST'])
def server_delete(server_id):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ServerInfo WHERE id=?", (server_id,))
    conn.commit()
    flash('服务器已删除！')
    return redirect(url_for('manage_server'))


@app.route('/server_edit/<int:id>', methods=['GET', 'POST'])
def server_edit(id):
    cursor = conn.cursor()

    # 查询指定id的服务器信息
    cursor.execute("SELECT * FROM ServerInfo WHERE id=?", (id,))
    server = cursor.fetchone()

    if request.method == 'POST':
        # 获取 POST 请求中的表单数据
        hostname = request.form['hostname']
        username = request.form['username']
        password = request.form['password']
        ip_address = request.form['ip_address']
        operating_system = request.form['operating_system']
        os_version = request.form['os_version']
        applications = request.form['applications']
        hardware_configuration = request.form['hardware_configuration']
        security_settings = request.form['security_settings']
        logs_and_monitoring = request.form['logs_and_monitoring']
        backup_and_recovery = request.form['backup_and_recovery']
        note = request.form['note']

        # 更新数据库中指定id的服务器信息
        cursor.execute("UPDATE ServerInfo SET hostname=?, username=?, password=?, ip_address=?, "
                       "operating_system=?, os_version=?, applications=?, hardware_configuration=?, "
                       "security_settings=?, logs_and_monitoring=?, backup_and_recovery=?, note=? "
                       "WHERE id=?",
                       (hostname, username, password, ip_address, operating_system, os_version,
                        applications, hardware_configuration, security_settings,
                        logs_and_monitoring, backup_and_recovery, note, id))
        conn.commit()

        # 显示成功消息
        flash('服务器信息已修改！')
        return redirect(url_for('manage_server'))

    # 显示编辑服务器信息的表单
    return render_template('server_edit.html', data=server)


###################################
# 单个操作服务器
###################################
@app.route('/server_connect/<int:server_id>', methods=['POST', 'GET'])
def server_connect(server_id):
    global ssh_conn

    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.form.get('ip_address')

    # 连接服务器
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip_address, username=username, password=password)
    except paramiko.AuthenticationException:
        return "Authentication failed, please verify your credentials"
    except paramiko.SSHException as sshException:
        return "Unable to establish SSH connection: %s" % sshException
    except paramiko.Exception as e:
        return "Exception in connecting to the server %s" % e

    ssh_conn = ssh

    return render_template('server_connect.html')


@app.route('/execute', methods=['POST'])
def execute():
    global ssh_conn

    command = request.form['command']

    if not command:
        result = '请输入要执行的命令。'
    else:
        if ssh_conn:
            stdin, stdout, stderr = ssh_conn.exec_command(command)
            result = stdout.read().decode('utf-8')
        else:
            result = '当前没有任何连接。'

    return render_template('server_connect.html', result=result)


@app.route('/disconnect', methods=['POST'])
def disconnect():
    global ssh_conn

    if ssh_conn:
        ssh_conn.close()
        ssh_conn = None
        result = "连接已断开。"
    else:
        result = '当前没有任何连接。'

    return render_template('server_connect.html', result=result)


###################################
# 批量操作服务器
###################################
@app.route('/batch_operation', methods=['POST'])
def batch_operation():  # 连接服务器
    global connected_servers
    global failed_servers

    servers = request.form.get('servers')

    if not servers:
        flash('请选择要操作的服务器。')
        return redirect(url_for('index'))

    server_data = json.loads(servers)
    connected_servers = []
    failed_servers = []

    for server in server_data:
        username = server['username']
        password = server['password']
        ip_address = server['ip_address']
        hostname = server['hostname']

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip_address, username=username, password=password)
            connected_servers.append(
                {'hostname': hostname, 'username': username, 'password': password, 'ip_address': ip_address})
            connected_clients.append(ssh)  # 将SSHClient对象添加到全局列表中

        except Exception as e:
            failed_servers.append({'server': server, 'error': str(e)})

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers)


@app.route('/disconnect_servers', methods=['POST'])
def disconnect_servers():
    global connected_servers
    global failed_servers

    connected_servers = []
    failed_servers = []

    global connected_clients
    if connected_clients:
        for ssh in connected_clients:
            ssh.close()
        connected_clients.clear()
        result = "连接已断开。"
    else:
        result = '当前没有任何连接。'
    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


def save_operation(command, hostname, ip_address):
    # 将用户操作添加到 operations 表
    timestamp = datetime.now()  # 获取当前日期和时间
    cursor.execute(
        "INSERT INTO operations (username, hostname, ip_address, operation, timestamp) VALUES (?, ?, ?, ?, ?)",
        (session['username'], hostname, ip_address, command, timestamp))
    conn.commit()


@app.route('/batch_execute', methods=['POST'])
def batch_execute():
    global connected_servers
    global failed_servers

    command = request.form.get('command')
    result = ''

    if not command:
        result = '请输入要执行的命令。'

    else:
        for ssh in connected_clients:
            try:
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                if output:
                    result += f"{output}\n"

                    # 获取远程主机的IP地址和端口号
                    ip, port = ssh.get_transport().getpeername()

                    # 根据IP地址反向查找主机名
                    hostname = socket.gethostbyaddr(ip)[0]

                    # 将用户操作添加到 operations 表
                    save_operation(command, hostname, ip)

                if error:
                    result += f"{error}\n"
            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


# 查询目录
@app.route('/batch_show_directory_files', methods=['POST'])
def batch_show_directory_files():
    global connected_servers
    global failed_servers

    remote_dir_path = request.form['remote_dir_path']
    result = ''

    if not remote_dir_path:
        result = '请输入目标文件夹地址。'
    else:
        for ssh in connected_clients:
            try:
                # 使用SFTP列出远程计算机上指定目录的文件和子目录
                sftp = ssh.open_sftp()
                files = sftp.listdir(remote_dir_path)

                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()

                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]

                # 将用户操作添加到 operations 表
                save_operation(remote_dir_path, hostname, ip)

                sftp.close()

                result += f"{ssh.get_transport().getpeername()[0]} 上的文件和文件夹：\n"

                for file in files:
                    result += f"{file}\n"
                result += '\n\n'  # 添加空行

            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


# 批量下载
@app.route('/batch_download', methods=['POST'])
def batch_download():
    global connected_servers
    global failed_servers

    remote_file_path = request.form['remote_file_path']
    local_file_path = request.form['local_file_path']
    result = ''

    if not remote_file_path or not local_file_path:
        result = '请输入目标文件地址和本地保存地址。'

    else:
        for ssh in connected_clients:
            try:
                # 获取主机名前缀
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.read().decode().strip()

                # 获取本地文件名和目录
                local_dir = os.path.dirname(local_file_path)
                local_filename = os.path.basename(local_file_path)

                # 在本地文件名之前添加主机名前缀
                local_file_path_with_hostname = os.path.join(local_dir, f"{hostname}_{local_filename}")

                # 使用SFTP从远程计算机下载文件
                sftp = ssh.open_sftp()
                sftp.get(remote_file_path, local_file_path_with_hostname)

                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()
                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]
                command = 'Download from ' + remote_file_path + ' to ' + local_file_path
                # 将用户操作添加到 operations 表
                save_operation(command, hostname, ip)

                sftp.close()
                result = "下载成功！"
            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


@app.route('/batch_upload', methods=['POST'])
def batch_upload():
    global connected_clients
    global failed_servers

    local_file_path = request.form['local_file_path']
    remote_file_path = request.form['remote_file_path']
    overwrite = request.form.get('overwrite')
    result = ''

    if not local_file_path or not remote_file_path:
        result = '请输入本地文件地址和目标文件夹地址。'

    else:
        for ssh in connected_clients:
            try:
                # 使用SFTP上传文件到远程计算机
                sftp = ssh.open_sftp()
                try:
                    sftp.stat(remote_file_path)

                    if overwrite is None:

                        # 获取远程主机的IP地址和端口号
                        ip, port = ssh.get_transport().getpeername()
                        # 根据IP地址反向查找主机名
                        hostname = socket.gethostbyaddr(ip)[0]
                        command = 'Upload from ' + local_file_path + ' to ' + remote_file_path
                        # 将用户操作添加到 operations 表
                        save_operation(command, hostname, ip)

                        return render_template('confirm_overwrite.html', local_file_path=local_file_path,
                                               remote_file_path=remote_file_path)
                    elif overwrite == 'no':
                        result = '上传已取消。'
                        break
                    else:
                        pass
                except IOError:
                    pass
                sftp.put(local_file_path, remote_file_path)
                sftp.close()
                result += f"{ssh.get_transport().getpeername()[0]} 上传成功！\n"

            except Exception as e:
                result += f"{ssh.get_transport().getpeername()[0]} 执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


###################################
# 缓存
###################################
cache = Cache(app, config={'CACHE_TYPE': 'simple'})


###################################
# 操作记录。
###################################
@app.route('/delete_operation', methods=['POST'])
def delete_operation():
    operations_id = request.form.get('operations')
    if operations_id == '[]':
        flash('请选择要删除的记录。')
        return redirect(url_for('manage_operation'))
    operations_id_list = json.loads(operations_id)
    for operation_id in operations_id_list:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM operations WHERE id=?", (operation_id,))
            conn.commit()
            flash(f'记录{operation_id}已删除！')
        except Exception as e:
            flash(f'记录{operation_id}删除失败！')
    return redirect(url_for('manage_operation'))


@cache.cached(timeout=300, key_prefix='manage_operation')
@app.route('/manage_operation', methods=['GET', 'POST'])
def manage_operation():
    # 检查缓存中是否已经有数据
    cached_data = cache.get('manage_operation')
    if cached_data is not None:
        print("从缓存中检索到数据。")
        data = cached_data
    else:
        # 连接数据库
        cursor = conn.cursor()

        # 获取 ServerInfo 表中的所有数据
        cursor.execute("SELECT * FROM operations")
        data = cursor.fetchall()

        # 缓存数据以供未来的请求
        cache.set('manage_operation', data, timeout=300)

    # 分页
    page = int(request.args.get('page', 1))  # 获取当前页码，默认为第一页
    current_data, pagination = paginate(data, page)

    return render_template('manage_operation.html', data=current_data, pagination=pagination)


###################################
# 搜索操作记录数据库。
###################################
@cache.cached(timeout=300, key_prefix='search')
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        column = request.form.get('db_column')
        keyword = request.form.get('db_keyword')
        if column and keyword:
            # 尝试从缓存中获取数据
            cache_key = f"search:{column}:{keyword}"
            cached_data = cache.get(cache_key)
            if cached_data is not None:
                print("从缓存中检索到数据。")
                return cached_data

            data = search_db(column, keyword)

            # 分页
            page = int(request.args.get('page', 1))  # 获取当前页码，默认为第一页
            current_data, pagination = paginate(data, page)

            # 将查询结果缓存起来
            cache.set(cache_key, render_template('manage_operation.html', data=current_data, pagination=pagination),
                      timeout=300)

            return render_template('manage_operation.html', data=current_data, pagination=pagination)

    return render_template('manage_operation.html')


# 分页
def paginate(data, page, per_page=25):
    data_count = len(data)  # 数据总量
    page_count = (data_count - 1) // per_page + 1  # 总页数
    start = (page - 1) * per_page  # 当前页数据起始下标
    end = start + per_page  # 当前页数据终止下标

    # 获取当前页的数据
    current_data = data[start:end]

    pagination = {
        'page': page,
        'per_page': per_page,
        'data_count': data_count,
        'page_count': page_count,
        'start': start,
        'end': end
    }

    return current_data, pagination


# 定义数据库操作函数
def search_db(column, keyword):
    cursor = conn.cursor()
    if column == 'timestamp':  # 如果搜索的是时间列
        sql = "SELECT * FROM operations WHERE CONVERT(varchar(100), timestamp, 120) LIKE ?"
    else:  # 否则搜索其他列
        sql = "SELECT * FROM operations WHERE {} LIKE ?".format(column)
    value = ("%" + keyword + "%",)
    cursor.execute(sql, value)
    result = cursor.fetchall()
    return result


###################################
# 文件编辑。
###################################
# 读取文档文件
@app.route('/read_file', methods=['POST'])
def read_file():
    global connected_servers
    global failed_servers

    file_path = request.form.get('read_file_path')
    result = ''

    if not file_path:
        result = '请输入要执行的命令。'

    else:
        for ssh in connected_clients:
            try:
                sftp = ssh.open_sftp()
                remote_file = sftp.open(file_path, 'r')
                # output = remote_file.read()
                output = remote_file.read().decode('utf-8')

                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"

                if output:
                    result += f"{output}\n"

                    # 获取远程主机的IP地址和端口号
                    ip, port = ssh.get_transport().getpeername()

                    # 根据IP地址反向查找主机名
                    hostname = socket.gethostbyaddr(ip)[0]

                    # 将用户操作添加到 operations 表
                    save_operation('Read' + file_path, hostname, ip)

            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


# 编辑文档文件
@app.route('/edit_file', methods=['POST'])
def edit_file():
    global connected_servers
    global failed_servers

    file_path = request.form.get('edit_file_path')
    new_content = request.form.get('new_file_content')
    result = ''

    if not file_path or not new_content:
        result = '请输入要执行的命令。'

    else:
        for ssh in connected_clients:
            try:
                sftp = ssh.open_sftp()
                remote_file = sftp.open(file_path, 'w')
                remote_file.write(new_content)
                remote_file.close()

                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                result += f"文件 {file_path} 编辑成功！\n"

                # 将新文件的内容存储到 SQL Server 数据库中
                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()
                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]
                # 将用户操作添加到 files 表
                save_file(file_path, new_content, hostname, ip)

                # 将用户操作添加到 operations 表
                command = 'Edit ' + file_path + ': ' + new_content
                save_operation(command, hostname, ip)

            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


# 查看文件编辑历史
@app.route('/file_edit_history', methods=['GET', 'POST'])
def file_edit_history():
    # 连接数据库
    cursor = conn.cursor()

    # 获取 ServerInfo 表中的所有数据
    cursor.execute("SELECT * FROM files")
    data = cursor.fetchall()

    # 分页
    page = int(request.args.get('page', 1))  # 获取当前页码，默认为第一页
    current_data, pagination = paginate(data, page)

    return render_template('file_edit_history.html', data=current_data, pagination=pagination)


# 删除文件编辑记录
@app.route('/delete_file_edit_history', methods=['POST'])
def delete_file_edit_history():
    files_id = request.form.get('files')
    if files_id == '[]':
        flash('请选择要删除的记录。')
        return redirect(url_for('delete_file_edit_history'))
    files_id_list = json.loads(files_id)
    for file_id in files_id_list:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE id=?", (file_id,))
            conn.commit()
            flash(f'记录{file_id}已删除！')
        except Exception as e:
            flash(f'记录{file_id}删除失败！')
    return redirect(url_for('file_edit_history'))


# 储存每一次的修改版本
def save_file(file_path, content, hostname, ip_address):
    timestamp = datetime.now()  # 获取当前日期和时间

    # 查询 ServerInfo 表中的密码
    cursor.execute("SELECT username, password FROM ServerInfo WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    if row is None:
        # 如果没有找到密码，则将密码设置为 None
        password = None
        username = None
    else:
        # 如果找到了密码，则将其赋值给 password 和 username 变量
        username = row[0]
        password = row[1]

    # 插入新记录到 files 表
    cursor.execute(
        "INSERT INTO files (editor, hostname, username, password, ip_address, FilePath, Content, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (session['username'], hostname, username, password, ip_address, file_path, content, timestamp)
    )
    conn.commit()


# 根据列和关键字搜索
@app.route('/search_db_files', methods=['GET', 'POST'])
def search_db_files():
    if request.method == 'POST':
        column = request.form.get('db_column')
        keyword = request.form.get('db_keyword')
        if column and keyword:

            data = search_dbFiles(column, keyword)

            # 分页
            page = int(request.args.get('page', 1))  # 获取当前页码，默认为第一页
            current_data, pagination = paginate(data, page)

            return render_template('file_edit_history.html', data=current_data, pagination=pagination)

    return render_template('file_edit_history.html')


# 根据列和关键字搜索数据库
def search_dbFiles(column, keyword):
    cursor = conn.cursor()
    if column == 'timestamp':  # 如果搜索的是时间列
        sql = "SELECT * FROM files WHERE CONVERT(varchar(100), timestamp, 120) LIKE ?"
    else:  # 否则搜索其他列
        sql = "SELECT * FROM files WHERE {} LIKE ?".format(column)
    value = ("%" + keyword + "%",)
    cursor.execute(sql, value)
    result = cursor.fetchall()
    return result


# 文档回滚
@app.route('/file_rollback', methods=['POST'])
def file_rollback():
    global connected_servers

    servers = request.form.get('files')
    result = ''

    if not servers:
        flash('请选择要操作的服务器。')
        return redirect(url_for('index'))

    server_data = json.loads(servers)

    for server in server_data:
        username = server['username']
        password = server['password']
        ip_address = server['ip_address']
        file_path = server['FilePath']
        new_content = server['Content']

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip_address, username=username, password=password)

            try:
                sftp = ssh.open_sftp()
                remote_file = sftp.open(file_path, 'w')
                remote_file.write(new_content)
                remote_file.close()

                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                result += f"文件 {file_path} 回滚成功！\n"

                # 将新文件的内容存储到 SQL Server 数据库中
                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()
                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]
                # 将用户操作添加到 files 表
                save_file(file_path, new_content, hostname, ip)

                # 将用户操作添加到 operations 表
                command = 'Rollback: ' + file_path + ': ' + new_content
                save_operation(command, hostname, ip)

            except Exception as e:
                result += f"连接服务器成功，回滚出错：{str(e)}\n"

            ssh.close()

        except Exception as e:
            result += f"连接服务器出错：{str(e)}\n"

    # 获取 files 表中的所有数据
    cursor.execute("SELECT * FROM files")
    data = cursor.fetchall()

    # 分页
    page = int(request.args.get('page', 1))  # 获取当前页码，默认为第一页
    current_data, pagination = paginate(data, page)

    return render_template('file_edit_history.html', data=current_data, pagination=pagination, result=result)


##########################
# 防火墙
##########################
# 开关防火墙
@app.route('/firewall', methods=['POST'])
def firewall():
    global connected_servers
    global failed_servers

    result = ''
    action = request.form.get('command')

    if not action:
        result = '请输入要执行的命令。'
    else:
        for ssh in connected_clients:
            try:
                # 在本地计算机上运行 winrs 命令以在远程计算机上以管理员身份运行 PowerShell
                command = ''

                # 构造命令，使用管道输入密码
                if action == 'on':
                    command = 'netsh advfirewall set allprofiles state on'

                elif action == 'off':
                    command = 'netsh advfirewall set allprofiles state off'

                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()

                if action == 'off':
                    # 添加名为"OpenSSH"的防火墙规则，以允许SSH流量通过端口22, 避免关闭防火墙时段时候见SSH连接断开
                    add_rule_cmd = 'netsh advfirewall firewall add rule name="OpenSSH" dir=in action=allow protocol=TCP localport=22'
                    stdin, stdout, stderr = ssh.exec_command(add_rule_cmd)

                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"

                if output:
                    result += f"{output}\n"

                    # 获取远程主机的IP地址和端口号
                    ip, port = ssh.get_transport().getpeername()

                    # 根据IP地址反向查找主机名
                    hostname = socket.gethostbyaddr(ip)[0]

                    # 将用户操作添加到 operations 表
                    save_operation(command, hostname, ip)
                if error:
                    result += f"{error}\n"

            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers,
                           failed_servers=failed_servers, result=result)


######################
# 应用端口转发规则
######################
def run_command(command):
    # 创建带有管理员权限的命令提示符窗口
    win32api.ShellExecute(
        0,
        'runas',
        'cmd.exe',
        '/c ' + command,
        None,
        win32con.SW_SHOW
    )
    return 'Command executed successfully\n'


# 应用端口转发规则
@app.route('/port_forwarding_rule', methods=['POST'])
def port_forwarding_rule():
    global connected_servers
    global failed_servers

    result = ''
    remote_port = request.form['remote_port']
    local_port = request.form['local_port']

    if not remote_port or not local_port:
        result = '请输入端口。'
    else:
        for ssh in connected_clients:
            transport = ssh.get_transport()
            ip = transport.getpeername()[0]  # 获取IP
            command = 'netsh interface portproxy add v4tov4 listenport=' + local_port + ' listenaddress=0.0.0.0 connectport=' + remote_port + ' connectaddress=' + ip
            result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
            output = run_command(command)

            if output:
                result += f"{output}\n"

                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()
                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]
                # 将用户操作添加到 operations 表
                save_operation(command, hostname, ip)

                # 保存到数据库
                save_port_forwarding_rules(ip, remote_port, local_port, command)

    return render_template('batch_operation.html', connected_servers=connected_servers,
                           failed_servers=failed_servers, result=result)


def save_port_forwarding_rules(ip_address, remote_port, local_port, content):
    timestamp = datetime.now()  # 获取当前日期和时间

    # 查询 ServerInfo 表中的记录
    cursor.execute("SELECT hostname, username, password FROM ServerInfo WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    if row is None:
        # 如果没有找到记录，则将 hostname、username 和 password 都设置为 None
        hostname = None
        username = None
        password = None
    else:
        # 如果找到了记录，则将其赋值给 hostname、username 和 password 变量
        hostname = row[0]
        username = row[1]
        password = row[2]

    # 插入新记录到 port_forwarding_rules 表
    cursor.execute(
        "INSERT INTO port_forwarding_rules (editor, hostname, username, password, ip_address, remote_port, "
        "local_port, Content, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session['username'], hostname, username, password, ip_address, remote_port, local_port, content, timestamp))
    conn.commit()


##############
# 端口转发规则数据库表
#############
@app.route('/port_forwarding_rule_html', methods=['GET', 'POST'])
def port_forwarding_rule_html():
    # 连接数据库
    cursor = conn.cursor()

    # 获取 ServerInfo 表中的所有数据
    cursor.execute("SELECT * FROM port_forwarding_rules")
    data = cursor.fetchall()

    return render_template('port_forwarding_rules_table.html', data=data)


@app.route('/search_db_port_forwarding_rules', methods=['GET', 'POST'])
def search_db_port_forwarding_rules():
    if request.method == 'POST':
        column = request.form.get('db_column')
        keyword = request.form.get('db_keyword')
        data = search_db_port_forwarding_rules_keyword(column, keyword)

        return render_template('port_forwarding_rules_table.html', data=data)

    return render_template('port_forwarding_rules_table.html')


# 根据列和关键字搜索数据库
def search_db_port_forwarding_rules_keyword(column, keyword):
    cursor = conn.cursor()
    if column == 'timestamp':  # 如果搜索的是时间列
        sql = "SELECT * FROM port_forwarding_rules WHERE CONVERT(varchar(100), timestamp, 120) LIKE ?"
    else:  # 否则搜索其他列
        sql = "SELECT * FROM port_forwarding_rules WHERE {} LIKE ?".format(column)
    value = ("%" + keyword + "%",)
    cursor.execute(sql, value)
    result = cursor.fetchall()
    return result


# 导入规则
@app.route('/run_port_forwarding_rule', methods=['POST'])
def run_port_forwarding_rule():
    global connected_servers

    servers = request.form.get('port_forwarding_rules')
    result = ''

    if not servers:
        flash('请选择要操作的服务器。')
        return redirect(url_for('index'))

    server_data = json.loads(servers)

    for server in server_data:
        hostname = server['hostname']
        ip_address = server['ip_address']
        content = server['Content']

        result += f"====== {hostname} ({ip_address}) ======\n"
        output = run_command(content)

        if output:
            result += f"{output}\n"

            # 将用户操作添加到 operations 表
            save_operation(content, hostname, ip_address)

        else:
            result += f"{导入出错}\n"

    # 获取 port_forwarding_rules 表中的所有数据
    cursor.execute("SELECT * FROM port_forwarding_rules")
    data = cursor.fetchall()

    return render_template('port_forwarding_rules_table.html', data=data, result=result)


##########################
# 软件安装，删除
#########################
# 软件安装
@app.route('/software_install', methods=['POST'])
def software_install():
    global connected_servers
    global failed_servers

    command = request.form.get('command')
    command = 'msiexec /i "' + command + '" /qn'
    result = ''

    if not command:
        result = '请输入要执行的命令。'

    else:
        for ssh in connected_clients:
            try:
                stdin, stdout, stderr = ssh.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()
                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                if exit_status == 0:
                    result += f"安装成功。\n"

                    # 获取远程主机的IP地址和端口号
                    ip, port = ssh.get_transport().getpeername()

                    # 根据IP地址反向查找主机名
                    hostname = socket.gethostbyaddr(ip)[0]

                    # 将用户操作添加到 operations 表
                    save_operation(command, hostname, ip)

                if exit_status == 1:
                    result += f"安装失败。\n"
            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


# 软件删除
@app.route('/software_uninstall', methods=['POST'])
def software_uninstall():
    global connected_servers
    global failed_servers

    command = request.form.get('command')
    command = 'wmic product where "name=\'' + command + '\'" call uninstall'
    result = ''

    if not command:
        result = '请输入要执行的命令。'

    else:
        for ssh in connected_clients:
            try:
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                if output:
                    result += f"{output}\n"

                    # 获取远程主机的IP地址和端口号
                    ip, port = ssh.get_transport().getpeername()

                    # 根据IP地址反向查找主机名
                    hostname = socket.gethostbyaddr(ip)[0]

                    # 将用户操作添加到 operations 表
                    save_operation(command, hostname, ip)

                if error:
                    result += f"{error}\n"
            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


@app.route('/batch_software_install', methods=['POST'])
def batch_software_install():
    global connected_servers
    global failed_servers

    software_dir = request.form['software_dir']
    result = ''

    if not software_dir:
        result = '请输入目标文件夹地址。'
    else:
        for ssh in connected_clients:
            try:
                # 使用SFTP列出远程计算机上指定目录的文件和子目录
                sftp = ssh.open_sftp()
                files = sftp.listdir(software_dir)

                for file in files:
                    file_path = os.path.join(software_dir, file)
                    command = 'msiexec /i "' + file_path + '" /qn'
                    try:
                        stdin, stdout, stderr = ssh.exec_command(command)
                        exit_status = stdout.channel.recv_exit_status()
                        result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                        if exit_status == 0:
                            result += f"安装成功。\n"

                            # 获取远程主机的IP地址和端口号
                            ip, port = ssh.get_transport().getpeername()
                            # 根据IP地址反向查找主机名
                            hostname = socket.gethostbyaddr(ip)[0]
                            # 将用户操作添加到 operations 表
                            save_operation(command, hostname, ip)

                        if exit_status == 1:
                            result += f"安装失败。\n"
                    except Exception as e:
                        result += f"执行安装命令出错：{str(e)}\n"

                    result += f"{file_path}\n"
                result += '\n\n'  # 添加空行

            except Exception as e:
                result += f"路径有误：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)

@app.route('/show_directory', methods=['POST'])
def show_directory():
    global connected_servers
    global failed_servers

    remote_dir_path = request.form['remote_dir_path']
    result = ''

    if not remote_dir_path:
        result = '请输入目标文件夹地址。'
    else:
        for ssh in connected_clients:
            try:
                # 使用SFTP列出远程计算机上指定目录的文件和子目录
                sftp = ssh.open_sftp()
                files = sftp.listdir(remote_dir_path)

                # 获取远程主机的IP地址和端口号
                ip, port = ssh.get_transport().getpeername()
                # 根据IP地址反向查找主机名
                hostname = socket.gethostbyaddr(ip)[0]
                # 将用户操作添加到 operations 表
                save_operation(remote_dir_path, hostname, ip)
                sftp.close()

                result += f"{ssh.get_transport().getpeername()[0]} 上的文件和文件夹：\n"

                for file in files:
                    file_path = os.path.join(remote_dir_path, file)

                    result += f"{file_path}\n"
                result += '\n\n'  # 添加空行

            except Exception as e:
                result += f"执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


@app.route('/app_file_html', methods=['GET', 'POST'])
def app_file_html():
    if request.method == 'POST':
        selected_files = request.form.getlist('files')
        print(selected_files)
    files = os.listdir('E:\\try')
    return render_template('app_file.html', files=files)


@app.route('/batch_upload_and_install', methods=['POST'])
def batch_upload_and_install():
    global connected_clients
    global failed_servers

    selected_files = request.form.getlist('selected_files')
    result = ''

    if not selected_files:
        result = '请选择要安装的软件。'

    else:
        # 首先将所有软件上传到所有连接的服务器
        for ssh in connected_clients:
            try:
                sftp = ssh.open_sftp()
                for file in selected_files:
                    local_file_path = os.path.join('E:\\try', file)
                    remote_file_path = os.path.join('C:\\here', file)
                    sftp.put(local_file_path, remote_file_path)
                    result += f"{ssh.get_transport().getpeername()[0]} 上传成功！\n"
                sftp.close()

            except Exception as e:
                result += f"{ssh.get_transport().getpeername()[0]} 执行命令出错：{str(e)}\n"

        # 然后在每台服务器上安装所有软件
        for ssh in connected_clients:
            try:
                for file in selected_files:
                    file_path = os.path.join('C:\\here', file)
                    command = 'msiexec /i "' + file_path + '" /qn'
                    stdin, stdout, stderr = ssh.exec_command(command)
                    exit_status = stdout.channel.recv_exit_status()
                    result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                    if exit_status == 0:
                        result += f"安装成功。\n"

                        # 获取远程主机的IP地址和端口号
                        ip, port = ssh.get_transport().getpeername()
                        # 根据IP地址反向查找主机名
                        hostname = socket.gethostbyaddr(ip)[0]
                        # 将用户操作添加到 operations 表
                        save_operation(command, hostname, ip)

                    if exit_status == 1:
                        result += f"安装失败。\n"

            except Exception as e:
                result += f"{ssh.get_transport().getpeername()[0]} 执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


@app.route('/app_install_html', methods=['GET', 'POST'])
def app_install_html():
    remote_dir_path = 'C:\\here'
    result = ''

    # 获取第一个连接的远程主机
    ssh = connected_clients[0]

    try:
        # 使用SFTP列出远程计算机上指定目录的文件和子目录
        sftp = ssh.open_sftp()
        files = sftp.listdir(remote_dir_path)
        sftp.close()

    except Exception as e:
        result += f"执行命令出错：{str(e)}\n"
        return render_template('batch_operation.html', connected_servers=connected_servers,
                               failed_servers=failed_servers,
                               result=result)

    # 将文件列表传递给模板引擎
    return render_template('app_install.html', files=files)


@app.route('/app_install', methods=['POST'])
def app_install():
    global connected_clients
    global failed_servers

    selected_files = request.form.getlist('selected_files')
    result = ''

    if not selected_files:
        result = '请选择要安装的软件。'

    else:
        # 在每台服务器上安装所有软件
        for ssh in connected_clients:
            try:
                for file in selected_files:
                    file_path = os.path.join('C:\\here', file)
                    command = 'msiexec /i "' + file_path + '" /qn'
                    stdin, stdout, stderr = ssh.exec_command(command)
                    exit_status = stdout.channel.recv_exit_status()
                    result += f"====== {ssh.get_transport().getpeername()[0]} ({ssh.get_transport().getpeername()[1]}) ======\n"
                    if exit_status == 0:
                        result += f"安装成功。\n"

                        # 获取远程主机的IP地址和端口号
                        ip, port = ssh.get_transport().getpeername()
                        # 根据IP地址反向查找主机名
                        hostname = socket.gethostbyaddr(ip)[0]
                        # 将用户操作添加到 operations 表
                        save_operation(command, hostname, ip)

                    if exit_status == 1:
                        result += f"安装失败。\n"

            except Exception as e:
                result += f"{ssh.get_transport().getpeername()[0]} 执行命令出错：{str(e)}\n"

    return render_template('batch_operation.html', connected_servers=connected_servers, failed_servers=failed_servers,
                           result=result)


if __name__ == '__main__':
    app.run(debug=True)

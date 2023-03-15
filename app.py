import random, pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "secret key"  # 设置 secret key 以启用 flash 消息

############
# 数据库配置
############
# Connect to SQL Server Express using Windows authentication
server = 'localhost'
database = 'ServerManager'
conn = pyodbc.connect('Driver={SQL Server};Server=' + server + ';Database=' + database + ';Trusted_Connection=yes;')

# 读取数据库信息
cursor = conn.cursor()
cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='users'")

# 检查数据库中是否存在users表。若没有则创建。
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


############
# 发送邮件配置
############
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'servermanagerapp@gmail.com'  # 电子邮件地址
app.config['MAIL_PASSWORD'] = 'abeqwuusddabgzot'  # 电子邮第三方app件密码，不是电子邮件密码，需要在邮箱设置。
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


@app.route('/panel')
def panel():
    # 如果未登录，则跳转到登录页面
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('panel.html', username=session['username'])


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


@app.route('/manage_server', methods=['GET', 'POST'])
def manage_server():
    cursor = conn.cursor()

    if request.method == 'POST':
        if request.form.get('delete'):
            # 获取 POST 请求中的表单数据
            server_id = request.form['server_id']

            # 从 ServerInfo 表中删除指定服务器
            cursor.execute("DELETE FROM ServerInfo WHERE id=?", (server_id,))
            conn.commit()

            # 显示成功消息
            flash('服务器已删除！')
        else:
            # 获取 POST 请求中的表单数据
            hostname = request.form['hostname']
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
            cursor.execute("INSERT INTO ServerInfo (hostname, password, ip_address, "
                           "operating_system, os_version, applications, hardware_configuration, "
                           "security_settings, logs_and_monitoring, backup_and_recovery, note) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (hostname, password, ip_address, operating_system, os_version,
                            applications, hardware_configuration, security_settings,
                            logs_and_monitoring, backup_and_recovery, note))
            conn.commit()

            # 显示成功消息
            flash('服务器已添加！')

    # 获取 ServerInfo 表中的所有数据
    cursor.execute("SELECT * FROM ServerInfo")
    data = cursor.fetchall()

    return render_template('manage_server.html', data=data)


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
        cursor.execute("UPDATE ServerInfo SET hostname=?, password=?, ip_address=?, "
                       "operating_system=?, os_version=?, applications=?, hardware_configuration=?, "
                       "security_settings=?, logs_and_monitoring=?, backup_and_recovery=?, note=? "
                       "WHERE id=?",
                       (hostname, password, ip_address, operating_system, os_version,
                        applications, hardware_configuration, security_settings,
                        logs_and_monitoring, backup_and_recovery, note, id))
        conn.commit()

        # 显示成功消息
        flash('服务器信息已修改！')
        return redirect(url_for('manage_server'))

    # 显示编辑服务器信息的表单
    return render_template('server_edit.html', data=server)



if __name__ == '__main__':
    app.run(debug=True)

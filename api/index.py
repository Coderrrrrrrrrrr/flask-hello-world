from flask import Flask, render_template, session, redirect, url_for, request
import os
import uuid
import requests
import json
import time
import qrcode
import io
import base64
# 添加MySQL数据库支持
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # 在生产环境中需要更安全的密钥

# 微信登录配置
WECHAT_CONFIG = {
    'appid': 'wxc36270057b608f9f',  # 替换为你的微信appid
    'secret': 'e4579e61849e774ed42468ebc08db53d',  # 替换为你的微信secret
    'platform_type': 'open',  # 'mp'表示公众号平台，'open'表示开放平台
}

# MySQL数据库配置
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'cxtx1028',
    'database': 'ecommerce',
    'charset': 'utf8mb4'
}

# 商品数据
products = [
    {
        'id': 1,
        'title': '智能手机',
        'price': 2999.99,
        'image': '/static/image/2.jpg'
    },
    {
        'id': 2,
        'title': '笔记本电脑',
        'price': 5999.99,
        'image': '/static/image/2.jpg'
    },
    {
        'id': 3,
        'title': '无线耳机',
        'price': 299.99,
        'image': '/static/image/2.jpg'
    },
    {
        'id': 4,
        'title': '智能手表',
        'price': 1599.99,
        'image': '/static/image/2.jpg'
    }
]

# 模拟用户数据库
users = {}

# 存储登录票据
login_tickets = {}

# 数据库连接函数
def get_db_connection():
    return pymysql.connect(**MYSQL_CONFIG)

# 初始化数据库表
def init_db():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            # 创建用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    nickname VARCHAR(100),
                    avatar VARCHAR(255) DEFAULT '/static/image/default_avatar.png',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 插入测试用户（如果不存在）
            cursor.execute("SELECT id FROM users WHERE username = 'admin'")
            if not cursor.fetchone():
                hashed_password = generate_password_hash('admin123')
                cursor.execute(
                    "INSERT INTO users (username, password, nickname) VALUES (%s, %s, %s)",
                    ('admin', hashed_password, '管理员')
                )
            
        connection.commit()
        connection.close()
        print("数据库初始化完成")
    except Exception as e:
        print(f"数据库初始化失败: {e}")

@app.route('/')
def home():
    return render_template('index.html', products=products, user=session.get('user'))

@app.route('/about')
def about():
    return render_template('about.html', user=session.get('user'))

# 商品详情页面
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return render_template('product.html', product=product, user=session.get('user'))
    return 'Product not found', 404

# 登录页面 - 显示账号密码登录表单
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 默认显示账号密码登录
    login_type = request.args.get('type', 'password')
    
    if login_type == 'wechat':
        # 微信扫码登录逻辑
        # 生成一个唯一的票据ID
        ticket_id = str(uuid.uuid4())
        print(f"创建新的登录票据: {ticket_id}")
        
        # 获取微信二维码URL
        qr_url = get_wechat_qr_code(ticket_id)
        
        if qr_url:
            # 存储票据信息
            login_tickets[ticket_id] = {
                'status': 'pending',
                'user_id': None,
                'created_at': time.time()
            }
            print(f"创建票据成功: {ticket_id}, 当前所有票据: {login_tickets}")
            
            # 直接传递二维码图片URL
            return render_template('login.html', qr_url=qr_url, ticket_id=ticket_id, 
                                 user=session.get('user'), login_type='wechat')
        else:
            print(f"获取二维码失败，ticket_id: {ticket_id}")
            return "获取二维码失败，请稍后重试", 500
    else:
        # 账号密码登录逻辑
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    user = cursor.fetchone()
                    
                connection.close()
                
                if user and check_password_hash(user[2], password):  # user[2] 是密码字段
                    # 登录成功，设置会话
                    session['user'] = {
                        'id': user[0],
                        'username': user[1],
                        'nickname': user[3],
                        'avatar': user[4]
                    }
                    return redirect(url_for('home'))
                else:
                    return render_template('login.html', error='用户名或密码错误', 
                                         user=session.get('user'), login_type='password')
            except Exception as e:
                print(f"登录时发生错误: {e}")
                return render_template('login.html', error='登录失败，请稍后重试', 
                                     user=session.get('user'), login_type='password')
        
        # GET请求显示登录表单
        return render_template('login.html', user=session.get('user'), login_type='password')

# 获取微信二维码
def get_wechat_qr_code(ticket_id):
    try:
        redirect_uri = request.url_root.rstrip('/') + url_for('wechat_login_callback')
        encoded_redirect_uri = requests.utils.quote(redirect_uri, safe='')
        
        # 根据平台类型选择不同的授权URL和scope
        if WECHAT_CONFIG.get('platform_type') == 'mp':
            # 微信公众号平台使用网页授权接口
            # 根据文档: https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html
            auth_url = f"https://open.weixin.qq.com/connect/oauth2/authorize?appid={WECHAT_CONFIG['appid']}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_userinfo&state={ticket_id}#wechat_redirect"
            print(f"使用公众号授权URL: {auth_url}")
        else:
            # 微信开放平台使用扫码登录接口
            # 根据文档: https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
            auth_url = f"https://open.weixin.qq.com/connect/qrconnect?appid={WECHAT_CONFIG['appid']}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_login&state={ticket_id}#wechat_redirect"
            print(f"使用开放平台授权URL: {auth_url}")
            
        print(f"生成的授权URL: {auth_url}")
        print(f"重定向URI: {redirect_uri}")
        print(f"编码后的重定向URI: {encoded_redirect_uri}")
        
        # 使用qrcode库生成二维码图片
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(auth_url)
        qr.make(fit=True)
        
        # 创建二维码图片
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 将图片转换为base64编码
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        # 返回可以直接在HTML中使用的base64编码图片URL
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        print(f"获取微信二维码失败: {e}")
        return None

# 检查登录状态的API端点
@app.route('/check_login_status/<ticket_id>')
def check_login_status(ticket_id):
    print(f"检查登录状态: {ticket_id}")
    print(f"当前所有票据: {login_tickets}")
    
    if ticket_id in login_tickets:
        status = login_tickets[ticket_id]['status']
        print(f"票据 {ticket_id} 的状态: {status}")
        
        if status == 'scanned':
            return {'status': 'scanned'}
        elif status == 'confirmed':
            user_id = login_tickets[ticket_id]['user_id']
            if user_id in users:
                # 设置用户会话
                session['user'] = users[user_id]
                # 清理票据记录
                del login_tickets[ticket_id]
                return {'status': 'confirmed'}
            else:
                print(f"找不到用户ID: {user_id}")
                return {'status': 'error', 'message': '找不到用户信息'}
        else:
            return {'status': 'pending'}
    else:
        print(f"找不到票据: {ticket_id}")
        return {'status': 'invalid'}, 404

# 微信扫码回调URL - 用户扫码后微信服务器调用

# 添加一个测试路由，用于验证微信配置
@app.route('/test_wechat_config')
def test_wechat_config():
    platform_type = WECHAT_CONFIG.get('platform_type', 'unknown')
    appid = WECHAT_CONFIG.get('appid', 'unknown')
    redirect_uri = request.url_root.rstrip('/') + url_for('wechat_login_callback')
    encoded_redirect_uri = requests.utils.quote(redirect_uri, safe='')
    
    if platform_type == 'mp':
        auth_url = f"https://open.weixin.qq.com/connect/oauth2/authorize?appid={appid}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_userinfo&state=test#wechat_redirect"
    else:
        auth_url = f"https://open.weixin.qq.com/connect/qrconnect?appid={appid}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_login&state=test#wechat_redirect"
    
    config_info = {
        'platform_type': platform_type,
        'appid': appid,
        'redirect_uri': redirect_uri,
        'encoded_redirect_uri': encoded_redirect_uri,
        'auth_url': auth_url
    }
    
    return render_template('test_config.html', config=config_info)

# 添加一个直接测试微信扫码登录的路由
@app.route('/test_wechat_login')
def test_wechat_login():
    # 生成一个唯一的票据ID
    ticket_id = str(uuid.uuid4())
    print(f"创建测试登录票据: {ticket_id}")
    
    # 直接生成授权URL
    platform_type = WECHAT_CONFIG.get('platform_type', 'open')
    appid = WECHAT_CONFIG.get('appid')
    redirect_uri = request.url_root.rstrip('/') + url_for('wechat_login_callback')
    encoded_redirect_uri = requests.utils.quote(redirect_uri, safe='')
    
    if platform_type == 'mp':
        auth_url = f"https://open.weixin.qq.com/connect/oauth2/authorize?appid={appid}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_userinfo&state={ticket_id}#wechat_redirect"
    else:
        auth_url = f"https://open.weixin.qq.com/connect/qrconnect?appid={appid}&redirect_uri={encoded_redirect_uri}&response_type=code&scope=snsapi_login&state={ticket_id}#wechat_redirect"
    
    # 存储票据信息
    login_tickets[ticket_id] = {
        'status': 'pending',
        'user_id': None,
        'created_at': time.time()
    }
    print(f"创建测试票据成功: {ticket_id}, 当前所有票据: {login_tickets}")
    
    # 生成二维码
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(auth_url)
    qr.make(fit=True)
    
    # 创建二维码图片
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 将图片转换为base64编码
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # 返回可以直接在HTML中使用的base64编码图片URL
    qr_url = f"data:image/png;base64,{img_str}"
    
    return render_template('test_login.html', qr_url=qr_url, ticket_id=ticket_id, auth_url=auth_url)

# 微信登录回调URL - 用户确认登录后微信服务器调用
@app.route('/wechat_login_callback', methods=['GET'])
def wechat_login_callback():
    try:
        # 解析微信发送的数据
        code = request.args.get('code')
        state = request.args.get('state')  # ticket_id
        
        if not code or not state:
            print("微信回调缺少code或state参数")
            return 'fail: 缺少code或state参数', 400
            
        print(f"收到微信回调，code: {code}, state: {state}")
        print(f"当前所有票据: {login_tickets}")
        
        # 通过code获取access_token
        token_url = f"https://api.weixin.qq.com/sns/oauth2/access_token?appid={WECHAT_CONFIG['appid']}&secret={WECHAT_CONFIG['secret']}&code={code}&grant_type=authorization_code"
        print(f"请求token的URL: {token_url}")
        
        token_response = requests.get(token_url)
        print(f"token响应状态码: {token_response.status_code}")
        print(f"token响应内容: {token_response.text}")
        
        token_data = token_response.json()
        
        if 'errcode' in token_data:
            error_code = token_data.get('errcode')
            error_msg = token_data.get('errmsg', '未知错误')
            print(f"获取token失败: 错误码 {error_code}, 错误信息: {error_msg}")
            
            # 常见错误处理建议
            if error_code == 40029:
                return "无效的授权码，请重新扫描二维码", 400
            elif error_code == 40163:
                return "授权码已被使用，请重新扫描二维码", 400
            elif error_code == 41001:
                return "缺少access_token参数", 400
            elif error_code == 41002:
                return "缺少appid参数", 400
            elif error_code == 41003:
                return "缺少refresh_token参数", 400
            elif error_code == 41004:
                return "缺少secret参数", 400
            elif error_code == 42001:
                return "access_token已过期", 400
            elif error_code == 43004:
                return "需要用户授权", 400
            elif error_code == 40001:
                return "AppSecret错误或已重置", 400
            else:
                return f"获取token失败: {error_msg} (错误码: {error_code})", 400
        
        if 'access_token' in token_data and 'openid' in token_data:
            access_token = token_data['access_token']
            openid = token_data['openid']
            
            print(f"成功获取token: access_token={access_token[:10]}..., openid={openid}")
            
            # 获取用户信息
            user_info_url = f"https://api.weixin.qq.com/sns/userinfo?access_token={access_token}&openid={openid}&lang=zh_CN"
            print(f"请求用户信息的URL: {user_info_url}")
            
            user_response = requests.get(user_info_url)
            print(f"用户信息响应状态码: {user_response.status_code}")
            print(f"用户信息响应内容: {user_response.text}")
            
            user_data = user_response.json()
            
            if 'errcode' in user_data:
                error_code = user_data.get('errcode')
                error_msg = user_data.get('errmsg', '未知错误')
                print(f"获取用户信息失败: 错误码 {error_code}, 错误信息: {error_msg}")
                return f"获取用户信息失败: {error_msg} (错误码: {error_code})", 400
            
            if 'openid' in user_data:
                # 保存用户信息
                users[openid] = {
                    'id': openid,
                    'nickname': user_data.get('nickname', '微信用户'),
                    'avatar': user_data.get('headimgurl', '/static/image/default_avatar.png'),
                    'openid': openid,
                    'info': user_data
                }
                
                print(f"成功获取用户信息: nickname={user_data.get('nickname', '微信用户')}, openid={openid}")
                print(f"用户数据: {users[openid]}")
                
                # 更新票据状态
                if state in login_tickets:
                    login_tickets[state]['status'] = 'confirmed'
                    login_tickets[state]['user_id'] = openid
                    
                    # 将用户信息存储在session中
                    session['user'] = users[openid]
                    print(f"更新票据状态成功: {state}, status=confirmed, user_id={openid}")
                    print(f"用户已登录，会话数据: {session.get('user')}")
                    
                    # 重定向到首页或其他页面
                    return redirect(url_for('home'))
                else:
                    print(f"找不到对应的票据: {state}")
                    return "找不到对应的登录票据", 400
            else:
                print("用户信息中没有openid")
                return "获取用户信息失败: 响应中没有openid", 400
        else:
            print("token响应中没有access_token或openid")
            return "获取token失败: 响应中没有access_token或openid", 400
    except Exception as e:
        import traceback
        print(f"处理微信登录回调失败: {e}")
        print(traceback.format_exc())
        return f"处理微信登录回调失败: {str(e)}", 500

# 用户资料页面
@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user)

# 登出功能
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# 创建templates目录和基础模板
if not os.path.exists('templates'):
    os.makedirs('templates')

# 创建基础模板
base_template = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if title %}{{ title }} - 电商网站{% else %}电商网站{% endif %}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        /* 顶部导航栏 */
        .navbar {
            background: linear-gradient(to right, #ff4444, #ff6600);
            padding: 0 5%;
            height: 60px;
            display: flex;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo {
            color: white;
            font-size: 24px;
            font-weight: bold;
            text-decoration: none;
        }
        
        .nav-links {
            display: flex;
            margin-left: auto;
            align-items: center;
        }
        
        .nav-links a {
            color: white;
            text-decoration: none;
            padding: 10px 15px;
            margin: 0 5px;
            border-radius: 4px;
            transition: background 0.3s;
        }
        
        .nav-links a:hover {
            background-color: rgba(255, 255, 255, 0.2);
        }
        
        .user-info {
            display: flex;
            align-items: center;
            color: white;
            margin-left: 15px;
        }
        
        .user-avatar {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .search-bar {
            flex: 1;
            max-width: 500px;
            margin: 0 20px;
            position: relative;
        }
        
        .search-bar input {
            width: 100%;
            padding: 10px 15px;
            border: none;
            border-radius: 20px;
            font-size: 14px;
        }
        
        /* 主容器 */
        .container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 0 20px;
        }
        
        /* 页面标题 */
        h2 {
            margin: 20px 0;
            font-size: 24px;
            color: #333;
            border-left: 4px solid #ff4444;
            padding-left: 10px;
        }
        
        /* 商品网格 */
        .products {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        /* 商品卡片 */
        .product-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            overflow: hidden;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .product-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .product-badge {
            position: absolute;
            top: 10px;
            left: 10px;
            background: linear-gradient(to right, #ff4444, #ff6600);
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            z-index: 10;
        }
        
        .product-image {
            width: 100%;
            height: 250px;
            object-fit: cover;
            transition: transform 0.5s;
        }
        
        .product-card:hover .product-image {
            transform: scale(1.05);
        }
        
        .product-info {
            padding: 15px;
        }
        
        .product-title {
            font-size: 16px;
            margin: 0 0 10px 0;
            color: #333;
            height: 40px;
            overflow: hidden;
        }
        
        .product-price {
            font-size: 20px;
            color: #ff4444;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .product-price small {
            font-size: 14px;
            color: #999;
            text-decoration: line-through;
            margin-left: 8px;
        }
        
        .product-sales {
            font-size: 13px;
            color: #999;
            margin: 5px 0;
        }
        
        .btn {
            display: inline-block;
            background: linear-gradient(to right, #ff4444, #ff6600);
            color: white;
            padding: 8px 15px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 10px;
            border: none;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
            width: 100%;
            text-align: center;
        }
        
        .btn:hover {
            background: linear-gradient(to right, #ff2222, #ff5500);
            transform: translateY(-2px);
            box-shadow: 0 4px 10px rgba(255, 68, 68, 0.3);
        }
        
        /* 商品详情页面 */
        .product-detail {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            padding: 30px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        @media (max-width: 768px) {
            .product-detail {
                grid-template-columns: 1fr;
            }
        }
        
        .product-detail-image {
            max-width: 100%;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .product-detail-info h2 {
            font-size: 28px;
            margin-bottom: 15px;
            color: #333;
        }
        
        .product-detail-price {
            font-size: 32px;
            color: #ff4444;
            font-weight: bold;
            margin: 15px 0;
        }
        
        .product-detail-price small {
            font-size: 16px;
            color: #999;
            text-decoration: line-through;
            margin-left: 10px;
        }
        
        .product-detail-description {
            color: #666;
            line-height: 1.6;
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 5px;
        }
        
        /* 关于页面 */
        .about-content {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            padding: 30px;
            line-height: 1.8;
        }
        
        .about-content h2 {
            border: none;
            padding: 0;
            margin-bottom: 20px;
        }
        
        .about-content p {
            margin-bottom: 15px;
            color: #666;
        }
        
        /* 登录页面 */
        .login-container {
            max-width: 400px;
            margin: 50px auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            padding: 30px;
            text-align: center;
        }
        
        .qr-code {
            width: 200px;
            height: 200px;
            margin: 20px auto;
        }
        
        .qr-code img {
            max-width: 100%;
            max-height: 100%;
        }
        
        .login-instructions {
            margin: 20px 0;
            color: #666;
        }
        
        .login-status {
            margin: 15px 0;
            padding: 10px;
            border-radius: 4px;
        }
        
        .status-pending {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        
        .status-scanned {
            background-color: #fff3e0;
            color: #f57c00;
        }
        
        .status-confirmed {
            background-color: #e8f5e9;
            color: #388e3c;
        }
        
        /* 用户资料页面 */
        .profile-container {
            max-width: 800px;
            margin: 30px auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            padding: 30px;
        }
        
        .profile-header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin-right: 20px;
        }
        
        .profile-info h2 {
            margin-bottom: 10px;
        }
        
        .profile-info p {
            color: #666;
            margin: 5px 0;
        }
        
        .profile-details {
            margin-top: 20px;
        }
        
        .profile-details h3 {
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        
        .user-info-item {
            display: flex;
            margin-bottom: 10px;
        }
        
        .user-info-label {
            width: 120px;
            font-weight: bold;
            color: #333;
        }
        
        .user-info-value {
            flex: 1;
            color: #666;
        }
        
        /* 登录表单 */
        .login-form {
            text-align: left;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        
        .error-message {
            color: #ff4444;
            margin: 10px 0;
            padding: 10px;
            background-color: #ffebee;
            border-radius: 4px;
        }
        
        .login-switch {
            margin: 20px 0;
            font-size: 14px;
        }
        
        .login-switch a {
            color: #ff4444;
            text-decoration: none;
        }
        
        /* 页脚 */
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .navbar {
                padding: 0 10px;
                flex-wrap: wrap;
                height: auto;
                padding: 10px;
            }
            
            .search-bar {
                order: 3;
                margin: 10px 0 0 0;
                width: 100%;
            }
            
            .nav-links {
                margin-left: auto;
            }
            
            .products {
                grid-template-columns: repeat(auto-fill, minmax(100%, 1fr));
            }
            
            .profile-header {
                flex-direction: column;
                text-align: center;
            }
            
            .profile-avatar {
                margin-right: 0;
                margin-bottom: 15px;
            }
            
            .user-info-item {
                flex-direction: column;
            }
            
            .user-info-label {
                width: 100%;
                margin-bottom: 5px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <a href="{{ url_for('home') }}" class="logo">电商网站</a>
        <div class="search-bar">
            <input type="text" placeholder="搜索商品...">
        </div>
        <div class="nav-links">
            <a href="{{ url_for('home') }}">首页</a>
            <a href="{{ url_for('about') }}">关于我们</a>
            {% if user %}
                <a href="{{ url_for('profile') }}">个人资料</a>
                <div class="user-info">
                    <img src="{{ user.avatar }}" alt="头像" class="user-avatar">
                    <span>{{ user.nickname or user.username }}</span>
                    <a href="{{ url_for('logout') }}" style="color: white; margin-left: 10px;">退出</a>
                </div>
            {% else %}
                <a href="{{ url_for('login') }}">登录</a>
            {% endif %}
        </div>
    </nav>
    
    <div class="container">
        {% block content %}{% endblock %}
    </div>
    
    <div class="footer">
        <p>&copy; 2023 电商网站. 保留所有权利.</p>
    </div>
    
    {% block scripts %}{% endblock %}
</body>
</html>'''

# 创建首页模板
index_template = '''{% extends "base.html" %}

{% block content %}
<h2>热门商品</h2>
<div class="products">
    {% for product in products %}
    <div class="product-card">
        <span class="product-badge">热卖</span>
        <img src="{{ product.image }}" alt="{{ product.title }}" class="product-image">
        <div class="product-info">
            <h3 class="product-title">{{ product.title }}</h3>
            <p class="product-price">¥{{ product.price }} <small>¥{{ product.price * 1.2 | round(2) }}</small></p>
            <p class="product-sales">销量: {{ (product.id * 123) }}件</p>
            <a href="{{ url_for('product_detail', product_id=product.id) }}" class="btn">立即购买</a>
        </div>
    </div>
    {% endfor %}
</div>
{% endblock %}'''

# 创建关于页面模板
about_template = '''{% extends "base.html" %}

{% block content %}
<div class="about-content">
    <h2>关于我们</h2>
    <p>欢迎来到我们的电商平台！我们致力于为您提供最优质的商品和最好的购物体验。</p>
    <p>我们的平台拥有丰富的商品种类，从电子产品到家居用品，从时尚服饰到美妆护肤，应有尽有。所有商品都经过严格筛选，确保品质优良。</p>
    <p>我们拥有专业的客服团队，7x24小时为您提供服务，任何问题都可以随时联系我们。同时我们提供快速的物流服务，确保您能尽快收到心仪的商品。</p>
    <p>感谢您选择我们的平台，我们将不断努力，为您提供更优质的购物体验！</p>
</div>
{% endblock %}'''

# 创建商品详情页面模板
product_template = '''{% extends "base.html" %}

{% block content %}
<div class="product-detail">
    <div class="product-images">
        <img src="{{ product.image }}" alt="{{ product.title }}" class="product-detail-image">
    </div>
    <div class="product-detail-info">
        <h2>{{ product.title }}</h2>
        <p class="product-detail-price">¥{{ product.price }} <small>¥{{ product.price * 1.2 | round(2) }}</small></p>
        <p class="product-sales">销量: {{ (product.id * 123) }}件</p>
        <div class="product-detail-description">
            <p>这是一件高质量的商品，采用优质材料制作，工艺精良，品质可靠。我们提供完善的售后服务，支持7天无理由退换货，让您购物无忧。</p>
            <p>商品特点：</p>
            <ul>
                <li>高品质材料，经久耐用</li>
                <li>精美工艺，细节考究</li>
                <li>符合人体工学设计</li>
                <li>品牌保证，售后无忧</li>
            </ul>
        </div>
        <a href="#" class="btn">立即购买</a>
        <a href="{{ url_for('home') }}" class="btn" style="background: #666;">返回首页</a>
    </div>
</div>
{% endblock %}'''

# 创建登录页面模板
login_template = '''{% extends "base.html" %}

{% block content %}
<div class="login-container">
    {% if login_type == 'wechat' %}
        <h2>微信扫码登录</h2>
        <p class="login-instructions">请使用微信扫描下方二维码进行登录</p>
        
        <div class="qr-code">
            {% if qr_url %}
                <img src="{{ qr_url }}" alt="微信登录二维码">
            {% else %}
                <div class="qr-code-placeholder">二维码加载失败</div>
            {% endif %}
        </div>
        
        <div id="login-status" class="login-status status-pending">
            等待扫描二维码...
        </div>
        
        <p>票据ID: {{ ticket_id }}</p>
        
        <div class="login-switch">
            <p>使用账号密码登录？<a href="{{ url_for('login') }}">点击这里</a></p>
        </div>
    {% else %}
        <h2>账号密码登录</h2>
        <p class="login-instructions">请输入您的账号和密码</p>
        
        {% if error %}
            <div class="error-message">{{ error }}</div>
        {% endif %}
        
        <form class="login-form" method="POST">
            <div class="form-group">
                <label for="username">用户名:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">密码:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">登录</button>
        </form>
        
        <div class="login-switch">
            <p>使用微信扫码登录？<a href="{{ url_for('login', type='wechat') }}">点击这里</a></p>
        </div>
    {% endif %}
    
    <a href="{{ url_for('home') }}" class="btn" style="background: #666;">返回首页</a>
</div>
{% endblock %}

{% block scripts %}
{% if login_type == 'wechat' %}
<script>
    // 定期检查登录状态
    const ticketId = "{{ ticket_id }}";
    const statusElement = document.getElementById('login-status');
    
    function checkLoginStatus() {
        fetch(`/check_login_status/${ticketId}`)
            .then(response => response.json())
            .then(data => {
                switch(data.status) {
                    case 'pending':
                        statusElement.className = 'login-status status-pending';
                        statusElement.textContent = '等待扫描二维码...';
                        break;
                    case 'scanned':
                        statusElement.className = 'login-status status-scanned';
                        statusElement.textContent = '二维码已扫描，请在微信中确认登录...';
                        break;
                    case 'confirmed':
                        statusElement.className = 'login-status status-confirmed';
                        statusElement.textContent = '登录成功，正在跳转...';
                        // 延迟跳转以显示成功消息
                        setTimeout(() => {
                            window.location.href = "{{ url_for('home') }}";
                        }, 1000);
                        break;
                    default:
                        statusElement.className = 'login-status status-pending';
                        statusElement.textContent = '二维码已失效，请刷新页面重试';
                        break;
                }
            })
            .catch(error => {
                console.error('检查登录状态时出错:', error);
            });
    }
    
    // 每2秒检查一次登录状态
    setInterval(checkLoginStatus, 2000);
    
    // 页面加载时立即检查一次
    checkLoginStatus();
</script>
{% endif %}
{% endblock %}'''

# 创建用户资料页面模板
profile_template = '''{% extends "base.html" %}

{% block content %}
<div class="profile-container">
    <div class="profile-header">
        <img src="{{ user.avatar }}" alt="{{ user.nickname or user.username }}" class="profile-avatar">
        <div class="profile-info">
            <h2>{{ user.nickname or user.username }}</h2>
            <p>欢迎回来！</p>
            <p>用户ID: {{ user.id }}</p>
        </div>
    </div>
    
    <div class="profile-details">
        <h3>用户详细信息</h3>
        <div class="user-info-item">
            <div class="user-info-label">用户名:</div>
            <div class="user-info-value">{{ user.username }}</div>
        </div>
        <div class="user-info-item">
            <div class="user-info-label">昵称:</div>
            <div class="user-info-value">{{ user.nickname or '未设置' }}</div>
        </div>
        {% if user.info %}
            <div class="user-info-item">
                <div class="user-info-label">性别:</div>
                <div class="user-info-value">
                    {% if user.info.sex == 1 %}男
                    {% elif user.info.sex == 2 %}女
                    {% else %}未知
                    {% endif %}
                </div>
            </div>
            <div class="user-info-item">
                <div class="user-info-label">城市:</div>
                <div class="user-info-value">{{ user.info.city }}</div>
            </div>
            <div class="user-info-item">
                <div class="user-info-label">省份:</div>
                <div class="user-info-value">{{ user.info.province }}</div>
            </div>
            <div class="user-info-item">
                <div class="user-info-label">国家:</div>
                <div class="user-info-value">{{ user.info.country }}</div>
            </div>
            <div class="user-info-item">
                <div class="user-info-label">语言:</div>
                <div class="user-info-value">{{ user.info.language }}</div>
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}'''

# 写入模板文件
with open('templates/base.html', 'w', encoding='utf-8') as f:
    f.write(base_template)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(index_template)

with open('templates/about.html', 'w', encoding='utf-8') as f:
    f.write(about_template)

with open('templates/product.html', 'w', encoding='utf-8') as f:
    f.write(product_template)

with open('templates/login.html', 'w', encoding='utf-8') as f:
    f.write(login_template)

# 新增用户资料页面模板
with open('templates/profile.html', 'w', encoding='utf-8') as f:
    f.write(profile_template)

# 添加一个直接登录的测试路由（仅用于开发测试）
@app.route('/test_direct_login')
def test_direct_login():
    # 创建一个测试用户
    test_user_id = 'test_user_' + str(uuid.uuid4())
    users[test_user_id] = {
        'id': test_user_id,
        'nickname': '测试用户',
        'avatar': '/static/image/default_avatar.png',
        'openid': test_user_id,
        'info': {
            'nickname': '测试用户',
            'sex': 1,
            'province': '广东',
            'city': '深圳',
            'country': '中国',
            'headimgurl': '/static/image/default_avatar.png',
            'privilege': [],
            'language': 'zh_CN'
        }
    }
    
    # 设置用户会话
    session['user'] = users[test_user_id]
    
    print(f"创建测试用户成功: {test_user_id}")
    print(f"用户数据: {users[test_user_id]}")
    print(f"会话数据: {session.get('user')}")
    
    # 重定向到首页
    return redirect(url_for('home'))

# 初始化数据库
init_db()

# 添加启动应用的代码
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
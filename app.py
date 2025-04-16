import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf import FlaskForm
from wtforms import TextAreaField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from wtforms import StringField
from functools import wraps
import bleach
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if not user or not user['is_admin']:
            flash('관리자만 접근할 수 있습니다.')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function



class BioForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[Length(max=500)])

class PasswordForm(FlaskForm):
    current_password = PasswordField('현재 비밀번호', validators=[DataRequired()])
    new_password = PasswordField('새 비밀번호', validators=[Length(min=6)])

class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])

class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])

class NewProductForm(FlaskForm):
    title = StringField('제목', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('설명', validators=[DataRequired(), Length(min=10, max=1000)])
    price = StringField('가격', validators=[DataRequired(), Length(max=20)])

class ReportForm(FlaskForm):
    target_id = StringField('신고 대상 ID', validators=[DataRequired(), Length(min=1)])
    reason = TextAreaField('신고 사유', validators=[DataRequired(), Length(min=5, max=1000)])


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        user_id = str(uuid.uuid4())

        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/user/<user_id>')
def view_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('해당 사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    return render_template('user_profile.html', user=user)

@app.route('/admin')
@admin_required
def admin_page():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, username, is_admin FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()

    # 유저 신고 수 집계
    cursor.execute("""
        SELECT target_id, COUNT(*) AS report_count
        FROM report
        WHERE target_id IN (SELECT id FROM user)
        GROUP BY target_id
    """)
    user_reports = {row['target_id']: row['report_count'] for row in cursor.fetchall()}

    # 상품 신고 수 집계
    cursor.execute("""
        SELECT target_id, COUNT(*) AS report_count
        FROM report
        WHERE target_id IN (SELECT id FROM product)
        GROUP BY target_id
    """)
    product_reports = {row['target_id']: row['report_count'] for row in cursor.fetchall()}

    return render_template(
        'admin.html',
        users=users,
        products=products,
        reports=reports,
        user_reports=user_reports,
        product_reports=product_reports
    )

# 관리자 - 상품 삭제제
@csrf.exempt
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_page'))


# 관리자 - 유저 휴면 처리
@app.route('/admin/suspend_user/<user_id>', methods=['POST'])
@csrf.exempt
@admin_required
def suspend_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash('해당 사용자가 휴면 처리되었습니다.')
    return redirect(url_for('admin_page'))



# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            if user['is_suspended']:
                flash('이 계정은 휴면 상태입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))

    return render_template('login.html', form=form)



# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@csrf.exempt
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

@app.route('/search')
def search_products():
    query = request.args.get('q')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE title LIKE ?", (f'%{query}%',))
    results = cursor.fetchall()
    return render_template('search_results.html', query=query, results=results)



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    bio_form = BioForm()
    password_form = PasswordForm()

    
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_products = cursor.fetchall()

    if request.method == 'POST':
        action_type = request.form.get("action_type")

        if action_type == "update_bio" and bio_form.validate_on_submit():
            raw_bio = bio_form.bio.data
            safe_bio = bleach.clean(raw_bio, tags=[], attributes={}, strip=True)
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (safe_bio, session['user_id']))
            db.commit()
            flash('소개글이 업데이트되었습니다.')
            return redirect(url_for('profile'))

        elif action_type == "change_password" and password_form.validate_on_submit():
            current_pw = password_form.current_password.data
            new_pw = password_form.new_password.data

            if not current_pw or not new_pw:
                flash('비밀번호를 변경하려면 현재 비밀번호와 새 비밀번호를 모두 입력해야 합니다.')
                return redirect(url_for('profile'))

            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            db_pw = cursor.fetchone()

            if not db_pw or not check_password_hash(db_pw['password'], current_pw):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))

            hashed_pw = generate_password_hash(new_pw)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
            db.commit()
            session.pop('user_id', None)
            flash('비밀번호가 변경되었습니다. 다시 로그인 해주세요.')
            return redirect(url_for('login'))

    bio_form.bio.data = current_user['bio'] or ''

    return render_template(
        'profile.html',
        user=current_user,
        bio_form=bio_form,
        password_form=password_form,
        my_products=my_products 
    )



# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = NewProductForm()

    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        price = form.price.data

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html', form=form)


# 상품 상세보기
@app.route('/product/<product_id>')
@csrf.exempt
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ReportForm()

    if form.validate_on_submit():
        target_id = form.target_id.data
        raw_reason = form.reason.data

        # ✅ XSS 방어 필터링
        safe_reason = bleach.clean(raw_reason, tags=[], attributes={}, strip=True)

        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, safe_reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html', form=form)


@csrf.exempt
@app.route('/message/send/<receiver_id>', methods=['GET', 'POST'])
def send_message(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 쪽지를 받을 유저 정보 조회 (존재하는지 확인)
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    if not receiver:
        flash('받는 사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        content = request.form['content']
        message_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
            (message_id, session['user_id'], receiver_id, content)
        )
        db.commit()
        flash('쪽지를 보냈습니다.')
        return redirect(url_for('messages'))

    return render_template('send_message.html', receiver=receiver)


@csrf.exempt
@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 받은 쪽지 불러오기 (최근순)
    cursor.execute("""
        SELECT m.id, m.content, m.created_at, u.username AS sender_name
        FROM message m
        JOIN user u ON m.sender_id = u.id
        WHERE m.receiver_id = ?
        ORDER BY m.created_at DESC
    """, (session['user_id'],))
    messages = cursor.fetchall()

    return render_template('messages.html', messages=messages)


@csrf.exempt
@app.route('/message/<message_id>')
def view_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 내가 받은 쪽지만 열람 가능하게 제한
    cursor.execute("""
        SELECT m.*, u.username AS sender_name
        FROM message m
        JOIN user u ON m.sender_id = u.id
        WHERE m.id = ? AND m.receiver_id = ?
    """, (message_id, session['user_id']))
    
    message = cursor.fetchone()

    if not message:
        flash('쪽지를 찾을 수 없거나 접근 권한이 없습니다.')
        return redirect(url_for('messages'))

    return render_template('message_detail.html', message=message)


@csrf.exempt
@app.route('/message/compose', methods=['GET', 'POST'])
def compose_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        content = request.form['content']

        # 사용자명으로 상대 유저 ID 조회
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()

        if not receiver:
            flash('해당 사용자명을 찾을 수 없습니다.')
            return redirect(url_for('compose_message'))

        message_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
            (message_id, session['user_id'], receiver['id'], content)
        )
        db.commit()
        flash('쪽지를 보냈습니다.')
        return redirect(url_for('messages'))

    return render_template('compose_message.html')

@csrf.exempt
@app.route('/messages/sent')
def sent_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 보낸 쪽지 불러오기 (최근순)
    cursor.execute("""
        SELECT m.id, m.content, m.created_at, u.username AS receiver_name
        FROM message m
        JOIN user u ON m.receiver_id = u.id
        WHERE m.sender_id = ?
        ORDER BY m.created_at DESC
    """, (session['user_id'],))
    messages = cursor.fetchall()

    return render_template('sent_messages.html', messages=messages)



# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
@csrf.exempt
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)

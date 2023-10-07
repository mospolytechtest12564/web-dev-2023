import re
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL
import mysql.connector
PERMITED_PARAMS = ['login', 'password', 'last_name', 'first_name', 'middle_name', 'role_id']
EDIT_PARAMS = ['last_name', 'first_name', 'middle_name', 'role_id']
PASSWORD_PARAMS = ['old_password', 'new_password', 'repeat_new_password']

app = Flask(__name__)
application = app

app.config.from_pyfile('config.py')

db = MySQL(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице нужно авторизироваться.'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self, user_id, user_login):
        self.id = user_id
        self.login = user_login

@app.route('/')
def index():
    return render_template('index.html')

def check_pass_conditions_by_one(output_pass, error_pass, password):
    output_pass = "Пароль не соответствует следующим критериям: "
    crits = []
    
    if password is None:
        crits.append("1")
        error_pass = True
        output_pass += ", ".join(crits)
        return["Поле не должно быть пустым.", error_pass]


    if len(password) < 8 or len(password) > 128:
        crits.append("1")
        error_pass = True

    if not bool(re.search(r'[A-ZА-ЯЁ]', password)):
        crits.append("2")
        error_pass = True

    if not bool(re.search(r'[a-zа-яё]', password)):
        crits.append("3")
        error_pass = True

    if not bool(re.search(r'[A-ZА-ЯЁa-zа-яё]', password)):
        crits.append("4")
        error_pass = True

    if not bool(re.search(r'\d', password)):
        crits.append("5")
        error_pass = True

    if " " in password:
        crits.append("6")
        error_pass = True
    
    if crits == []:
        output_pass = ""
    else:
        output_pass += ", ".join(crits)
    return [output_pass, error_pass]



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = request.form.get('remember_me') == 'on'

        query = 'SELECT * FROM users WHERE login = %s and password_hash = SHA2(%s, 256);'

        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (login, password))
            print(cursor.statement)
            user = cursor.fetchone()

        if user:
            login_user(User(user.id, user.login), remember = remember)
            flash('Вы успешно прошли аутентификацию!', 'success')
            param_url = request.args.get('next')
            return redirect(param_url or url_for('index'))
        flash('Введён неправильный логин или пароль.', 'danger')
    return render_template('login.html')


@app.route('/users')
def users():
    query = 'SELECT users.*, roles.name AS role_name FROM users LEFT JOIN roles ON roles.id = users.role_id'
    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        users_list = cursor.fetchall()
    
    return render_template('users.html', users_list=users_list)

@app.route('/users/new')
@login_required
def users_new():
    roles_list = load_roles()
    return render_template('users_new.html', roles_list=roles_list, user={})

def load_roles():
    query = 'SELECT * FROM roles;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query)
    roles = cursor.fetchall()
    cursor.close()
    return roles

def extract_params(params_list):
    params_dict = {}
    for param in params_list:
        params_dict[param] = request.form[param] or None
    return params_dict

def check_params(params):
    output_login, output_pass, output_f_n, output_l_n = ("",) * 4      
    error_login, error_pass, error_f_n, error_l_n = (False,) * 4

    pattern_login = re.compile(r'^[0-9a-zA-Z]{5,50}$')
   
    if params["login"] == None:
        output_login = "Поле не должно быть пустым."
        error_login = True
    elif not bool(pattern_login.match(params["login"])):
        output_login = "Введенный логин не соответствует требованиям (длина должна быть больше 5)."
        error_login = True
    if params["password"] == None:
        output_pass = "Поле не должно быть пустым."
        error_pass = True
    [output_pass, error_pass] = check_pass_conditions_by_one(output_pass, error_pass, params['password'])

    if params["last_name"] == None:
        output_l_n = "Поле не должно быть пустым."
        error_l_n = True
    if params["first_name"] == None:
        output_f_n = "Поле не должно быть пустым."
        error_f_n = True
    
    if error_login == False and error_pass == False and error_f_n == False and error_l_n == False:
        return [True]
    else:
        return [False, render_template('users_new.html', user = params, roles_list = load_roles(), m = True,
                        output_login=output_login, error_login=error_login,
                        output_pass=output_pass, error_pass=error_pass,
                        output_f_n=output_f_n, error_f_n=error_f_n,
                        output_l_n=output_l_n, error_l_n=error_l_n)]

    

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_pass():
    method = False
    params = ["", "", ""]
    
    print("I'm here", current_user.login)
    output_old_pass, output_new_pass, output_repeat_pass = ("", ) * 3
    error_old_pass, error_new_pass, error_repeat_pass = (False, ) * 3
    if request.method == 'POST':
        method = True
        params = extract_params(PASSWORD_PARAMS)
        old_password =  request.form['old_password']
        new_password =  request.form['new_password']
        repeat_new_password =  request.form['repeat_new_password']
        print(old_password, new_password, repeat_new_password)
    
        if params['old_password'] == None:
            output_old_pass = "Поле не должно быть пустым."
            error_old_pass = True
        

        if params['new_password'] == None:
            output_new_pass = "Поле не должно быть пустым."
            error_new_pass = True
        
        [output_new_pass, error_new_pass] = check_pass_conditions_by_one(output_new_pass, error_new_pass, params['new_password'])

        if params['repeat_new_password'] == None:
            output_repeat_pass = "Поле не должно быть пустым."
            error_repeat_pass = True
        elif params['repeat_new_password'] != params['new_password']:
            output_repeat_pass = "Пароли не совпадают."
            error_repeat_pass = True
        elif params['repeat_new_password'] == params['new_password']:
            output_repeat_pass = output_new_pass
            error_repeat_pass = error_new_pass
        

        query = 'SELECT * FROM users WHERE login = %s and password_hash = SHA2(%s, 256);'

        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (current_user.login, params['old_password']))
            user = cursor.fetchone()
        
        if not error_new_pass and not error_repeat_pass and not error_old_pass:
            if user:
                query = 'UPDATE users SET password_hash=SHA2(%s, 256) WHERE login=%s;'
                try:
                    cursor = db.connection().cursor(named_tuple=True)
                    cursor.execute(query, ( params['new_password'], current_user.login))
                    db.connection().commit()
                    cursor.close()
                    flash('Пароль успешно изменен', 'success')
                    return redirect(url_for('index'))
                
                except mysql.connector.errors.DatabaseError:
                    db.connection().rollback()
                    flash('При изменении пароля возникла ошибка.', 'danger')
            else:
                flash('Введён неправильный пароль.', 'danger')
                error_old_pass = True


    return render_template('change_password.html', user = params, m=method, output_old_pass=output_old_pass, error_old_pass=error_old_pass,
                        output_new_pass=output_new_pass, error_new_pass=error_new_pass,
                        output_repeat_pass=output_repeat_pass, error_repeat_pass=error_repeat_pass)

@app.route('/users/create', methods=['POST'])
@login_required
def create_user():
    params = extract_params(PERMITED_PARAMS)

    check_res = check_params(params)
    if not check_res[0]:
        return check_res[1]

    else:
        query = 'INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id) VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(role_id)s);'
        print("query", query)
        try:
            with db.connection().cursor(named_tuple=True) as cursor:
                cursor.execute(query, params)
                db.connection().commit()
                flash('Успешно!', 'success')
        except mysql.connector.errors.DatabaseError:
            db.connection().rollback()
            flash('При сохранении данных возникла ошибка.', 'danger')
            return render_template('users_new.html', user = params, roles_list = load_roles())
    
    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
def update_user(user_id):
    params = extract_params(EDIT_PARAMS)
    print(params)
    output_f_n, output_l_n = ("",) * 2    
    error_f_n, error_l_n = (False,) * 2
    if params["last_name"] == None:
        output_l_n = "Поле не должно быть пустым."
        error_l_n = True
    if params["first_name"] == None:
        output_f_n = "Поле не должно быть пустым."
        error_f_n = True
    params['id'] = user_id
    query = ('UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, '
             'middle_name=%(middle_name)s, role_id=%(role_id)s WHERE id=%(id)s;')
    try:
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, params)
            db.connection().commit()
            flash('Успешно!', 'success')
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()
        flash('При сохранении данных возникла ошибка.', 'danger')
        return render_template('users_edit.html', user = params, roles_list = load_roles(), m = True,
                        output_f_n=output_f_n, error_f_n=error_f_n,
                        output_l_n=output_l_n, error_l_n=error_l_n)

    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/edit')
@login_required
def edit_user(user_id):
    query = 'SELECT * FROM users WHERE users.id = %s;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users_edit.html', user=user, roles_list = load_roles())


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    query = 'DELETE FROM users WHERE users.id=%s;'
    try:
        cursor = db.connection().cursor(named_tuple=True)
        cursor.execute(query, (user_id,))
        db.connection().commit()
        cursor.close()
        flash('Пользователь успешно удален', 'success')
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()
        flash('При удалении пользователя возникла ошибка.', 'danger')
    return redirect(url_for('users'))


@app.route('/user/<int:user_id>')
def show_user(user_id):
    query = 'SELECT users.id, users.login, users.password_hash, users.last_name, users.first_name, users.middle_name, r.name, users.created_at '\
            'FROM users ' \
            'INNER JOIN roles as r on r.id = users.role_id '\
            'WHERE users.id = %s;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users_show.html', user=user)

@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('index'))

@login_manager.user_loader
def load_user(user_id):
    query = 'SELECT * FROM users WHERE users.id = %s;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return User(user.id, user.login)
    return None

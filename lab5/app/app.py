
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from mysql_db import MySQL
import mysql.connector
import re
PERMITED_PARAMS = ['login', 'password', 'last_name', 'first_name', 'middle_name', 'role_id']
EDIT_PARAMS = ['last_name', 'first_name', 'middle_name', 'role_id']

app = Flask(__name__)
application = app

app.config.from_pyfile('config.py')

db = MySQL(app)

from auth import bp as auth_bp
from auth import init_login_manager, permission_check

from visits import bp as visits_bp

app.register_blueprint(auth_bp)
init_login_manager(app)

app.register_blueprint(visits_bp)

@app.before_request
def loger():
    if request.endpoint == 'static':
        return
    path = request.path
    user_id = getattr(current_user, 'id', None)
    query = 'INSERT INTO visit_logs(user_id, path) VALUES (%s, %s);'
    try:
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (user_id, path))
            db.connection().commit()
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users')
def users():
    query = 'SELECT users.*, roles.name AS role_name FROM users LEFT JOIN roles ON roles.id = users.role_id'
    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        users_list = cursor.fetchall()
    
    return render_template('users.html', users_list=users_list)

@app.route('/users/new')
@login_required
@permission_check('create')
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
        params_dict[param] = request.form.get(param, None)
    return params_dict


def check_pass_conditions_by_one(output_pass, error_pass, password):
    output_pass = "Пароль не соответствует следующим критериям: "
    crits = []
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
    
    [output_pass, error_pass] = check_pass_conditions_by_one(output_pass, error_pass, params['password'])
    if params["password"] == "":
        output_pass = "Поле не должно быть пустым."
        error_pass = True
    
    if params["last_name"] == "":
        print("last name")
        output_l_n = "Поле не должно быть пустым."
        error_l_n = True
    if params["first_name"] == "":
        print("first name")
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


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@permission_check('create')
def create_user():
    params = extract_params(PERMITED_PARAMS)
    check_res = check_params(params)
    if not check_res[0]:
        return check_res[1]
    query = 'INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id) VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(role_id)s);'
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

# create_user = login_required(create_user)

@app.route('/users/<int:user_id>/update', methods=['GET', 'POST'])
@login_required
@permission_check('edit')
def update_user(user_id):
    params = extract_params(EDIT_PARAMS)
    params['id'] = user_id
    if not params['last_name'] or not params['first_name']:
        flash('При редактировании пользователя возникла ошибка: пустое поле(я).', 'danger')
        return render_template('users_edit.html', user = params, roles_list = load_roles())
    if current_user.can('change_role'):
        query = ('UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, '
                'middle_name=%(middle_name)s, role_id=%(role_id)s WHERE id=%(id)s;')
    else:
        del params['role_id']
        query = ('UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, '
                'middle_name=%(middle_name)s WHERE id=%(id)s;')
    try:
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, params)
            db.connection().commit()
            flash('Успешно!', 'success')
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()
        flash('При сохранении данных возникла ошибка.', 'danger')
        return render_template('users_edit.html', user = params, roles_list = load_roles())

    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/edit')
@login_required
@permission_check('edit')
def edit_user(user_id):
    query = 'SELECT * FROM users WHERE users.id = %s;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users_edit.html', user=user, roles_list = load_roles())


@app.route('/users/<int:user_id>/delete', methods=['GET', 'POST'])
@login_required
@permission_check('delete')
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
@permission_check('show')
def show_user(user_id):
    query = 'SELECT * FROM users WHERE users.id = %s;'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users_show.html', user=user)



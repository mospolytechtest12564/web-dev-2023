
from flask import render_template, Blueprint, request, send_file, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app import db, app
from math import ceil
import csv
from auth import permission_check
PER_PAGE = 10

bp = Blueprint('visits', __name__, url_prefix='/visits')

@bp.route('/')
@login_required
def logging():
    page = request.args.get('page', 1, type = int)
    role = getattr(current_user, 'role_id')
    if role == 1:
        query = 'SELECT visit_logs.*, users.login '\
                'FROM users RIGHT JOIN visit_logs ON visit_logs.user_id = users.id '\
                'ORDER BY created_at DESC LIMIT %s OFFSET %s '
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (PER_PAGE, (page-1)*PER_PAGE))
            logs = cursor.fetchall()
        query = 'SELECT COUNT(*) AS count FROM visit_logs'
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query)
            count = cursor.fetchone().count
    elif role == 2:
        query = 'SELECT visit_logs.*, users.login '\
                'FROM users RIGHT JOIN visit_logs ON visit_logs.user_id = users.id '\
                'WHERE users.id = %s '\
                'ORDER BY created_at DESC LIMIT %s OFFSET %s '
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (getattr(current_user, 'id'), PER_PAGE, (page-1)*PER_PAGE))
            logs = cursor.fetchall()
        query = 'SELECT COUNT(*) AS count '\
                'FROM users RIGHT JOIN visit_logs ON visit_logs.user_id = users.id '\
                'WHERE users.id = %s '
        with db.connection().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (getattr(current_user, 'id'),))
            count = cursor.fetchone().count
    
    last_page = ceil(count/PER_PAGE)

    return render_template('visits/logs.html', start_index = (page-1)*10, logs = logs, last_page = last_page, current_page = page)


@bp.route('/pages')
@login_required
@permission_check('look_statistic')
def statistic_pages():
    page = request.args.get('page', 1, type = int)
    query = 'SELECT path, COUNT(path) as count FROM visit_logs GROUP BY path '\
            'ORDER BY count DESC LIMIT %s OFFSET %s;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (PER_PAGE, (page-1)*PER_PAGE))
        logs = cursor.fetchall()
    
    query = 'SELECT COUNT(DISTINCT path) AS count FROM visit_logs;'
    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        count = cursor.fetchone().count
    
    last_page = ceil(count/PER_PAGE)
    return render_template('visits/logs_pages.html', start_index = (page-1)*10, logs = logs, last_page = last_page, current_page = page)

@bp.route('/users')
@login_required
@permission_check('look_statistic')
def statistic_users():
    page = request.args.get('page', 1, type = int)
    query = 'SELECT CONCAT(u.last_name, " ", u.first_name, " ", COALESCE(u.middle_name,"")) AS login, COUNT(login) as count '\
            'FROM visit_logs AS v '\
            'LEFT JOIN users AS u ON u.id = v.user_id '\
            'GROUP BY login '\
            'ORDER BY count DESC LIMIT %s;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (PER_PAGE,))
        logs = cursor.fetchall()
    logs = logs[:-1]
            
    query = 'SELECT COUNT(*) AS count FROM visit_logs AS v LEFT JOIN users AS u ON u.id = v.user_id WHERE login IS NULL;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        anon = cursor.fetchone().count
    anonymous = {"login" : "Анонимный пользователь","count" : anon}
   
    if logs[-1].count >= anon:
        logs.append(anonymous)
    else:
        for i in range(len(logs) - 1):
            if logs[i].count >= anon and logs[i + 1].count <= anon :
                logs.insert(i+1, anonymous)   
                break
            

    query = 'SELECT COUNT(DISTINCT login) AS count FROM visit_logs AS v '\
            'LEFT JOIN users AS u ON u.id = v.user_id;'
    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        count = cursor.fetchone().count
    
    last_page = ceil(count/PER_PAGE)
    return render_template('visits/logs_users.html', start_index = (page-1)*10, logs = logs, last_page = last_page, current_page = page)


@bp.route('/pages/download')
@login_required
@permission_check('download_statistic')
def download_statistic_pages():
    print("ready to download")
    query = 'SELECT path, COUNT(path) as count FROM visit_logs GROUP BY path '\
            'ORDER BY count DESC;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        logs = cursor.fetchall()
    stat = []
    for i in range(len(logs)):
        log = {"Num" : i+1, "page" : logs[i].path, "visits_count" : logs[i].count}
        stat.append(log)
    
    with open("statistic.csv", "w", newline="") as csv_file:
        columns = ["Num", "page", "visits_count"]
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(stat)

    path = 'statistic.csv'
    return send_file(path, as_attachment=True)


@bp.route('/users/download')
@login_required
@permission_check('download_statistic')
def download_statistic_users():
    query = 'SELECT CONCAT(u.last_name, " ", u.first_name, " ", COALESCE(u.middle_name,"")) AS login, COUNT(login) as count '\
            'FROM visit_logs AS v '\
            'LEFT JOIN users AS u ON u.id = v.user_id '\
            'GROUP BY login '\
            'ORDER BY count DESC;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        logs = cursor.fetchall()
    logs = logs[:-1]
            
    query = 'SELECT COUNT(*) AS count FROM visit_logs AS v LEFT JOIN users AS u ON u.id = v.user_id WHERE login IS NULL;'

    with db.connection().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        anon = cursor.fetchone().count
    anonymous = {"login" : "Анонимный пользователь","count" : anon}
    
    if logs[-1].count >= anon:
        logs.append(anonymous)
    else:
        for i in range(len(logs) - 1):
            if logs[i].count >= anon and logs[i + 1].count <= anon :
                logs.insert(i+1, anonymous)   
                break
            
    print(logs)
    stat = []
    for i in range(len(logs)):
        if type(logs[i]) == dict:
            log = {"Num" : i+1, "user" : logs[i].get("login"), "visits_count" : logs[i].get("count")}
        else:
            log = {"Num" : i+1, "user" : logs[i].login, "visits_count" : logs[i].count}
        stat.append(log)
    
    with open("statistic.csv", "w", newline="") as csv_file:
        columns = ["Num", "user", "visits_count"]
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(stat)

    path = 'statistic.csv'
    return send_file(path, as_attachment=True)
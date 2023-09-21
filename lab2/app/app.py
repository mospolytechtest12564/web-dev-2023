from flask import Flask, render_template, request
from flask import make_response
import re

app = Flask(__name__)
application = app

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/headers')
def headers():
    return render_template('headers.html')

@app.route('/args')
def args():
    return render_template('args.html')

@app.route('/cookies')
def cookies():
    resp = make_response(render_template('cookies.html'))
    if "name" in request.cookies:
        resp.delete_cookie("name")
    else:
        resp.set_cookie("name", "value")
    return resp

@app.route('/form', methods=['GET', 'POST'])
def form():
    return render_template('form.html')


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

@app.route('/form_number', methods=['GET', 'POST'])
def form_number():
    text = ''
    is_error = False
    if request.method=='POST':

        phone_number = request.form['number'].replace(' ', '')
        
        for symbol in phone_number:
            if symbol not in ["+", "(", ")", "-", ".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                text = 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'
                is_error = True
                break
            
        phone_number = re.sub('[^0-9]', '', phone_number)

        if not is_error:
            if len(phone_number) == 10:
                text = f"8-{phone_number[0:3]}-{phone_number[3:6]}-{phone_number[6:8]}-{phone_number[8:10]}"
            elif len(phone_number) == 11:
                text = f"8-{phone_number[1:4]}-{phone_number[4:7]}-{phone_number[7:9]}-{phone_number[9:11]}"
            else:
                text = 'Недопустимый ввод. Неверное количество цифр.'
                is_error = True

    return render_template('form_number.html', output=text, error=is_error)

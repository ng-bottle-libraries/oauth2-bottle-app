from random import randint

from bottle import Bottle, response, request
from mongoengine.errors import NotUniqueError, ValidationError
from rfc6749.oauth2_errors import OAuth2Error, error
from rfc6749.Tokens import AccessToken
from namespace_models.User import User
from namespace_utils.validators import is_email
from namespace_utils.bottle_helpers import from_params_or_json

oauth2_app = Bottle(catchall=False, autojson=True)

__version__ = '0.0.9'


def oauth2_error_catcher(environ, start_response):
    try:
        return oauth2_app.wsgi(environ, start_response)
    except OAuth2Error as e:
        message = dict(e.message)
        response.status = message.pop('status_code')
        return message


@oauth2_app.hook('after_request')
def enable_cors():
    response.headers['Access-Control-Allow-Origin'] = '*'


def oauth2_secured():
    """ Decorator to validate token.

        if valid: return route decorated
        else: provide relevant OAuth2 error
    """

    def decorate(f):
        def wrapped(*args, **kwargs):
            try:
                if AccessToken.objects(token=from_params_or_json(request, 'access_token')).first():
                    return f(*args, **kwargs)
                raise OAuth2Error('expired_token')
            except OAuth2Error as e:
                message = dict(e.message)
                response.status = message.pop('status_code')
                return message

        return wrapped

    return decorate


@oauth2_app.route('/api/oauth2/register_or_login', method=['GET', 'POST', 'PUT', 'OPTIONS'])
def register_or_login():
    """ Registers or logs in the user, always returning access_token on success """
    email = from_params_or_json(request, 'email')
    email = email if is_email(email) else ''
    password = from_params_or_json(request, 'password')
    grant_type = from_params_or_json(request, 'grant_type') or 'password'
    # meta = from_params_or_json(request, 'meta')

    register_resp = register(email, password)
    if register_resp.get('error_description') == "Email already registered":  # the lookup first approach fails
        response.status = 200
        return login(email, password, grant_type)
    elif 'access_token' in register_resp:
        return register_resp

    return error(response, 'server_error', "Registration failed")


@oauth2_app.route('/api/oauth2/register', method=['POST', 'PUT'])
def register(email=None, password=None):
    email = from_params_or_json(request, 'email') or email
    email = email if is_email(email) else ''
    password = from_params_or_json(request, 'password') or password

    if not email or not password:
        return error(response, 'invalid_request', "`email` and `password` required")
    try:
        registered = User(email=email, password=password).register()
        if registered:
            tok = AccessToken(user=registered).generate()
            return {'access_token': tok.token,
                    'expires_in': randint(0, 200)}
    except NotUniqueError:
        return error(response, 'access_denied', "Email already registered")
    except ValidationError as e:
        return error(response, 'invalid_request', e.message)
    except OAuth2Error as e:
        message = dict(e.message)
        response.status = message.pop('status_code')
        return message

    return error(response, 'server_error', "Registration failed")


@oauth2_app.route('/api/oauth2/login')
def login(email=None, password=None, grant_type=None):
    email = from_params_or_json(request, 'email') or email
    email = email if is_email(email) else ''
    password = from_params_or_json(request, 'password') or password
    grant_type = from_params_or_json(request, 'grant_type') or grant_type

    try:
        if email and password and grant_type == 'password':
            login_resp = User(email=email, password=password).login()
            if login_resp and 'access_token' in login_resp:
                return login_resp
            return error(response, 'server_error', "Login failed")
        else:
            return error(response, 'invalid_request', "`email`, `password` and `grant_type='password'` required")
    except OAuth2Error as e:
        message = dict(e.message)
        response.status = message.pop('status_code')
        return message


@oauth2_app.route('/api/oauth2/logout', method=['GET', 'DELETE'])
def logout():
    access_token = from_params_or_json(request, 'access_token')
    try:
        User().logout(access_token=access_token)
        return {'logged_out': True}
    except OAuth2Error as e:
        message = dict(e.message)
        response.status = message.pop('status_code')
        return message


@oauth2_app.route('/api/oauth2/unregister', method='DELETE')
def unregister():
    email = from_params_or_json(request, 'email')
    email = email if is_email(email) else ''
    password = from_params_or_json(request, 'password')

    try:
        User(email=email, password=password).unregister()
    except OAuth2Error:
        pass

    response.status = 204
    # DO NOT return anything; 204s shouldn't


@oauth2_app.route('/api/meta', method=['GET', 'POST', 'PUT', 'OPTIONS'])
def meta():
    return {'request.params': request.params.dict,
            'request.query': request.query.dict,
            'request.json.keys()': request.json.keys() if request.json else []}


@oauth2_app.route('/api/secrets')
@oauth2_secured()
def secrets():
    return {'my_secret': 'is_out!'}


if __name__ == '__main__':
    # run(app=oauth2_error_catcher, debug=True)
    oauth2_app.run(host='0.0.0.0', port=5555, debug=True)

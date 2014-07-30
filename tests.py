from unittest import TestCase, main as unittest_main

from webtest import TestApp, AppError
from namespace_utils.test_class import Test

from oauth2_bottle_app import oauth2_app


class TestFunctionalOAuth2PasswordCredentialsGrant(TestCase):
    app = TestApp(oauth2_app)
    users = ({'email': 'foo', 'password': 'bar'},
             {'email': 'foo@bar.com', 'password': 'haz'},
             {'email': 'bar@foo.com', 'password': 'can'})
    access_token = ''

    def test_0_meta(self):
        register_resp = self.app.get('/api/meta')
        self.assertEqual(register_resp.content_type, 'application/json')
        self.assertEqual(register_resp.status_code, 200)

    def test_1_register_failure(self):
        self.assertRaises(AppError, lambda: self.app.post('/api/oauth2/register', params=self.users[0]))
        register_resp = self.app.post('/api/oauth2/register', params=self.users[0], expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), register_resp.json.keys())
        self.assertNotEqual(register_resp.status_code, 200)

    def test_1_register_success(self):
        register_resp = self.app.post('/api/oauth2/register', params=self.users[1])
        self.assertEqual(register_resp.content_type, 'application/json')
        self.assertEqual(register_resp.status_code, 200)
        self.assertIn('access_token', register_resp.json)
        self.assertIn('expires_in', register_resp.json)

        # Save access token
        self.__class__.access_token = register_resp.json['access_token']

    def test_2_login_failure(self):
        self.assertRaises(AppError, lambda: self.app.get('/api/oauth2/login', params=self.users[1]))
        login_resp = self.app.get('/api/oauth2/login', params=self.users[1], expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), login_resp.json.keys())
        self.assertNotEqual(login_resp.status_code, 200)

    def test_2_login_success(self):
        login_resp = self.app.get('/api/oauth2/login', params=dict(grant_type='password', **self.users[1]))
        self.assertEqual(login_resp.content_type, 'application/json')
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn('access_token', login_resp.json)
        self.assertIn('expires_in', login_resp.json)

        # Save access token
        self.__class__.access_token = login_resp.json['access_token']

    def test_3_register_or_login_failure_register(self):
        self.assertRaises(AppError, lambda: self.app.put('/api/oauth2/register_or_login', self.users[0]))
        register_or_login_resp = self.app.put('/api/oauth2/register_or_login', self.users[0], expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), register_or_login_resp.json.keys())
        self.assertNotEqual(register_or_login_resp.status_code, 200)

    def test_3_register_or_login_success_register(self):
        register_or_login_resp = self.app.put('/api/oauth2/register_or_login', self.users[2])
        self.assertEqual(register_or_login_resp.content_type, 'application/json')
        self.assertEqual(register_or_login_resp.status_code, 200)
        self.assertIn('access_token', register_or_login_resp.json)
        self.assertIn('expires_in', register_or_login_resp.json)

        # Save access token
        self.__class__.access_token = register_or_login_resp.json['access_token']

    def test_3_register_or_login_failure_login(self):
        bad_user = self.users[1].copy()
        bad_user['password'] = 'fooooooooooo wrong'
        register_or_login_resp = self.app.post('/api/oauth2/register_or_login', bad_user, expect_errors=True)

        self.assertGreater(register_or_login_resp.content_length, 0)
        self.assertItemsEqual(('error', 'error_description'), register_or_login_resp.json.keys())
        self.assertNotEqual(register_or_login_resp.status_code, 200)

    def test_3_register_or_login_success_login(self):
        register_or_login_resp = self.app.put('/api/oauth2/register_or_login', self.users[1])
        self.assertEqual(register_or_login_resp.content_type, 'application/json')
        self.assertEqual(register_or_login_resp.status_code, 200)
        self.assertIn('access_token', register_or_login_resp.json)
        self.assertIn('expires_in', register_or_login_resp.json)

        # Save access token
        self.__class__.access_token = register_or_login_resp.json['access_token']

    def test_4_access_token_failure(self):
        """ Attempt to access protected resource """
        self.assertRaises(AppError, lambda: self.app.get('/api/secrets', params={'access_token': 'da24ab3c5'}))
        tok_resp = self.app.get('/api/secrets', params={'access_token': 'da24ab3c5'}, expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), tok_resp.json.keys())
        self.assertNotEqual(tok_resp.status_code, 200)

    def test_4_access_token_success(self):
        """ Access protected resource """
        tok_resp = self.app.get('/api/secrets', params=dict(access_token=self.__class__.access_token))
        self.assertEqual(tok_resp.content_type, 'application/json')
        self.assertEqual(tok_resp.status_code, 200)

    def test_5_logout_failure(self):
        self.assertRaises(AppError, lambda: self.app.delete('/api/oauth2/logout', params={'access_token': 'da24ab3c5'}))
        logout_resp = self.app.delete('/api/oauth2/logout', params={'access_token': 'da24ab3c5'}, expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), logout_resp.json.keys())
        self.assertNotEqual(logout_resp.status_code, 200)

    def test_5_logout_success(self):
        access_token = {'access_token': self.__class__.access_token}
        logout_resp = self.app.delete('/api/oauth2/logout', params=access_token)
        self.assertEqual(logout_resp.content_type, 'application/json')
        self.assertEqual(logout_resp.status_code, 200)
        self.assertEqual(logout_resp.json, {'logged_out': True})

        # Confirm access token is invalidated
        self.assertRaises(AppError, lambda: self.app.get('/api/secrets', params=access_token))
        tok_resp = self.app.get('/api/secrets', params=access_token, expect_errors=True)
        self.assertItemsEqual(('error', 'error_description'), tok_resp.json.keys())
        self.assertNotEqual(tok_resp.status_code, 200)

    @classmethod
    def tearDownClass(cls):
        unregister_resps = (cls.app.delete('/api/oauth2/unregister', params=cls.users[1]),
                            cls.app.delete('/api/oauth2/unregister', params=cls.users[2]))
        for unregister_resp in unregister_resps:
            self = Test()
            self.assertEqual(got=unregister_resp.content_type, expect=None)
            self.assertEqual(got=unregister_resp.status, expect="204 No Content")


if __name__ == '__main__':
    unittest_main()

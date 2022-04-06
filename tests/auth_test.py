import pytest
import flask_wtf
import flask_login
from flask import session
from app.db.models import User

"""This test the homepage"""

def test_request_main_menu_links(client):
    """This makes the index page"""
    response = client.get("/")
    assert response.status_code == 200
    assert b'href="/login"' in response.data
    assert b'href="/register"' in response.data

def test_auth_pages(client):
    """This makes the index page"""
    response = client.get("/dashboard")
    assert response.status_code == 302
    response = client.get("/register")
    assert response.status_code == 200
    response = client.get("/login")
    assert response.status_code == 200

# Test 4 Password check
def test_register_matchingPasswords(client):
    #Test that mismatching passwords are correctly handled
    response = client.post("/register", data={"email": "test@mail.com", "password": "testpassword", "confirm": ""})
    assert b'Passwords must match' in response.data
    # Test that mismatching passwords are correctly handled even if the field is not empty
    response = client.post("/register", data={"email": "test@mail.com", "password": "testpassword", "confirm": "test2"})
    assert b'Passwords must match' in response.data

# Test 8, does registration work
def test_register(client):
    assert client.get("/register").status_code == 200
    response = client.post("/register", data={"email": "test@mail.com", "password": "testpassword", "confirm": "testpassword"})
    with client.application.app_context():
        user_id = User.query.filter_by(email="test@mail.com").first().get_id()
    #check if the user is redirected properly
    assert "/login" == response.headers["Location"]
    #check if the user is in the database
    assert user_id is not None

# Test 7, does login work
def test_login(client):
    with client:
        assert client.get("/login").status_code == 200
        response = client.post("/login", data={"email": "test@mail.com", "password": "testpassword", "confirm": "testpassword"})
        #test that the user is redirected to the dashboard
        assert "/dashboard" == response.headers["Location"]
        #test that the session has the correct user id
        with client.application.app_context():
            user_id = User.query.filter_by(email="test@mail.com").first().get_id()
        assert session['_user_id'] == user_id

#Tests 1 and 2, bad password and username/email for login

@pytest.mark.parametrize(
    ("email", "password"),
    (
        ("EmailNotInDatabase", "PasswordNotInDatabase"),
        ("test@mail.com", "PasswordNotInDatabase")
    )
)
def test_badLogin(client, email, password):
    assert client.get("/login").status_code == 200
    response = client.post("/login", data={"email": email, "password": password})
    #if the login is invalid, the user should remain on the login page
    assert "/login" == response.headers["Location"]

#tests 3 and 5, bad username and email for registration + bad password criteria
@pytest.mark.parametrize(
    ("email", "password", "confirm"),
    (
        ("a", "a", "a"),
        ("a@", "a", "a"),
        ("a@mail.com", "a", "a")
    )
)
def test_badRegistration(client, email, password, confirm):
    assert client.get("/register").status_code == 200
    response = client.post("/register", data={"email": email, "password": password, "confirm": confirm})
    #if invalid registration data is inputted, the user should return to the registration page
    assert "/login" == response.headers["Location"]

#Test 6, is the user already registered
def test_alreadyRegistered(client):
    with client:
        assert client.get("/register").status_code == 200
        response = client.post("/register", data={"email": "test@mail.com", "password": "testpassword", "confirm": "testpassword"})
        assert client.get("/register").status_code == 200
        response_2 = client.post("/register", data={"email": "test@mail.com", "password": "testpassword", "confirm": "testpassword"})
        #The user should now be redirected back to the registration
        assert "/login" == response_2.headers["Location"]


#test 10, acess to dashboard for logged in users
def test_dashboardAccess(client):
    assert client.get("/login").status_code == 200
    response = client.post("/login", data={"email": "test@mail.com", "password": "testpassword", "confirm": "testpassword"})
    #test that the user is redirected to the dashboard
    assert "/dashboard" == response.headers["Location"]
    #test that the dashboard loads
    assert client.get("/dashboard").status_code == 200

#test 9, deny dashboard to users not logged in
def test_dashboardDenied(client):
    response = client.get("/dashboard")
    #users not logged in should be redirected to the login
    assert "/login?next=%2Fdashboard" == response.headers["Location"]

import pytest
from flask import g
from flask import session

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
    
# Password Confirmation - Unit Test 4
def test_register_matchingPasswords(client):
    #Test that mismatching passwords are correctly handled
    response = client.post("/register", data={"email": "admin@mail.com", "password": "a", "confirm": ""})
    assert b"Passwords must match" in response.data
    # Test that mismatching passwords are correctly handled even if the field is not empty
    response = client.post("/register", data={"email": "admin@mail.com", "password": "a", "confirm": "b"})
    assert b"Passwords must match" in response.data

# Successful Registration - Unit Test 8
def test_register(client):
    assert client.get("/register").status_code == 200
    response = client.post("/register", data={"email": "admin@mail.com", "password": "abcdef", "confirm": "abcdef"})
    with client.application.app_context():
        user_id = User.query.filter_by(email="admin@mail.com").first().get_id()
    #check if the user is redirected properly
    assert "/login" == response.headers["Location"]
    #check if the user is in the database
    assert user_id is not None

# Successful Login - Unit Test 7
def test_login(client):
    with client:
        assert client.get("/login").status_code == 200
        response = client.post("/login", data={"email": "admin@mail.com", "password": "abcdef", "confirm": "abcdef"})
        #test that the user is redirected to the dashboard
        assert "/dashboard" == response.headers["Location"]
        #test that the session has the correct user id
        with client.application.app_context():
            user_id = User.query.filter_by(email="admin@mail.com").first().get_id()
        assert session['_user_id'] == user_id

#Bad password (Login), Bad username/email (Login) - Unit tests 1 and 2
@pytest.mark.parametrize(
    ("email", "password"),
    (
        ("EmailNotInDatabase", "PasswordNotInDatabase"),
        ("admin@mail.com", "PasswordNotInDatabase")
    )
)
def test_badLogin(client, email, password):
    assert client.get("/login").status_code == 200
    response = client.post("/login", data={"email": email, "password": password})
    #if the login is invalid, the user should remain on the login page
    assert "/login" == response.headers["Location"]

#Bad username (registration), Bad Password (does not meet criteria; registration) - Unit test 3 and 5
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

#Test if a user is already registered - Unit test 6
def test_alreadyRegistered(client):
    with client:
        assert client.get("/register").status_code == 200
        response = client.post("/register", data={"email": "admin@mail.com", "password": "abcdef", "confirm": "abcdef"})
        assert client.get("/register").status_code == 200
        response_2 = client.post("/register", data={"email": "admin@mail.com", "password": "abcdef", "confirm": "abcdef"})
        #The user should now be redirected back to the registration
        assert "/login" == response_2.headers["Location"]


#Access the dashboard for logged in users - Unit test 10
def test_dashboardAccess(client):
    assert client.get("/login").status_code == 200
    response = client.post("/login", data={"email": "admin@mail.com", "password": "abcdef", "confirm": "abcdef"})
    #test that the user is redirected to the dashboard
    assert "/dashboard" == response.headers["Location"]
    #test that the dashboard loads
    assert client.get("/dashboard").status_code == 200

#Deny Access to the dashboard for users not logged in - Unit test 9
def test_dashboardDenied(client):
    response = client.get("/dashboard")
    #users not logged in should be redirected to the login
    assert "/login?next=%2Fdashboard" == response.headers["Location"]

# Оксана Паскида

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200


def test_get_users():
    response = client.get("/users/")
    assert response.status_code == 200 or 404


def test_create_user():
    response = client.post("/register/",
                           json={"username": "testuser", "email": "testuser@example.com", "full_name": "Test User",
                                 "password": "password123"}, )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"


def test_register_new_user():
    new_user_data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "secure_password_123"
    }

    response = client.post("/register/", json=new_user_data)

    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "newuser"
    assert user_data["email"] == "newuser@example.com"


def test_duplicate_username_registration():
    duplicate_user_data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "secure_password_123"
    }

    response = client.post("/register/", json=duplicate_user_data)

    assert response.status_code == 400


def test_duplicate_email_registration():
    duplicate_email_data = {
        "username": "newuser_",
        "email": "newuser@example.com",
        "full_name": "New User _",
        "password": "secure_password_1234"
    }

    response = client.post("/register/", json=duplicate_email_data)

    assert response.status_code == 400


def test_successful_login():
    global access_token
    login_data = {"grant_type": "password", "username": "newuser", "password": "secure_password_123"}

    response = client.post("/token", data=login_data, headers={"Content-Type": "application/x-www-form-urlencoded"})

    data = response.json()
    access_token = 'Bearer ' + data['access_token']

    assert response.status_code == 200


def test_failed_login_incorrect_username():
    wrong_login_data = {"username": "string1", "password": "string"}

    response = client.post("/token", data=wrong_login_data)

    assert response.status_code == 401


def test_failed_login_wrong_password():
    incorrect_password_data = {"username": "string", "password": "string1"}

    response = client.post("/token", data=incorrect_password_data)

    assert response.status_code == 401


def test_invalid_or_expired_token():
    expired_token_headers = {"Authorization": ""}

    response = client.get("/users/me", headers=expired_token_headers)

    assert response.status_code == 401


def test_get_all_users():
    response = client.get("/users/")

    assert response.status_code == 200
    users_list = response.json()
    assert isinstance(users_list, list)
    assert len(users_list) >= 1
    first_user = users_list[0]
    assert "username" in first_user and "email" in first_user


def test_get_current_user_with_valid_token():
    global user_id
    valid_token_headers = {"Authorization": access_token}

    response = client.get("/users/me", headers=valid_token_headers)

    data = response.json()
    user_id = data['id']

    assert response.status_code == 200


def test_update_user_details():
    global access_token

    update_data = {"username": "Updated_username", "email": "updated_email@example.com",
                   "full_name": "Updated Full Name", "password": "updated_password_123"}
    valid_token_headers = {"Authorization": access_token}

    response = client.put(f"/users/{user_id}", json=update_data, headers=valid_token_headers)

    login_data = {"grant_type": "password", "username": "Updated_username", "password": "updated_password_123"}

    response_ = client.post("/token", data=login_data, headers={"Content-Type": "application/x-www-form-urlencoded"})

    data = response_.json()
    access_token = 'Bearer ' + data['access_token']

    assert response.status_code == 200


def test_update_user_with_invalid_data():
    invalid_update_data = {"username": 1}
    valid_token_headers = {"Authorization": access_token}

    response = client.put(f"/users/{user_id}", json=invalid_update_data, headers=valid_token_headers)

    assert response.status_code == 422


def test_unauthorized_update_user():
    unauthorized_headers = {}

    response = client.put(f"/users/{user_id}", json={}, headers=unauthorized_headers)

    assert response.status_code == 401


def test_delete_user():
    valid_token_headers = {"Authorization": access_token}

    response = client.delete(f"/users/{user_id}", headers=valid_token_headers)

    assert response.status_code == 200


def test_repeated_deletion_of_deleted_user():
    valid_token_headers = {"Authorization": access_token}

    response = client.delete(f"/users/{user_id}", headers=valid_token_headers)

    assert response.status_code == 401 or response.status_code == 404

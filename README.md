# Sense User Management System

**Sense** is a user management system built using Flask, SQLAlchemy, and Flask-Login. It provides a secure and efficient way to manage users, their roles, and bans. The system includes features such as login/logout functionality, user role management, banning/unbanning users, and more.

## Features

- **User Authentication**: Sense ensures secure user authentication with hashed passwords, protecting user credentials.
- **Role-Based Access Control**: Users are assigned roles, with administrators having special privileges. Regular users and banned users are managed accordingly.
- **User Panel**: The system provides a user panel for both regular users and administrators, each with a tailored interface.
- **Banning/Unbanning Users**: Administrators can easily ban and unban users, controlling access to the system.
- **RESTful API**: Sense offers a simple RESTful API (`/loginme`) for programmatic user authentication.

## Getting Started

### Prerequisites

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/V1ERA/Sense-Flask.git
    cd Sense-Flask
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the application:

    ```bash
    python app.py
    ```

Visit [http://localhost:8000](http://localhost:8000) to access the **Sense User Management System**.

## Usage

- **Login**: Access the system through the login page using your credentials.
- **User Panel**: Navigate through the user panel to manage users, roles, and access privileges.
- **Banning Users**: Administrators can ban users, preventing them from accessing the system.
- **RESTful API**: Use the `/loginme` endpoint for programmatic authentication.

## Acknowledgments

Special thanks to the Flask, SQLAlchemy, and Flask-Login communities for providing the tools and inspiration to build **Sense**.

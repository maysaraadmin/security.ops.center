"""
User Model
----------
Defines the User model for authentication and authorization.
"""
from flask_login import UserMixin

class User(UserMixin):
    """User model for authentication and authorization."""
    
    def __init__(self, user_data):
        """Initialize a user with the given user data."""
        self.id = str(user_data.get('username'))
        self.username = user_data.get('username')
        self.role = user_data.get('role', 'user')
        self.email = user_data.get('email', '')
        self.full_name = user_data.get('full_name', '')
        self.is_active = user_data.get('is_active', True)
        self.is_admin = self.role == 'admin'
    
    def get_id(self):
        """Return the user ID as a string."""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Check if the user is authenticated."""
        return True
    
    @property
    def is_anonymous(self):
        """Check if the user is anonymous."""
        return False
    
    @classmethod
    def get(cls, user_id):
        """Get a user by ID."""
        # In a real app, this would query the database
        from ...web.auth import USERS
        user_data = USERS.get(user_id)
        if user_data:
            user_data['username'] = user_id
            return cls(user_data)
        return None

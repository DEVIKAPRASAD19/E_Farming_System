from django.db import models
from django.contrib.auth.hashers import make_password, check_password


# Define the choices for the Role field
ROLE_CHOICES = [
    ('farmer', 'Farmer'),
    ('buyer', 'Buyer'),
]

class Registeruser(models.Model):
    # Additional fields
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    contact = models.CharField(max_length=15)
    place = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    reset_token = models.CharField(max_length=100, blank=True, null=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    




""" from django.db import models

class Crop(models.Model):
    CROP_CATEGORIES = [
        ('Vegetable', 'Vegetable'),
        ('Fruit', 'Fruit'),
        ('Grain', 'Grain'),
        ('Herb', 'Herb'),
        ('Other', 'Other'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='crop_images/')
    category = models.CharField(max_length=50, choices=CROP_CATEGORIES)
    added_by = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name """




from django.db import models
from django.contrib.auth.models import User

class Crop(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=100)
    farmer = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to the User model

    def __str__(self):
        return self.name

class CropImage(models.Model):
    crop = models.ForeignKey(Crop, related_name='images', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='crop_images/', null=False)  # Directory for storing images

    def __str__(self):
        return f"Image for {self.crop.name}"


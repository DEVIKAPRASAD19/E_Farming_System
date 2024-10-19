from django.db import models
from django.utils import timezone
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
    status = models.BooleanField(default=True)  # Boolean field, defaulting to True (e.g., for active users)
    delivery_address = models.TextField(blank=True, null=True)  # Field for delivery address
    pincode = models.CharField(max_length=10, blank=True, null=True)  #
    created_at = models.DateTimeField(default=timezone.now)  # Automatically sets the current time for existing records
    updated_at = models.DateTimeField(auto_now=True)  # Automatically updates the timestamp whenever the record is updated
    last_login = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
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
    farmer = models.ForeignKey(Registeruser, on_delete=models.CASCADE)  # Link to the User model
    stock = models.IntegerField(default=0)  # Stock for available quantity
    status = models.BooleanField(default=True)         # 1 if available, else 0
    is_verified = models.BooleanField(default=False)  # Admin verification field
    added_at = models.DateTimeField(auto_now_add=True) # Timestamp for when the product is added
    updated_at = models.DateTimeField(auto_now=True)   # Timestamp for when the product is last updated
    

    def __str__(self):
        return self.name

class CropImage(models.Model):
    crop = models.ForeignKey(Crop, related_name='images', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='crop_images/', null=False)  # Directory for storing images

    def __str__(self):
        return f"Image for {self.crop.name}"
    
    
    
class Cart(models.Model):
    user = models.ForeignKey(Registeruser, on_delete=models.CASCADE)
    crop = models.ForeignKey(Crop, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'crop')  # Prevent duplicates for the same user and crop

    def __str__(self):
        return f"{self.quantity} of {self.crop.name} in cart"
    
    def get_total_price(self):
        return self.quantity * self.crop.price




class Adminm(models.Model):
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=128)



class Wishlist(models.Model):
    crop = models.ForeignKey(Crop, on_delete=models.CASCADE)
    user = models.ForeignKey(Registeruser, on_delete=models.CASCADE)  # Use ForeignKey to associate with the user
    added_date = models.DateTimeField(auto_now_add=True)

    

""" class Order(models.Model):
    PAYMENT_CHOICES = (
        ('cod', 'Cash on Delivery'),
        ('online', 'Online Payment'),
    )
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Shipped', 'Shipped'),
        ('Delivered', 'Delivered'),
    )

    user = models.ForeignKey('Registeruser', on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=False, blank=False)
    contact = models.CharField(max_length=20)
    email = models.EmailField()
    place = models.CharField(max_length=255)
    pincode = models.CharField(max_length=6)
    delivery_address = models.TextField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=10, choices=PAYMENT_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    order_date = models.DateTimeField(auto_now_add=True)

    # Store the related cart items (many-to-many relation)
    items = models.ManyToManyField(Cart)

    def __str__(self):
        return f"Order {self.id} - {self.user.name}" """
    

class Order(models.Model):
    PAYMENT_CHOICES = (
        ('cod', 'Cash on Delivery'),
        ('online', 'Online Payment'),
    )
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Shipped', 'Shipped'),
        ('Delivered', 'Delivered'),
    )

    user = models.ForeignKey('Registeruser', on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=False, blank=False)
    contact = models.CharField(max_length=20)
    email = models.EmailField()
    place = models.CharField(max_length=255)
    pincode = models.CharField(max_length=6)
    delivery_address = models.TextField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=10, choices=PAYMENT_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    order_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order {self.id} - {self.user.name}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='order_items')
    crop = models.ForeignKey('Crop', on_delete=models.CASCADE)  # Assuming you have a Crop model
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.crop.name} (x{self.quantity})"

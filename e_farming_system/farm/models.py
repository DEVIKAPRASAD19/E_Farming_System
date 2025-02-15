from django.db import models
from django.utils import timezone
from django.db.models import Count
from django.contrib.auth.hashers import make_password, check_password




# Define the choices for the Role field
ROLE_CHOICES = [
    ('farmer', 'Farmer'),
    ('buyer', 'Buyer'),
    ('delivery_boy', 'Delivery Boy'),
]

class Registeruser(models.Model):
    # Additional fields
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    contact = models.CharField(max_length=15)
    place = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=15, choices=ROLE_CHOICES)
    status = models.BooleanField(default=True)  # Boolean field, defaulting to True (e.g., for active users)
    delivery_address = models.TextField(blank=True, null=True)  # Field for delivery address
    pincode = models.CharField(max_length=10, blank=True, null=True)  #
    is_verified = models.BooleanField(default=False)
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
    








from django.db import models
from django.contrib.auth.models import User

class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Example: Grains, Vegetables, Fruits

    def __str__(self):
        return self.name

class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="subcategories")
    name = models.CharField(max_length=255)

    class Meta:
        unique_together = ('category', 'name')  # Prevent duplicate subcategories under the same category

    def __str__(self):
        return f"{self.category.name} - {self.name}"


class Crop(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    subcategory = models.ForeignKey(SubCategory, on_delete=models.CASCADE, null=True, blank=True)  # New field
    farmer = models.ForeignKey(Registeruser, on_delete=models.CASCADE)  # Link to the User model
    stock = models.IntegerField(default=0)  # Stock for available quantity
    status = models.BooleanField(default=True)         # 1 if available, else 0
    is_verified = models.BooleanField(default=True)  # Admin verification field
    added_at = models.DateTimeField(auto_now_add=True) # Timestamp for when the product is added
    updated_at = models.DateTimeField(auto_now=True)   # Timestamp for when the product is last updated

    class Meta:
        unique_together = ('name', 'farmer', 'subcategory')  # Ensure that the same crop cannot be added by the same farmer
    
    def __str__(self):
         return f"{self.name} - {self.subcategory.name if self.subcategory else ''}"
    
    @classmethod
    def search_varieties(cls, crop_name):
        return cls.objects.filter(
            name__iexact=crop_name
        ).select_related('subcategory', 'farmer')
    
    

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

    

class Order(models.Model):
    PAYMENT_CHOICES = (
        ('cod', 'Cash on Delivery'),
        ('online', 'Online Payment'),
    )
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Accepted', 'Accepted'),
        ('Out for Delivery', 'Out for Delivery'),
        ('Delivered', 'Delivered')
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
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    order_date = models.DateTimeField(auto_now_add=True)
    assigned_delivery_boy = models.ForeignKey('DeliveryBoyDetail',on_delete=models.SET_NULL,null=True,blank=True,related_name='assigned_orders')
    updated_at = models.DateTimeField(auto_now=True)
    is_accepted = models.BooleanField(default=False)
    is_canceled = models.BooleanField(default=False)  # Track cancellations
    is_verified = models.BooleanField(default=False)  # Mark order as delivered after QR scan

    def save(self, *args, **kwargs):
        """Override save method to log status history on status change."""
        if self.pk:  # Check if the order is being updated
            previous_order = Order.objects.get(pk=self.pk)
            if previous_order.status != self.status:
                # Record the status change
                OrderStatusHistory.objects.create(
                    order=self,
                    status=self.status,
                    location=self.place  # Assuming place is used as location
                )
        super().save(*args, **kwargs)
    
    def save(self, *args, **kwargs):
        """Automatically assigns a delivery boy to the order when saved."""
        if self.assigned_delivery_boy is None and not self.is_canceled:
            self.assign_delivery_boy()
        super().save(*args, **kwargs)

    def assign_delivery_boy(self):
        """Automatically assigns the least busy verified delivery boy."""
        available_boys = DeliveryBoyDetail.objects.filter(verified=True).annotate(
            order_count=Count('assigned_orders')
        ).order_by('order_count')  # Assign the delivery boy with the least orders

        if available_boys.exists():
            self.assigned_delivery_boy = available_boys.first()


    def __str__(self):
        return f"Order {self.id} - {self.user.name}"

class OrderStatusHistory(models.Model):
    order = models.ForeignKey('Order', on_delete=models.CASCADE, related_name='status_history')
    status = models.CharField(max_length=20, choices=Order.STATUS_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Order {self.order.id} - {self.status} at {self.timestamp}"



class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='order_items')
    crop = models.ForeignKey('Crop', on_delete=models.CASCADE)  # Assuming you have a Crop model
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.crop.name} (x{self.quantity})"


class Notification(models.Model):
    farmer = models.ForeignKey(Registeruser, on_delete=models.CASCADE)
    message = models.TextField()
    crop = models.ForeignKey(Crop, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Notification for {self.farmer.name}: {self.message}"
    

class Feedback(models.Model):
    user = models.ForeignKey(Registeruser, on_delete=models.CASCADE)  # Must be linked to Registeruser model
    crop = models.ForeignKey('Crop', on_delete=models.CASCADE)  # Linking to Crop model
    feedback_text = models.TextField()
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)], default=5)  # Rating from 1 to 5
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.rating} Stars"



class DeliveryBoyDetail(models.Model):
    VEHICLE_TYPE_CHOICES = [
        ('bike', 'Bike'),
        ('car', 'Car'),
        ('van', 'Van'),
        ('truck', 'Truck'),
        ('other', 'Other'),
    ]

    user = models.OneToOneField(Registeruser, on_delete=models.CASCADE, related_name='delivery_details')
    name = models.CharField(max_length=100)
    contact = models.CharField(max_length=15)
    place = models.CharField(max_length=100)
    email = models.EmailField(max_length=254)
    vehicle_type = models.CharField(max_length=20, choices=VEHICLE_TYPE_CHOICES, blank=True, null=True)
    vehicle_number = models.CharField(max_length=20, blank=True, null=True)
    license_number = models.CharField(max_length=50, blank=True, null=True)
    area_of_service = models.TextField(blank=True, null=True)
    additional_documents = models.FileField(upload_to='delivery_docs/', blank=True, null=True)
    completed_registration = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    current_orders = models.IntegerField(default=0) 

    def __str__(self):
        return f"Delivery Details for {self.user.name}"

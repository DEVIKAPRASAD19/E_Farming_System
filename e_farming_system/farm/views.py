from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from django.contrib.auth.tokens import default_token_generator as custom_token_generator
from django.utils.html import strip_tags
from .models import Registeruser, Adminm, Cart, Wishlist
from .forms import SetPasswordForm
from .tokens import custom_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.decorators import login_required
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import logout 
from .models import Crop, CropImage
from django.views.decorators.cache import cache_control
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from decimal import Decimal  # Add this import statement





# Create your views here.
def index(request):
    return render(request,'index.html')

def about(request):
    return render(request,'about.html')

def contact(request):
    return render(request,'contact.html')

def adminfarm(request):
    return render(request,'adminfarm.html')



def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Check if the user is an admin
        admin = Adminm.objects.filter(email=email, password=password).first()
        if admin:
            request.session['admin_email'] = admin.email
            return redirect('adminfarm')  # Replace with the correct URL name

        # Check if the user is a farmer or buyer
        user = Registeruser.objects.filter(email=email).first()  # Get the user by email
        if user:
            # Check the password (ensure you're using hashed passwords in production)
            if user.password == password:  # Replace this with a secure hash check in production
                if not user.status:  # Check if the user's account is deactivated
                    messages.error(request, 'Your account is deactivated. Please contact support.')
                    return render(request, 'login.html')

                # If user is active, set session variables
                request.session['user_id'] = user.user_id
                request.session['name'] = user.name
                request.session['role'] = user.role

                # Redirect based on role
                if user.role == 'farmer':
                    return redirect('farmer_dashboard')  # Replace with the correct URL name
                elif user.role == 'buyer':
                    return redirect('buyer_dashboard')  # Replace with the correct URL name
            else:
                messages.error(request, 'Invalid email or password')
                return render(request, 'login.html')
        else:
            messages.error(request, 'Invalid email or password')
            return render(request, 'login.html')

    return render(request, 'login.html')



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout(request):
    request.session.flush()  # Clears the session data
    return redirect('index')  # Redirects to the login page

               

def register(request):
    if request.method == 'POST':
        name = request.POST['name']
        contact = request.POST['contact']
        place = request.POST['place']
        email = request.POST['email']
        password = request.POST['password']
        role = request.POST['role']

        # Check if the email already exists
        if Registeruser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')

        # Create the new user
        user = Registeruser(name=name, contact=contact, place=place, email=email, password=password, role=role)
        user.save()

        messages.success(request, 'Registration successful! Please log in.')
        return redirect('login')
    
    return render(request, 'register.html')



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def farmer_dashboard(request):
    # Check if user_id is in session
    user_id = request.session.get('user_id')
    if user_id:
        try:
            # Fetch user details from the database using user_id
            user = Registeruser.objects.get(user_id=user_id)
        except Registeruser.DoesNotExist:
            # Handle case where user does not exist
            return redirect('login')

        # Get farmer's name from session
        farmer_name = request.session.get('name')

        # Render the dashboard template with user context
        return render(request, 'farmer_dashboard.html', {
            'farmer_name': farmer_name,
            'user': user,  # Pass the user object to access user_id in the template
        })
    else:
        return redirect('login')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def buyer_dashboard(request):
    if request.session.get('user_id'):
        buyer_id = request.session.get('user_id')  # Get buyer's user ID from session
        try:
            # Fetch the buyer's details from the database
            buyer = Registeruser.objects.get(user_id=buyer_id)
            buyer_name = buyer.name  # Get buyer's name from the fetched user details
            
            # Render the dashboard with the user's details
            return render(request, 'buyer_dashboard.html', {'buyer_name': buyer_name, 'user': buyer})
        except Registeruser.DoesNotExist:
            # Handle the case where the user does not exist in the database
            return redirect('login')
    else:
        return redirect('login')




def adminviews(request):
    crops = Crop.objects.all()  # Fetch all crops
    return render(request, 'adminviews.html', {'crops': crops})

def salesview(request):
    return render(request, 'salesview.html')

def profile(request):
    return render(request, 'profile.html')


def forgotpass(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Check if the user exists with the provided email
        user = Registeruser.objects.filter(email=email).first()
        
        if user:
            # Generate a random token for the password reset
            token = get_random_string(20)
            
            # Build the password reset link
            reset_link = request.build_absolute_uri(reverse('reset_password', args=[token]))
            
            try:
                # Send an email to the user with the reset link
                send_mail(
                    'Password Reset Request',
                    f'Click the link below to reset your password:\n\n{reset_link}',
                    'your-email@example.com',  # Replace with the email address configured in settings.py
                    [email],
                    fail_silently=False,
                )
                
                # Save the reset token to the user's model (assuming the field reset_token exists)
                user.reset_token = token
                user.save()

                # Display success message to the user
               # messages.success(request, 'Password reset link has been sent to your email.')
                return redirect('login')  # Redirect to login after sending the email

            except Exception as e:
                # Display error message if email sending fails
                messages.error(request, f"Error sending email: {str(e)}")
        else:
            # If no user is found with that email
            messages.error(request, 'No account found with that email.')
    
    # Render the forgot password page
    return render(request, 'forgotpass.html')


def reset_password(request, token):
    # Find the user by the reset token
    user = Registeruser.objects.filter(reset_token=token).first()
    
    if user:
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if new_password == confirm_password:
                # Hash the new password before saving it
                user.password = new_password
                
                # Clear the reset token after successful reset
                user.reset_token = None
                user.save()

                # Show success message and redirect to login
                #messages.success(request, 'Password reset successful. You can now log in.')
                return redirect('login')
            else:
                # Show error if passwords do not match
                messages.error(request, 'Passwords do not match.')
        
        # Render the reset password page if the request method is GET
        return render(request, 'reset_password.html', {'token': token})
    else:
        # If the token is invalid or expired
        messages.error(request, 'Invalid or expired reset token.')
        return redirect('forgotpass')




def updateprofile(request):
    if not request.session.get('user_id'):
        return redirect('login')
    user_id = request.session.get('user_id')
    user = Registeruser.objects.get(user_id=user_id)
    if request.method == 'POST':
        new_name = request.POST.get('name')
        new_contact = request.POST.get('contact')
        new_place = request.POST.get('place')
        user.name = new_name
        user.contact = new_contact
        user.place = new_place
        user.save()
        return redirect('farmer_dashboard')
    else:
        return render(request, 'updateprofile.html', {'user':user})
    



def updatebuyer(request):
    if not request.session.get('user_id'):
        return redirect('login')
    user_id = request.session.get('user_id')
    user = Registeruser.objects.get(user_id=user_id)
    if request.method == 'POST':
        new_name = request.POST.get('name')
        new_contact = request.POST.get('contact')
        new_place = request.POST.get('place')
        user.name = new_name
        user.contact = new_contact
        user.place = new_place
        user.save()
        return redirect('buyer_dashboard')
    else:
        return render(request, 'updateprofile.html', {'user':user})





def farmercrops(request):
    crops = Crop.objects.all()  # Fetch all crops
    return render(request, 'farmercrops.html', {'crops': crops})



def addcrops(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        category = request.POST.get('category')
        
        # Get user_id from the session
        farmer_user_id = request.session.get('user_id')  # Assuming 'user_id' is stored in session for farmers
        
        try:
            # Fetch the Registeruser instance
            register_user = Registeruser.objects.get(user_id=farmer_user_id)
            
            # Check if a User instance exists for this Registeruser
            try:
                farmer = User.objects.get(email=register_user.email)  # Fetch the User instance by email
            except User.DoesNotExist:
                # If the User does not exist, you may want to create it
                farmer = User.objects.create_user(
                    username=register_user.email,  # You can adjust this to fit your requirements
                    email=register_user.email,
                    password='set_a_default_password_here'  # Set a password if needed, ideally use hashing
                )
                # Optionally set more user fields here, like first_name, etc.
        
        except Registeruser.DoesNotExist:
            return redirect('error_page')  # Handle user not found

        # Create the Crop instance
        crop_instance = Crop.objects.create(
            name=name,
            description=description,
            price=price,
            category=category,
            farmer=register_user  # Now this is a User instance
        )
        
        # Handle crop images
        crop_photos = request.FILES.getlist('crop_photos')  # Handling multiple image files
        for photo in crop_photos:
            CropImage.objects.create(crop=crop_instance, image=photo)  # Saving each image to CropImage

        #messages.success(request, 'Crop added successfully')
        
        return redirect('farmer_dashboard')  # Redirect to the farmer dashboard after crop addition
    
    return render(request, 'addcrops.html')  # Render the crop addition form




def crops_page(request):
    query = request.GET.get('query')
    category = request.GET.get('category')
    
    # Filter crops by status and any search criteria
    crops = Crop.objects.filter(status=1,is_verified=1)  # Only get activated crops

    if query:
        crops = crops.filter(name__icontains=query)  # Filter by search query
    if category:
        crops = crops.filter(category=category)  # Filter by category

    return render(request, 'crops_page.html', {'crops': crops})


def crop_details(request, id):
    # Fetch the crop object based on the id and ensure it's activated (status=1)
    crop_instance = get_object_or_404(Crop, id=id, status=True, is_verified=True)  # Assuming status=True is for active crops

    if request.method == 'POST':
        if 'add_to_wishlist' in request.POST:
            user_id = request.session.get('user_id')  # Fetch the user ID from session
            if user_id:
                user = get_object_or_404(Registeruser, user_id=user_id)  # Get the user
                # Add crop to the wishlist or fetch it if it already exists
                wishlist_item, created = Wishlist.objects.get_or_create(user=user, crop=crop_instance)

                if created:
                    messages.success(request, 'Crop added to your wishlist!')
                else:
                    messages.info(request, 'This crop is already in your wishlist.')
            else:
                messages.error(request, 'You need to log in to add crops to your wishlist.')

    # Render the crop details page with the fetched crop instance
    context = {
        'crop': crop_instance,
    }
    return render(request, 'crop_details.html', context)

# View to list farmers or buyers based on role
def manage_users(request, role):
    # Filter users based on role (farmer, buyer, etc.)
    users = Registeruser.objects.filter(role=role)  # Filter by role
    return render(request, 'manage_users.html', {'users': users, 'role': role})


def farmer_crops(request):
    # Check if user_id is in the session; if not, redirect to login
    if not request.session.get('user_id'):
        return redirect('login')

    # Fetch the logged-in farmer using the session's user_id
    farmer = get_object_or_404(Registeruser, user_id=request.session['user_id'])

    # Ensure the user is a farmer
    if farmer.role != 'farmer':
        return redirect('home')  # Redirect non-farmer users to another page

    # Check if the user wants to view inactive crops
    show_inactive = request.GET.get('show_inactive', 'false') == 'true'

    # Filter crops based on the show_inactive toggle
    if show_inactive:
        crops = Crop.objects.filter(farmer=farmer)  # Fetch all crops
    else:
        crops = Crop.objects.filter(farmer=farmer, status=True)  # Only fetch active crops

    # Display a message if no crops are found
    if not crops.exists():
        messages.info(request, 'You have no crops.')  # Inform the user

    context = {
        'crops': crops,
        'show_inactive': show_inactive  # Pass the toggle state to the template
    }

    return render(request, 'farmer_crops.html', context)



def verify_crops(request):
    crops = Crop.objects.filter(is_verified=False)  # Get crops that are not verified
    return render(request, 'verify_crops.html', {'crops': crops})

def approve_crop(request, crop_id):
    try:
        crop = Crop.objects.get(id=crop_id)
        crop.is_verified = True  # Mark as verified
        crop.save()
        return HttpResponse("Crop has been approved!")
    except Crop.DoesNotExist:
        return HttpResponse("Crop not found")

def reject_crop(request, crop_id):
    try:
        # Fetch the crop by its ID
        crop = Crop.objects.get(id=crop_id)
        
        # Update the crop's status to False (0) to mark it as rejected
        crop.status = False
        crop.save()  # Save the changes
        
        return HttpResponse("Crop has been rejected and its status is now inactive!")
    
    except Crop.DoesNotExist:
        return HttpResponse("Crop not found")




def update_crop(request, id):
    crop_instance = get_object_or_404(Crop, id=id)

    if request.method == 'POST':
        # Update crop details
        crop_instance.name = request.POST.get('name')
        crop_instance.description = request.POST.get('description')
        crop_instance.price = request.POST.get('price')
        crop_instance.category = request.POST.get('category')

        # Handle image update
        if 'image' in request.FILES:
            crop_instance.images.all().delete()  # Optionally delete old images
            # Assuming you have a related CropImage model
            for image in request.FILES.getlist('image'):
                CropImage.objects.create(crop=crop_instance, image=image)
        
        crop_instance.save()  # Save the updated crop instance
        return redirect('farmercrops')  # Redirect to your crops list page

    return render(request, 'update_crop.html', {'crop': crop_instance})


# View to update user
def update_user(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    if request.method == 'POST':
        user.name = request.POST.get('name')
        user.contact = request.POST.get('contact')
        user.place = request.POST.get('place')
        user.email = request.POST.get('email')
        user.save()
        return redirect('manage_users', role=user.role)
    
    context = {'user': user}
    return render(request, 'update_user.html', {'user': user})


def deactivate_user(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    user.status = False  # Deactivate the user
    user.save()

    # Send deactivation email
    send_mail(
    subject='Important: Your Account Has Been Deactivated',
    message=(
        f"Dear {user.name},\n\n"
        "We regret to inform you that your account has been deactivated by our admin team. "
        "This action means you will no longer be able to access your account or its features at this time.\n\n"
        "If you believe this is a mistake or if you have any questions, please feel free to contact us, and we will be happy to assist you.\n\n"
        "Best regards,\n"
        "The E-Farming Team\n"
        f"Contact us: {settings.DEFAULT_FROM_EMAIL}"
    ),
    from_email=settings.DEFAULT_FROM_EMAIL,
    recipient_list=[user.email],  # User's email
    fail_silently=False,
)


    messages.success(request, f'User {user.name} has been deactivated.')
    return redirect('manage_users', role=user.role)

def activate_user(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    user.status = True  # Activate the user
    user.save()

    # Send activation email
    send_mail(
    subject='Your Account Has Been Activated!',
    message=(
        f"Dear {user.name},\n\n"
        "We are happy to inform you that your account has been successfully activated by our admin team.\n"
        "You can now log in to your account and continue using all the features available to you.\n\n"
        "If you have any questions or require assistance, feel free to reach out to our support team.\n\n"
        "Best regards,\n"
        "The E-Farming Team\n"
        f"Contact us: {settings.DEFAULT_FROM_EMAIL}"
    ),
    from_email=settings.DEFAULT_FROM_EMAIL,
    recipient_list=[user.email],  # User's email
    fail_silently=False,
)


    messages.success(request, f'User {user.name} has been activated.')
    return redirect('manage_users', role=user.role)





def view_profile(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    return render(request, 'view_profile.html', {'user': user})


def search_crops(request):
    query = request.GET.get('query', '')
    category = request.GET.get('category', '')

    # Filter crops based on query and category, ensuring only activated crops are included
    crops = Crop.objects.filter(status=1, is_verified=1)  # Ensure only activated crops are considered

    if query:
        crops = crops.filter(name__icontains=query)  # Search by name if query is provided

    if category:
        crops = crops.filter(category=category)  # Filter by category if specified

    return render(request, 'crops_page.html', {'crops': crops})



def add_to_cart(request, crop_id):
    # Debug statement
    print("User is authenticated:", request.user.is_authenticated)  
    
    if request.user.is_authenticated:  # Check if user is logged in
        crop = get_object_or_404(Crop, id=crop_id)
        cart_item, created = Cart.objects.get_or_create(crop=crop, user=request.user)
        
        if not created:  # If the crop is already in the cart, increase the quantity
            cart_item.quantity += 1
            cart_item.save()
            messages.success(request, 'Crop quantity updated in your cart.')
        else:
            messages.success(request, 'Crop has been added to your cart!')
        
        return redirect('crop_details', crop_id=crop.id)  # Redirect back to crop details
    else:
        print("User is not authenticated, redirecting to login")  # Debugging line
        return redirect('login')  # Redirect to the login page if not authenticated

def remove_from_cart(request, crop_id):
    cart_item = get_object_or_404(Cart, crop__id=crop_id)
    cart_item.delete()
    
    return redirect('cart_page')  # Redirect to the cart page or wherever you want

def cart_page(request):
    cart_items = Cart.objects.all()  # Get all cart items
    return render(request, 'cart_page.html', {'cart_items': cart_items})


def deactivate_crop(request, crop_id):
    # Get the crop object
    crop = get_object_or_404(Crop, id=crop_id)

    # Set the crop's status to 0 (inactive)
    crop.status = 0
    crop.save()

    # Redirect to the crops list page or wherever you want
    return redirect('farmercrops')  # Update with the correct URL name for the crops list


def activate_crop(request, crop_id):
    # Get the crop object
    crop = get_object_or_404(Crop, id=crop_id)

    # Set the crop's status to 1 (active)
    crop.status = 1
    crop.save()

    # Redirect to the crops list page or wherever you want
    return redirect('farmercrops')  # Update with the correct URL name for the crops list




def wishlist(request):
    user_id = request.session.get('user_id')
    
    if user_id:
        # Fetch the user from Registeruser model
        user = get_object_or_404(Registeruser, user_id=user_id)
        
        if request.method == 'POST':
            crop_id = request.POST.get('remove_crop_id')  # Get the crop ID from POST data
            if crop_id:
                try:
                    wishlist_item = Wishlist.objects.get(user_id=user_id, crop_id=crop_id)
                    wishlist_item.delete()  # Remove the crop from the wishlist
                    messages.success(request, 'Crop removed from your wishlist.')
                except Wishlist.DoesNotExist:
                    messages.error(request, 'This crop is not in your wishlist.')
        
        # Fetch all wishlist items associated with the user
        wishlist_items = Wishlist.objects.filter(user_id=user_id)
        context = {
            'crops': [item.crop for item in wishlist_items],  # Change variable name here to crops
            'error': None
        }
    else:
        messages.error(request, "You need to log in to view your wishlist.")
        context = {
            'crops': [],  # Change variable name here as well
            'error': "You need to log in to view your wishlist."
        }
    
    return render(request, 'wishlist.html', context)




def add_to_cart(request, crop_id):
    if request.method == "POST":
        quantity = int(request.POST.get('quantity', 1))  # Get quantity from POST data, default to 1 if not provided
        cart = request.session.get('cart', {})

        # Update the cart with the new quantity
        if crop_id in cart:
            cart[crop_id] += quantity  # Increment existing quantity
        else:
            cart[crop_id] = quantity  # Add new crop with its quantity

        # Save the updated cart back to the session
        request.session['cart'] = cart

    return redirect('cart')  # Redirect to the cart page after adding




def cart(request):
    # Get the cart from the session
    cart = request.session.get('cart', {})

    # Initialize total price using Decimal for accuracy with money calculations
    total_price = Decimal('0.00')
    cart_items = []

    # Loop through each crop in the cart
    for crop_id, item in cart.items():
        crop = get_object_or_404(Crop, id=crop_id)
        
        # Ensure quantity is correctly retrieved from the session
        if isinstance(item, dict):
            quantity = item.get('quantity', 1)
        else:
            quantity = item  # If not a dict, it's already an integer

        # Calculate total price for the current item
        item_total_price = crop.price * quantity  # crop.price is Decimal, quantity is int
        
        # Append to cart items list
        cart_items.append({
            'crop': crop,
            'quantity': quantity,
            'item_total_price': item_total_price
        })

        # Add to the total price of the cart
        total_price += item_total_price

    # Render the cart template with cart items and total price
    return render(request, 'cart.html', {'cart_items': cart_items, 'total_price': total_price})


def remove_from_cart(request, crop_id):
    # Convert crop_id to string because session data is usually stored as strings
    crop_id_str = str(crop_id)

    # Get the cart from the session
    cart = request.session.get('cart', {})

    # Check if the crop is in the cart
    if crop_id_str in cart:
        # Remove the crop from the cart
        del cart[crop_id_str]

        # Save the updated cart back to the session
        request.session['cart'] = cart

    # Redirect to the cart page after removal
    return redirect('cart')
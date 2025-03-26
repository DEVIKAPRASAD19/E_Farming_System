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
from .models import Registeruser, Adminm, Cart, Wishlist, Order, OrderItem, Notification, Feedback, DeliveryBoyDetail, Crop, Category, SubCategory, CropImage,  OrderStatusHistory
from .forms import SetPasswordForm
from .tokens import custom_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.decorators import login_required
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import logout 
from django.views.decorators.cache import cache_control
from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from decimal import Decimal  # Add this import statement
import random
from django.utils import timezone
from django.views.decorators.http import require_POST
import json
from django.db.models import Sum, Max
from datetime import datetime
import pickle
import os
from django.db import transaction
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import qrcode
from io import BytesIO
from django.db.models import Count




# Create your views here.
def index(request):
    return render(request,'index.html')

def about(request):
    return render(request,'about.html')

def contact(request):
    return render(request,'contact.html')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
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
                elif user.role == 'delivery_boy':
                    # Check if the delivery boy has completed their profile
                    try:
                        profile = DeliveryBoyDetail.objects.get(user=user)
                        if profile.completed_registration:
                            return redirect('delivery_boy_dashboard')  # Redirect to delivery boy's dashboard
                        else:
                            messages.error(request, 'Please complete your profile.')
                            return render(request, 'login.html')
                    except DeliveryBoyDetail.DoesNotExist:
                        messages.error(request, 'Delivery boy profile not found.')
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
    email = request.session.get('email','')
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

       # Send welcome email to the registered user
        subject = 'Welcome to eFarming System'
        message = f'Hello {name},\n\nThank you for registering with our eFarming system. You can now log in with your credentials.\n\nBest regards,\nThe eFarming Team'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list)
            """ messages.success(request, 'Registration successful! A welcome email has been sent to your email address. Please log in.') """
        except Exception as e:
            messages.warning(request, 'Registration successful, but there was an error sending the welcome email. Please check your email configuration.')
        return redirect('login')
    
    return render(request, 'register.html', {'email': email})



# Dictionary to store OTPs temporarily
otp_storage = {}

def send_otp_email(user_email):
    # Generate a random 4-digit OTP
    otp = random.randint(1000, 9999)
    
    # Store the OTP associated with the user's email in otp_storage
    otp_storage[user_email] = otp

    # Define email subject, message, and sender/recipient details
    subject = 'Your OTP for Email Verification'
    message = f'Your OTP is {otp}. Please use this to verify your email.'
    from_email = 'efarming2024@gmail.com'  # Replace with your own email
    recipient_list = [user_email]

    # Send the OTP email using Django's send_mail function
    send_mail(subject, message, from_email, recipient_list)

# View to handle email input and OTP sending
def enter_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Check if email is already registered in the Registeruser model
        if Registeruser.objects.filter(email=email).exists():
            messages.info(request, "Email is already registered. Please log in.")
            return redirect('login')

        # Send OTP to the email address
        send_otp_email(email)

        # Store the email in session for OTP verification later
        request.session['user_email'] = email

        # Redirect to the OTP verification page
        return redirect('verify_otp')

    return render(request, 'enter_email.html')

# View to handle OTP verification
def verify_otp(request):
    # Get the email from the session (set during email input)
    email = request.session.get('user_email')

    # If email is not in session, redirect to the email entry page
    if not email:
        messages.error(request, "Session expired. Please enter your email again.")
        return redirect('enter_email')

    if request.method == 'POST':
        otp_input = request.POST.get('otp')

        # Check if the entered OTP matches the one sent to the user's email
        if otp_storage.get(email) and otp_storage[email] == int(otp_input):
            # OTP is valid, remove it from storage and mark email as verified
            del otp_storage[email]
            request.session['email'] = email

            # Redirect to the registration page
            return redirect('register')

        else:
            # OTP is invalid, show an error message
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'verify_otp.html')


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
            buyer = Registeruser.objects.get(user_id=buyer_id)  # Fetch buyer details
            buyer_name = buyer.name  # Get buyer's name

            # Get the most recent view for each crop using a subquery
            recent_crops = CropViewHistory.objects.filter(
                buyer=buyer,
                viewed_at__in=CropViewHistory.objects.filter(buyer=buyer)
                    .values('crop')
                    .annotate(max_date=Max('viewed_at'))
                    .values('max_date')
            ).order_by('-viewed_at')[:5]

            # Fetch popular crops (most viewed)
            popular_crops = CropViewHistory.objects.values('crop').annotate(
                view_count=Count('crop')
            ).order_by('-view_count')[:3]  # Reduced to 3 to make room for new crops
            
            popular_crop_ids = [item['crop'] for item in popular_crops]
            
            # Fetch newly added crops (last 2 crops added)
            new_crops = Crop.objects.filter(
                status=True,  # Only active crops
                is_verified=True  # Only verified crops
            ).order_by('-id')[:2]  # Get the 2 most recently added crops
            
            # Combine popular and new crops
            recommended_crops = list(Crop.objects.filter(id__in=popular_crop_ids))
            for crop in new_crops:
                if crop not in recommended_crops:  # Avoid duplicates
                    recommended_crops.append(crop)

            return render(request, 'buyer_dashboard.html', {
                'buyer_name': buyer_name,
                'user': buyer,
                'recent_crops': recent_crops,
                'recommended_crops': recommended_crops
            })
        except Registeruser.DoesNotExist:
            return redirect('login')
    else:
        return redirect('login')



def adminviews(request):
    # Fetch all crops and render the page
    crops = Crop.objects.all()
    return render(request, 'adminviews.html', {'crops': crops})

def deactivatecrop(request, crop_id):
    # Deactivate the crop by setting status to 0 (inactive)
    crop = get_object_or_404(Crop, id=crop_id)
    crop.status = 0
    crop.save()
    return redirect('adminviews')  # Redirect back to the crops list page

def activatecrop(request, crop_id):
    # Activate the crop by setting status to 1 (active)
    crop = get_object_or_404(Crop, id=crop_id)
    crop.status = 1
    crop.save()
    return redirect('adminviews')  # Redirect back to the crops list page

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
        return render(request, 'updatebuyer.html', {'user':user})





""" def farmercrops(request):
    crops = Crop.objects.all()  # Fetch all crops
    return render(request, 'farmercrops.html', {'crops': crops}) """


def addcrops(request):
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Get form data
                name = request.POST.get('name')
                description = request.POST.get('description')
                price = request.POST.get('price')
                category_name = request.POST.get('category')
                subcategory_name = request.POST.get('subcategory')
                stock = request.POST.get('stock')
                farmer_id = request.session.get('user_id')

                # Get or create Category
                category, _ = Category.objects.get_or_create(name=category_name)
                
                # Get or create SubCategory
                subcategory, _ = SubCategory.objects.get_or_create(
                    name=subcategory_name,
                    category=category
                )

                # Create the crop
                crop = Crop.objects.create(
                    name=name,
                    description=description,
                    price=price,
                    category=category,
                    subcategory=subcategory,
                    farmer_id=farmer_id,
                    stock=stock,
                    status=True,
                    is_verified=True
                )

                # Handle image upload
                if 'crop_photos' in request.FILES:
                    image = request.FILES['crop_photos']
                    CropImage.objects.create(
                        crop=crop,
                        image=image
                    )

                messages.success(request, 'Crop added successfully!')
                return redirect('farmer_dashboard')

        except Exception as e:
            print(f"Error: {str(e)}")  # For debugging
            messages.error(request, f'Error adding crop: {str(e)}')
            return redirect('addcrops')

    return render(request, 'addcrops.html')

# Add this view to get subcategories for AJAX
def get_subcategories(request):
    category_id = request.GET.get('category_id')
    subcategories = SubCategory.objects.filter(category_id=category_id).values('id', 'name')
    return JsonResponse(list(subcategories), safe=False)


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


from django.utils.timezone import now
from .models import CropViewHistory  # Import the model

def crop_details(request, id):
    # Fetch the crop object based on the id and ensure it's activated
    crop_instance = get_object_or_404(Crop, id=id, status=True, is_verified=True)

    # Track viewed crop if a user is logged in
    user_id = request.session.get('user_id')  # Fetch user ID from session
    if user_id:
        buyer = get_object_or_404(Registeruser, user_id=user_id)
        # Save crop view history
        CropViewHistory.objects.create(buyer=buyer, crop=crop_instance, viewed_at=now())

    # Handle wishlist addition
    if request.method == 'POST' and 'add_to_wishlist' in request.POST:
        if user_id:
            wishlist_item, created = Wishlist.objects.get_or_create(user=buyer, crop=crop_instance)
            if created:
                messages.success(request, 'Crop added to your wishlist!')
            else:
                messages.info(request, 'This crop is already in your wishlist.')
        else:
            messages.error(request, 'You need to log in to add crops to your wishlist.')

    # Render the crop details page
    return render(request, 'crop_details.html', {'crop': crop_instance})



def submit_feedback(request, crop_id):
    if request.method == 'POST':
        crop = get_object_or_404(Crop, id=crop_id)
        feedback_text = request.POST.get('feedback_text')
        rating = request.POST.get('rating', 5)  # Default rating is 5 if not provided

        # Check if user information is available in the session
        user_id = request.session.get('user_id')
        if user_id:
            # Change 'id' to 'user_id' here
            user = get_object_or_404(Registeruser, user_id=user_id)  # Use user_id instead of id
        else:
            # Handle case when user is not logged in; you might want to set a default user or redirect
            return redirect('login')  # Or handle differently if you want a default behavior

        # Create Feedback instance
        feedback = Feedback(
            user=user,  # Set to the user found in the session
            crop=crop,
            feedback_text=feedback_text,
            rating=rating
        )
        
        feedback.save()  # Now, user_id will not be null
        return redirect('crop_details', id=crop_id)  # Redirect to an appropriate page after submission

    return redirect('crops_page')  # Redirect if the request method is not POST

# View to display all feedback for a crop
def display_feedback(request, crop_id):
    crop = get_object_or_404(Crop, id=crop_id)
    feedback_list = Feedback.objects.filter(crop=crop).order_by('-submitted_at')
    
    return render(request, 'display_feedback.html', {'crop': crop, 'feedback_list': feedback_list})


def admin_feedback_page(request):
    # Check if the admin is logged in by verifying the session
    admin_id = request.session.get('admin_id')

    
    # Fetch all feedback from the database, including related user and crop information
    feedback_list = Feedback.objects.select_related('user', 'crop').order_by('-submitted_at')

    # Render the feedback page for the admin dashboard
    return render(request, 'admin_feedback.html', {'feedback_list': feedback_list})


def farmer_feedback(request):
    # Check if the farmer is logged in by verifying the session
    farmer_id = request.session.get('user_id')
    role = request.session.get('role')

    # Ensure the user is a farmer
    if not farmer_id or role != 'farmer':
        return redirect('login')  # Redirect to login if not authenticated or not a farmer

    # Fetch feedback for crops added by this farmer
    feedback_list = Feedback.objects.select_related('crop').filter(crop__farmer_id=farmer_id).order_by('-submitted_at')

    # Render the feedback page for the farmer dashboard
    return render(request, 'farmer_feedback.html', {'feedback_list': feedback_list})




# View to list farmers or buyers based on role
def manage_users(request, role):
    # Filter users based on role (farmer, buyer, etc.)
    users = Registeruser.objects.filter(role=role)  # Filter by role
    return render(request, 'manage_users.html', {'users': users, 'role': role})


def farmercrops(request):
    # Check if user_id is in the session; if not, redirect to login
    if not request.session.get('user_id'):
        return redirect('login')

    # Fetch the logged-in farmer using the session's user_id
    farmer = get_object_or_404(Registeruser, user_id=request.session['user_id'])

    # Ensure the user is a farmer
    if farmer.role != 'farmer':
        return redirect('index')  # Redirect non-farmer users to another page

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

    return render(request, 'farmercrops.html', context)



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




def update_crop(request, crop_id):
    crop = get_object_or_404(Crop, id=crop_id, farmer_id=request.session.get('user_id'))

    if request.method == 'POST':
        crop.name = request.POST.get('name')
        crop.description = request.POST.get('description')
        crop.price = request.POST.get('price')
        crop.stock = request.POST.get('stock')

        # ✅ Correct category assignment
        category_name = request.POST.get('category')
        try:
            crop.category = Category.objects.get(name=category_name)
        except Category.DoesNotExist:
            messages.error(request, "Invalid category selected.")
            return redirect('update_crop', crop_id=crop_id)

        # Handling images
        if 'image' in request.FILES:
            # Delete old images
            crop.images.all().delete()
            # Add new image
            CropImage.objects.create(crop=crop, image=request.FILES['image'])

        crop.save()
        messages.success(request, 'Crop updated successfully!')
        return redirect('farmercrops')

    return render(request, 'update_crop.html', {'crop': crop})


def delete_crop(request, crop_id):
    if request.method == 'POST':
        crop = get_object_or_404(Crop, id=crop_id, farmer_id=request.session.get('user_id'))
        crop.delete()
        messages.success(request, 'Crop deleted successfully!')
    return redirect('farmercrops')


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

    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()  # Get the reason from POST data
        user.status = False  # Deactivate the user
        user.save()

        # Send deactivation email with reason
        send_mail(
            subject='Important: Your Account Has Been Deactivated',
            message=(
                f"Dear {user.name},\n\n"
                "We regret to inform you that your account has been deactivated by our admin team. "
                "This action means you will no longer be able to access your account or its features at this time.\n\n"
                f"Reason for deactivation: {reason}\n\n"  # Include reason in the email
                "If you believe this is a mistake or if you have any questions, please feel free to contact us, and we will be happy to assist you.\n\n"
                "Best regards,\n"
                "The E-Farming Team\n"
                f"Contact us: {settings.DEFAULT_FROM_EMAIL}"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],  # User's email
            fail_silently=False,
        )
        
        return redirect('manage_users', role=user.role)  # Redirect to a success page or user list

    return render(request, 'deactivate_user.html', {'user': user})  


    

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


    # messages.success(request, f'User {user.name} has been activated.')
    return redirect('manage_users', role=user.role)





def view_profile(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    return render(request, 'view_profile.html', {'user': user})


def search_crops(request):
    query = request.GET.get('query', '')
    category = request.GET.get('category', '')
    
    # Debug print
    print("Received category:", category)
    print("All GET parameters:", request.GET)

    # Filter crops based on status and verification
    crops = Crop.objects.filter(status=True, is_verified=True)

    if query:
        crops = crops.filter(name__icontains=query)  # Search by crop name

    if category:
        # Debug print
        print("Searching for category:", category)
        # Get all categories in DB for comparison
        all_cats = Category.objects.all().values_list('name', flat=True)
        print("Available categories in DB:", list(all_cats))
        
        crops = crops.filter(category__name__iexact=category)

    # Debug print
    print("Number of crops found:", crops.count())
    
    return render(request, 'crops_page.html', {'crops': crops})





# Add a crop to the cart
def add_to_cart(request, crop_id):
    # Get the user from the session
    user_id = request.session.get('user_id')
    user = get_object_or_404(Registeruser, pk=user_id)  # Assuming you have a `Registeruser` model

    # Fetch the crop you want to add to the cart
    crop = get_object_or_404(Crop, id=crop_id)

    # Get the quantity from the POST request, if no quantity provided, default to 1
    quantity = int(request.POST.get('quantity', 1))

    # Check if the crop is already in the user's cart
    cart_item, created = Cart.objects.get_or_create(
        user=user,  # The logged-in user
        crop=crop,  # The crop to be added
        defaults={'quantity': quantity}  # Set default quantity if it's a new entry
    )

    if not created:  # If the crop already exists in the cart, update the quantity
        cart_item.quantity += quantity
        cart_item.save()

    # Redirect to the cart view with a success message
    messages.success(request, 'Crop added to cart successfully.')
    return redirect('viewcart')  # Redirect to the cart page


# View the cart
def viewcart(request):
    user_id = request.session.get('user_id')  # Get user_id from session
    if not user_id:
        return redirect('login')  # Redirect if not logged in
        
    user = get_object_or_404(Registeruser, user_id=user_id)  # Fetch the user
    cart_items = Cart.objects.filter(user=user)  # Fetch cart items

    # Calculate total price
    total_price = sum([item.get_total_price() for item in cart_items])

    context = {
        'cart_items': cart_items,
        'total_price': total_price,
        'user': user  # Add user to context
    }
    return render(request, 'viewcart.html', context)

# Update the quantity of a crop in the cart
def update_cart(request, cart_id):  # Expect cart_id, NOT crop_id
    cart_item = get_object_or_404(Cart, pk=cart_id)
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        if quantity > 0:
            cart_item.quantity = quantity
            cart_item.save()
        else:
            cart_item.delete()  # Optional: Remove item if quantity is 0
        return redirect('viewcart')


# Remove a crop from the cart
def delete_from_cart(request, cart_id):
    cart_item = get_object_or_404(Cart, pk=cart_id)  # Fetch the cart item by its ID
    cart_item.delete()  # Remove the cart item
    messages.success(request, f"{cart_item.crop.name} removed from cart.")  # Success message
    return redirect('viewcart')  # Redirect to the cart view


def crop_stock_details(request):
    # Get all crops
    crops = Crop.objects.all()

    # Get all completed orders
    sold_crops = OrderItem.objects.select_related('order', 'crop', 'crop__farmer').filter(
        order__status='Delivered',
        order__is_canceled=False
    ).order_by('-order__order_date')

    # Calculate total amount for each sale
    for sale in sold_crops:
        sale.total_amount = sale.price * sale.quantity

    # Calculate statistics
    total_crops_sold = sold_crops.values('crop').distinct().count()
    total_quantity_sold = sold_crops.aggregate(Sum('quantity'))['quantity__sum'] or 0
    total_sales_amount = sum(sale.total_amount for sale in sold_crops)
    unique_buyers_count = sold_crops.values('order__user').distinct().count()

    context = {
        'crops': crops,
        'sold_crops': sold_crops,
        'total_crops_sold': total_crops_sold,
        'total_quantity_sold': total_quantity_sold,
        'total_sales_amount': total_sales_amount,
        'unique_buyers_count': unique_buyers_count
    }

    return render(request, 'stock.html', context)


from django.db.models import Sum

from django.db.models import Sum, F

def stockfarmer(request):
    if not request.session.get('user_id'):
        return redirect('login')

    farmer = get_object_or_404(Registeruser, user_id=request.session['user_id'])

    if farmer.role != 'farmer':
        return redirect('home')

    crops = Crop.objects.filter(farmer=farmer)

    # Get completed orders for this farmer's crops
    sold_crops = OrderItem.objects.select_related('order', 'crop').filter(
        crop__farmer=farmer,
        order__status='Delivered',  # Only show delivered orders
        order__is_canceled=False    # Exclude canceled orders
    ).order_by('-order__order_date')

    # Calculate total amount for each sale and add it to the queryset
    for sale in sold_crops:
        sale.total_amount = sale.price * sale.quantity

    # Calculate statistics
    total_crops_sold = sold_crops.values('crop').distinct().count()
    total_quantity_sold = sold_crops.aggregate(Sum('quantity'))['quantity__sum'] or 0
    total_sales_amount = sum(sale.total_amount for sale in sold_crops)
    unique_buyers_count = sold_crops.values('order__user').distinct().count()

    context = {
        'crops': crops,
        'sold_crops': sold_crops,
        'total_crops_sold': total_crops_sold,
        'total_quantity_sold': total_quantity_sold,
        'total_sales_amount': total_sales_amount,
        'unique_buyers_count': unique_buyers_count
    }

    return render(request, 'stockfarmer.html', context)





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




def check_out_step1(request):
    user = Registeruser.objects.get(user_id=request.session['user_id'])

    return render(request, 'checkout_step1.html', {
        'user': user,
    })


""" def check_out_step2(request):
    user = Registeruser.objects.get(user_id=request.session['user_id'])
    cart_items = Cart.objects.filter(user=user)  # Fetch cart items for the user
    total_price = sum(item.get_total_price() for item in cart_items)

    return render(request, 'checkout_step2.html', {
        'user': user,
        'cart_items': cart_items,
        'total_price': total_price
    })

 """

# Update user details and save them in session
def update_user_details(request):
    if request.method == 'POST':
        user = Registeruser.objects.get(user_id=request.session['user_id'])
        
        # Save updated details only in the session without updating the Registeruser model
        request.session['updated_user_details'] = {
            'name': request.POST.get('name', user.name),
            'contact': request.POST.get('contact', user.contact),
            'email': request.POST.get('email', user.email),
            'place': request.POST.get('place', user.place),
            'pincode': request.POST.get('pincode', user.pincode),
            'delivery_address': request.POST.get('delivery_address', '')
        }
        
        # Debugging print statement to check session data
        print("Session data for updated user details:", request.session['updated_user_details'])

        return redirect('check_out_step2')  # Redirect back to the checkout page
    else:
        # Redirect to the previous step if the request is not POST
        return redirect('check_out_step1')




# Create an in-app notification for low stock
def create_low_stock_notification(farmer, crop):
    message = f"The stock for your crop '{crop.name}' has fallen below 5kg. Current Stock: {crop.stock} kg."
    Notification.objects.create(
        farmer=farmer,
        crop=crop,
        message=message,
        created_at=timezone.now(),
        is_read=False
    )

def mark_notification_as_read(request, notification_id):
    notification = Notification.objects.get(id=notification_id, farmer=request.session['user_id'])
    notification.is_read = True
    notification.save()
    return redirect('farmer_dashboard')




def send_low_stock_notification(farmer, crop):
    subject = 'Low Stock Alert for Your Crop'
    message = f"Dear {farmer.name},\n\nThe stock for your crop '{crop.name}' has fallen below 5 kg.\nCurrent Stock: {crop.stock} kg\n\nPlease consider restocking."
    send_mail(
        subject,
        message,
        'from@example.com',  # Replace with your email
        [farmer.email],  # Accessing the email directly from Registeruser model
        fail_silently=False,
    )


# Place order after updating user details and confirming purchase
def place_order(request):
    if request.method == 'POST':
        user = Registeruser.objects.get(user_id=request.session['user_id'])
        user_details = request.session.get('updated_user_details', None)

        if not user_details:
            return redirect('check_out')

        delivery_address = request.POST['address']
        payment_method = request.POST['payment_method']

        # Retrieve pincode from the session, falling back to user details if not set
        pincode = user_details.get('pincode') or request.POST.get('pincode') or request.session['updated_user_details'].get('pincode')

        cart_items = Cart.objects.filter(user=user)
        total_price = sum(item.get_total_price() for item in cart_items)

        order = Order.objects.create(
            user=user,
            name=user_details['name'],
            contact=user_details['contact'],
            email=user_details['email'],
            place=user_details['place'],
            pincode=pincode,  # Use the retrieved pincode here
            delivery_address=delivery_address,
            total_price=total_price,
            payment_method=payment_method
        )

        # Add cart items as order items and remove from wishlist if present
        for item in cart_items:
            OrderItem.objects.create(
                order=order,
                crop=item.crop,  # Assuming the Cart model has a crop reference
                quantity=item.quantity,
                price=item.crop.price  # Store the unit price
            )
            # Reduce the stock of the crop
            item.crop.stock -= item.quantity
            item.crop.save()  # Save the updated crop with reduced stock

            # Remove from wishlist if the item is present
            Wishlist.objects.filter(user=user, crop=item.crop).delete()

            # Check stock level and send notification if below 5 kg
            if item.crop.stock < 5:
                send_low_stock_notification(item.crop.farmer, item.crop)

                # Create in-app notification
                create_low_stock_notification(item.crop.farmer, item.crop)

        cart_items.delete()
        request.session['cart'] = []

        # Send confirmation email
        order_details = f"Order ID: {order.id}\nTotal Price: Rs. {total_price}\nPayment Method: {payment_method}\nDelivery Address: {delivery_address}"
        send_order_confirmation_email(order.email, order_details)

        return redirect('order_summary', order_id=order.id)

    return redirect('check_out')





def send_order_confirmation_email(user_email, order_details):
    subject = 'Order Confirmation'
    message = f'Your order has been placed successfully!\n\nOrder Details:\n{order_details}'
    from_email = settings.EMAIL_HOST_USER

    send_mail(
        subject,
        message,
        from_email,
        [user_email],
        fail_silently=False,
    )




def order_summary(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    
    # Calculate total prices for each order item and format the price
    order_items = order.order_items.all()
    
    # Format the item prices and calculate total price
    formatted_order_items = []
    total_price = 0

    for item in order_items:
        formatted_price = f"{item.price:.2f}"  # Format unit price to two decimal places
        total_item_price = item.price * item.quantity  # Calculate total price for the item
        formatted_total_item_price = f"{total_item_price:.2f}"  # Format total item price
        total_price += total_item_price  # Add to total order price
        
        formatted_order_items.append({
            'crop_name': item.crop.name,
            'quantity': item.quantity,
            'formatted_price': formatted_price,  # Unit price formatted
            'formatted_total_item_price': formatted_total_item_price,  # Total price for the item formatted
        })
    
    formatted_total_price = f"{total_price:.2f}"  # Format total price

    context = {
        'order': order,
        'order_items': formatted_order_items,
        'total_price': formatted_total_price,
        'payment_method': order.payment_method,  # Pass payment method if needed
    }
    
    return render(request, 'order_summary.html', context)



def order_history(request):
    # Check if user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    try:
        # Fetch the user object
        user = Registeruser.objects.get(user_id=user_id)
        # Fetch orders for the user
        orders = Order.objects.filter(user=user).order_by('-order_date')
        
        context = {
            'orders': orders,
            'user': user,  # Explicitly add user to context
        }
        return render(request, 'order_history.html', context)
    
    except Registeruser.DoesNotExist:
        # Handle case where user doesn't exist
        request.session.flush()  # Clear invalid session
        return redirect('login')





import requests
from django.shortcuts import render

API_KEY = '1c192ab813182062b3023f96fc2ad1a6'  # Replace with your actual OpenWeatherMap API key

def weather_update(request):
    location = 'Kottayam'  # Default location

    if request.method == 'POST':
        location = request.POST.get('location')  # Get the user input location

    # OpenWeatherMap API URL
    url = f'http://api.openweathermap.org/data/2.5/weather?q={location}&appid={API_KEY}&units=metric'
    
    # Fetching data from the API
    response = requests.get(url)
    data = response.json()

    # Parse the necessary weather information
    if response.status_code == 200:
        weather_data = {
            'city': data['name'],
            'temperature': data['main']['temp'],
            'description': data['weather'][0]['description'],
            'icon': data['weather'][0]['icon'],  # Weather icon
        }
    else:
        weather_data = {'error': 'Could not retrieve weather data.'}

    # Pass the data to the template
    return render(request, 'weather.html', {'weather_data': weather_data})



def expert_consultation(request):
    # Sample expert data
    experts = [
        {'name': 'Dr. A. Kumar', 'expertise': 'Agronomy', 'contact': '+91 7510508273', 'email': 'a.kumar@example.com'},
        {'name': 'Ms. B. Sharma', 'expertise': 'Horticulture', 'contact': '+91 9747911520', 'email': 'b.sharma@example.com'},
        {'name': 'Mr. C. Verma', 'expertise': 'Soil Science', 'contact': '+91 9947078273', 'email': 'c.verma@example.com'},
    ]

    return render(request, 'expert_consultation.html', {'experts': experts})


def buy_crop(request, crop_id):
    crop = get_object_or_404(Crop, pk=crop_id)  # Get the crop

    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 0))  # Get the quantity from the form

        # Check if quantity is valid
        if quantity <= 0 or quantity > crop.stock:
            messages.error(request, "Invalid quantity selected.")
            return redirect('crop_details', crop_id=crop.id)

        # Create an order record or cart entry (based on your design)
        order = Order.objects.create(crop=crop, quantity=quantity)  # Example order creation

        crop.stock -= quantity  # Deduct the purchased quantity from stock
        crop.save()  # Save the updated crop

        messages.success(request, f"You have successfully purchased {quantity} kg of {crop.name}.")

        # Redirect to a checkout or confirmation page
        return redirect('check_out')  # Change 'checkout_page' to your actual URL name



def farmer_notifications(request):
    user = Registeruser.objects.get(user_id=request.session['user_id'])
    notifications = Notification.objects.filter(farmer=user).order_by('-created_at')

    # Mark all unread notifications as read
    unread_notifications = notifications.filter(is_read=False)
    unread_notifications.update(is_read=True)

    return render(request, 'farmer_notifications.html', {
        'notifications': notifications,
    })


from datetime import timedelta

def order_details(request, order_id):
    # Check if the user is logged in through session
    user_id = request.session.get('user_id')  # Retrieve user ID from session

    # Check if user_id exists in session
    if user_id is None:
        # Handle the case where the user is not logged in
        return redirect('login')  # Redirect to your login page or handle as needed

    # Retrieve the order details
    order = get_object_or_404(Order, id=order_id)

    # Compare user IDs using session data
    if user_id != order.user.user_id:
        # If the user does not match the order's user, redirect to order history
        return redirect('order_history')  # Redirect to order history if not authorized

    # Get the status history for this order
    status_history = OrderStatusHistory.objects.filter(order=order).order_by('timestamp')

    # Calculate the expected delivery date (3 days after the order date)
    expected_delivery_date = order.order_date + timedelta(days=3)

    context = {
        'order': order,
        'status_history': status_history,
        'expected_delivery_date': expected_delivery_date,
    }

    # Render the order details page with the context
    return render(request, 'order_details.html', context)



def cancel_order(request, order_id):
    try:
        order = get_object_or_404(Order, id=order_id)
        
        # Check if order belongs to current user
        if order.user.user_id != request.session.get('user_id'):
            messages.error(request, 'Unauthorized access')
            return redirect('order_history')
            
        # Only allow cancellation of pending orders
        if order.status != 'Pending':
            messages.error(request, 'Only pending orders can be cancelled')
            return redirect('order_details', order_id=order_id)
        
        # Restock items
        order_items = OrderItem.objects.filter(order=order)
        for item in order_items:
            crop = item.crop
            # Add the quantity back to stock
            crop.stock += item.quantity
            crop.save()
            print(f"Restocked {item.quantity} units of {crop.name}")  # Debug log
        
        # Update order status
        order.status = 'Cancelled'
        order.save()
        
        messages.success(request, 'Order cancelled successfully and items restocked')
        return redirect('order_history')
        
    except Exception as e:
        print(f"Error in cancel_order: {str(e)}")  # Debug log
        messages.error(request, 'Error cancelling order')
        return redirect('order_details', order_id=order_id)



import razorpay

razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def check_out_step2(request):
    user = Registeruser.objects.get(user_id=request.session['user_id'])
    cart_items = Cart.objects.filter(user=user)

    # Calculate total price in rupees
    total_price = sum(item.get_total_price() for item in cart_items)

    # Convert total_price to paise for Razorpay (without using multiply in HTML)
    total_price_in_paise = int(total_price * 100)

    # Create a Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": total_price_in_paise,
        "currency": "INR",
        "payment_capture": "1"
    })

    # Save Razorpay order ID in the session to use it in the payment verification step
    request.session['razorpay_order_id'] = razorpay_order['id']

    return render(request, 'checkout_step2.html', {
        'user': user,
        'cart_items': cart_items,
        'total_price': total_price,  # Keep in rupees for display
        'razorpay_order_id': razorpay_order['id'],
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
    })



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def verify_payment(request):
    if request.method == "POST":
        data = request.POST
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        try:
            # Verify the payment signature
            razorpay_client.utility.verify_payment_signature(params_dict)
            
            # Retrieve the user and cart details
            user = Registeruser.objects.get(user_id=request.session['user_id'])
            cart_items = Cart.objects.filter(user=user)
            total_price = sum(item.get_total_price() for item in cart_items)

            # Create an order
            order = Order.objects.create(
                user=user,
                name=request.session['updated_user_details']['name'],
                contact=request.session['updated_user_details']['contact'],
                email=request.session['updated_user_details']['email'],
                place=request.session['updated_user_details']['place'],
                pincode=request.session['updated_user_details']['pincode'],
                delivery_address=request.session['updated_user_details']['delivery_address'],
                total_price=total_price,
                payment_method='Razorpay'
            )

            # Add cart items as order items and clear the cart
            for item in cart_items:
                OrderItem.objects.create(
                    order=order,
                    crop=item.crop,
                    quantity=item.quantity,
                    price=item.crop.price
                )
                item.crop.stock -= item.quantity
                item.crop.save()

            cart_items.delete()
            request.session['cart'] = []

            # Return success response
            return JsonResponse({"status": "Payment Successful!", "order_id": order.id})
        
        except razorpay.errors.SignatureVerificationError:
            return JsonResponse({"status": "Payment Verification Failed!"})
    
    return JsonResponse({"status": "Invalid Request"})




def government_schemes(request):
    GOVERNMENT_SCHEME_LINKS = [
        {"name": "PM Kisan Samman Nidhi", "url": "https://pmkisan.gov.in/"},
        {"name": "Pradhan Mantri Fasal Bima Yojana", "url": "https://pmfby.gov.in/"},
        {"name": "Soil Health Card Scheme", "url": "https://soilhealth.dac.gov.in/"},
        {"name": "National Agricultural Market (eNAM)", "url": "https://www.enam.gov.in/"},
        {"name": "Agriculture Infrastructure Fund", "url": "https://www.agriinfra.dac.gov.in/"},
    ]
    return render(request, 'schemes/government_schemes.html', {"scheme_links": GOVERNMENT_SCHEME_LINKS})


from django.http import JsonResponse
from google.cloud import dialogflow_v2 as dialogflow

PROJECT_ID = 'farmingbot-ywiv'  # Replace with your Dialogflow project ID

def chat_with_bot(request):
    # Get the user message from the request
    user_message = request.GET.get('message', '')

    # Set up Dialogflow session
    session_id = "12345"  # You can use a unique ID for each user
    session_client = dialogflow.SessionsClient()
    session = session_client.session_path(PROJECT_ID, session_id)

    # Prepare the text input
    text_input = dialogflow.TextInput(text=user_message, language_code="en")
    query_input = dialogflow.QueryInput(text=text_input)

    # Send the request to Dialogflow
    response = session_client.detect_intent(request={"session": session, "query_input": query_input})
    bot_reply = response.query_result.fulfillment_text

    # Send the bot's reply back to the user
    return JsonResponse({"response": bot_reply})


def chatbot_page(request):
    return render(request, 'chatbot.html')


def manage_delivery_boy_requests(request):
    if request.method == "POST":
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')
        user = get_object_or_404(Registeruser, pk=user_id)

        try:
            if action == "activate":
                user.is_verified = True
                user.save()

                # Update the verified status in the DeliveryBoyDetail table
                delivery_boy_detail, created = DeliveryBoyDetail.objects.get_or_create(
                    user=user,
                    defaults={
                        'name': user.name,
                        'contact': user.contact,
                        'place': user.place,
                        'email': user.email
                    }
                )
                delivery_boy_detail.verified = True
                delivery_boy_detail.save()

                # Create the activation link
                activation_link = reverse('complete_delivery_boy_details', kwargs={'user_id': user.user_id})
                full_link = request.build_absolute_uri(activation_link)

                # Send activation email with proper email configuration
                email_subject = "Activate Your Delivery Boy Account"
                email_message = f"""
                Hi {user.name},

                Your account has been activated. Please complete your registration by clicking the link below:

                {full_link}

                If you did not request this activation, please ignore this email.

                Best regards,
                Admin Team
                """

                try:
                    send_mail(
                        subject=email_subject,
                        message=email_message,
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                    messages.success(request, f"Account activated and activation email sent to {user.email}")
                except Exception as e:
                    messages.warning(request, f"Account activated but email failed to send: {str(e)}")

            elif action == "deactivate":
                user.is_verified = False
                user.save()

                delivery_boy_detail = DeliveryBoyDetail.objects.filter(user=user).first()
                if delivery_boy_detail:
                    delivery_boy_detail.verified = False
                    delivery_boy_detail.save()

                # Send deactivation email
                try:
                    send_mail(
                        subject="Account Deactivation",
                        message=f"Hi {user.name}, your account has been deactivated. Please contact admin for details.",
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                    messages.success(request, f"{user.name}'s account deactivated and notification email sent.")
                except Exception as e:
                    messages.warning(request, f"Account deactivated but email failed to send: {str(e)}")

        except Exception as e:
            messages.error(request, f"Error processing request: {str(e)}")

        return redirect('manage_delivery_boy_requests')

    # Fetch pending and verified delivery boys
    pending_requests = Registeruser.objects.filter(role='delivery_boy', is_verified=False)
    verified_users = Registeruser.objects.filter(role='delivery_boy', is_verified=True)

    return render(request, 'manage_delivery_boy_requests.html', {
        'pending_requests': pending_requests,
        'verified_users': verified_users,
    })


def complete_delivery_boy_details(request, user_id):
    user = get_object_or_404(Registeruser, pk=user_id)

    if request.method == 'POST':
        try:
            # Get the form data
            vehicle_type = request.POST.get('vehicle_type')
            vehicle_number = request.POST.get('vehicle_number')
            license_number = request.POST.get('license_number')
            area_of_service = request.POST.get('area_of_service')
            additional_documents = request.FILES.get('additional_documents')

            # Get or create the DeliveryBoyDetail instance
            delivery_boy_detail, created = DeliveryBoyDetail.objects.get_or_create(
                user=user,
                defaults={
                    'name': user.name,
                    'contact': user.contact,
                    'place': user.place,
                    'email': user.email,
                }
            )

            # Update the delivery boy details
            delivery_boy_detail.vehicle_type = vehicle_type
            delivery_boy_detail.vehicle_number = vehicle_number
            delivery_boy_detail.license_number = license_number
            delivery_boy_detail.area_of_service = area_of_service
            if additional_documents:
                delivery_boy_detail.additional_documents = additional_documents
            delivery_boy_detail.completed_registration = True
            delivery_boy_detail.verified = True
            delivery_boy_detail.save()

            # Update Registeruser to mark it as verified
            user.is_verified = True
            user.save()

            messages.success(request, "Delivery boy details successfully completed.")
            return redirect('delivery_boy_dashboard')  # Redirect to dashboard after completion

        except Exception as e:
            messages.error(request, f"Error saving details: {str(e)}")
            print(f"Error: {str(e)}")  # For debugging

    return render(request, 'complete_delivery_details.html', {'user': user})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def delivery_boy_dashboard(request):
    try:
        delivery_boy = DeliveryBoyDetail.objects.get(user__user_id=request.session.get('user_id'))
        
        # Get all assigned orders that are not delivered
        assigned_orders = Order.objects.filter(
            assigned_delivery_boy=delivery_boy,
            status__in=['Pending', 'Assigned', 'Accepted', 'Out for Delivery']
        ).order_by('-order_date')

        # Calculate statistics
        total_orders = Order.objects.filter(
            assigned_delivery_boy=delivery_boy
        ).count()

        pending_orders = Order.objects.filter(
            assigned_delivery_boy=delivery_boy,
            status__in=['Pending', 'Assigned', 'Accepted', 'Out for Delivery']
        ).count()

        completed_orders = Order.objects.filter(
            assigned_delivery_boy=delivery_boy,
            status='Delivered'
        ).count()

        context = {
            'delivery_boy': delivery_boy,
            'assigned_orders': assigned_orders,
            'total_orders': total_orders,
            'pending_orders': pending_orders,
            'completed_orders': completed_orders,
        }
        
        return render(request, 'delivery_boy_dashboard.html', context)
    except DeliveryBoyDetail.DoesNotExist:
        messages.error(request, 'Delivery boy profile not found')
        return redirect('login')



def assign_delivery_boy(request):
    unassigned_orders = Order.objects.filter(assigned_delivery_boy__isnull=True)
    verified_delivery_boys = DeliveryBoyDetail.objects.filter(verified=True)
    delivery_boys = [boy.user for boy in verified_delivery_boys]
    recent_assignments = Order.objects.filter(
        assigned_delivery_boy__isnull=False
    ).order_by('-order_date')[:5]
    
    all_delivery_boys = DeliveryBoyDetail.objects.all()
    all_orders = Order.objects.all().order_by('-order_date')

    if request.method == "POST":
        order_id = request.POST.get('order_id')
        delivery_boy_id = request.POST.get('delivery_boy_id')

        try:
            order = Order.objects.get(id=order_id)
            delivery_boy = DeliveryBoyDetail.objects.get(user__user_id=delivery_boy_id)

            # Assign the delivery boy to the order
            order.assigned_delivery_boy = delivery_boy
            order.save()

            messages.success(request, f'Order #{order_id} successfully assigned to {delivery_boy.name}')
            return redirect('assign_delivery_boy')

        except Order.DoesNotExist:
            messages.error(request, 'Order not found')
        except DeliveryBoyDetail.DoesNotExist:
            messages.error(request, 'Delivery boy not found')
        except Exception as e:
            messages.error(request, f'Error assigning delivery boy: {str(e)}')

    context = {
        'unassigned_orders': unassigned_orders,
        'delivery_boys': delivery_boys,
        'recent_assignments': recent_assignments,
        'today_assignments': Order.objects.filter(
            assigned_delivery_boy__isnull=False,
            order_date__date=timezone.now().date()
        ).count(),
        'all_orders': all_orders,
        'all_delivery_boys': all_delivery_boys
    }

    return render(request, 'assign_delivery_boy.html', context)



def assign_delivery_boy_auto():
    """Automatically assigns unassigned orders to available delivery boys."""
    unassigned_orders = Order.objects.filter(assigned_delivery_boy__isnull=True, is_canceled=False)
    available_boys = DeliveryBoyDetail.objects.filter(verified=True)

    for order in unassigned_orders:
        least_busy_boy = available_boys.annotate(order_count=models.Count('assigned_orders')).order_by('order_count').first()
        
        if least_busy_boy:
            order.assigned_delivery_boy = least_busy_boy
            order.save()
            print(f"Assigned Order {order.id} to {least_busy_boy.name}")

def order_list(request):
    """View all orders, auto-assign delivery boys if needed."""
    assign_delivery_boy_auto()  # Automatically assign delivery boys before showing orders
    orders = Order.objects.all().order_by('-order_date')

    context = {
        'orders': orders,
    }
    return render(request, 'orders_list.html', context)


def delivery_boy_orders(request, delivery_boy_id):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('login')

    try:
        # Fetch the delivery boy using the provided delivery_boy_id
        delivery_boy = get_object_or_404(DeliveryBoyDetail, id=delivery_boy_id, user__user_id=user_id)
        orders = Order.objects.filter(assigned_delivery_boy=delivery_boy).order_by('-order_date')

        # Fetch the latest location for each order
        for order in orders:
            latest_status = OrderStatusHistory.objects.filter(order=order).order_by('-timestamp').first()
            order.location = latest_status.location if latest_status else 'Location not available'

        context = {
            'delivery_boy': delivery_boy,
            'assigned_orders': orders,
        }
        return render(request, 'delivery_boy_orders.html', context)

    except Exception as e:
        messages.error(request, f'Error loading orders: {str(e)}')
        return redirect('login')



@require_POST
def update_order_status(request):
    try:
        order_id = request.POST.get('order_id')
        new_status = request.POST.get('status')
        location = request.POST.get('location')  # Capture the location
        order = get_object_or_404(Order, id=order_id)

        # Check delivery boy authorization
        delivery_boy = get_object_or_404(DeliveryBoyDetail, user__user_id=request.session.get('user_id'))
        
        if order.assigned_delivery_boy != delivery_boy:
            return JsonResponse({'success': False, 'message': 'You are not authorized to update this order'})

        # Update the order status
        order.status = new_status
        order.save()

        # Create a new OrderStatusHistory entry
        OrderStatusHistory.objects.create(
            order=order,
            status=new_status,
            location=location  # Save the location with the status
        )

        return JsonResponse({'success': True, 'new_status': new_status})

    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error updating order status: {str(e)}'})



def check_new_orders(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('login')

    try:
        delivery_boy = get_object_or_404(DeliveryBoyDetail, user__user_id=user_id)
        new_orders = Order.objects.filter(
            assigned_delivery_boy=delivery_boy,
            status='Assigned'
        )

        context = {
            'delivery_boy': delivery_boy,
            'new_orders': new_orders,
            'has_new_orders': new_orders.exists(),
        }
        return render(request, 'delivery_boy_dashboard.html', context)
    except Exception as e:
        messages.error(request, f'Error checking new orders: {str(e)}')
        return redirect('login')




def unassign_delivery_boy(request, order_id):
    """Unassign a delivery boy from an order and reassign if a previous order exists with the same address/pincode."""
    
    if request.method == "POST":  
        order = get_object_or_404(Order, id=order_id)  # Fetch order safely

        if order.assigned_delivery_boy:  
            order.assigned_delivery_boy = None  # Unassign the delivery boy
            order.save()
            messages.success(request, f"Delivery boy unassigned from Order #{order.id}.")
        else:
            messages.warning(request, f"Order #{order.id} has no assigned delivery boy.")
        
        # Check for any previous order with the same delivery_address or pincode
        previous_order = Order.objects.filter(
            delivery_address=order.delivery_address,  # Correct field name
            assigned_delivery_boy__isnull=False  # Ensure a delivery boy is assigned
        ).order_by('-id').first()  # Get the latest matching order

        if previous_order:
            order.assigned_delivery_boy = previous_order.assigned_delivery_boy  # Assign the same delivery boy
            order.save()
            messages.success(request, f"Order #{order.id} reassigned to delivery boy {order.assigned_delivery_boy.name}.")

    return redirect('assign_delivery_boy')  # Redirect to orders page





# views.py
from django.http import JsonResponse
import pickle
import pandas as pd
import numpy as np
import os

# Function to predict crop price
def predict_crop_price(crop_name, date):
    # Convert the date to ordinal (same as in training)
    date_ordinal = pd.to_datetime(date).toordinal()
    
    # Sanitize the crop name
    crop_name = crop_name.strip().lower().replace(' ', '_')
    
    # Construct the model file path
    model_filename = os.path.join("ml_model", f"price_model_{crop_name}.pkl")
    
    # Debugging step: print the model filename
    print(f"Trying to load model from: {model_filename}")
    
    # Check if the model file exists
    if not os.path.exists(model_filename):
        return {"error": "Model not found for the specified crop"}
    
    # Load the trained model for the crop
    with open(model_filename, 'rb') as f:
        model = pickle.load(f)
    
    # Make the prediction
    predicted_price = model.predict(pd.DataFrame([[date_ordinal]], columns=['Date']))
    return predicted_price[0]

# Example prediction
date_input = '06/01/2025'  # Input date
crop_input = 'Rice'        # Input crop
predicted_price = predict_crop_price(crop_input, date_input)

print(f"Predicted price of {crop_input} on {date_input}: {predicted_price}")


# View to predict price
def get_predicted_price(request):
    crop_name = request.GET.get('crop')
    date_input = request.GET.get('date')  # Format: 'DD/MM/YYYY'

    if not crop_name or not date_input:
        return JsonResponse({'error': 'Missing crop or date parameter'}, status=400)

    try:
        predicted_price = predict_crop_price(crop_name, date_input)
        if predicted_price is None:
            return JsonResponse({'error': 'Model not found for the specified crop'}, status=404)
        
        return JsonResponse({
            'crop': crop_name,
            'date': date_input,
            'predicted_price': predicted_price
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)




def show_predict_form(request):
    return render(request, 'predict_price_form.html')





from django.http import HttpResponse
import qrcode
from io import BytesIO

def generate_qr_code(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    if order.status != "Out for Delivery":
        return HttpResponse("QR Code is only available when the order is 'Out for Delivery'.", status=400)
    
    # Update this line to use the new view
    confirmation_url = f"http://127.0.0.1:8000/qr-scan/{order_id}/"
    qr = qrcode.make(confirmation_url)
    
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    
    return HttpResponse(buffer.getvalue(), content_type="image/png")











def verify_qr(request, order_id):
    """Verify QR Code and mark order as delivered"""
    order = get_object_or_404(Order, id=order_id)

    if order.status == "out_for_delivery":
        order.status = "delivered"
        order.is_verified = True
        order.save()
        return JsonResponse({"message": "Order successfully delivered!"})
    else:
        return JsonResponse({"error": "Invalid Order Status"}, status=400)
    

def confirm_delivery(request, order_id):
    """Mark order as delivered when QR code is scanned."""
    order = get_object_or_404(Order, id=order_id)

    if order.status == "Out for Delivery":
        order.status = "Delivered"
        order.save()
        return HttpResponse("Order has been successfully marked as Delivered!")

    return HttpResponse("Invalid QR Code or Order is not Out for Delivery.")




@csrf_exempt
def send_location(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        delivery_boy_id = data.get('delivery_boy_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        # Update the location in the database
        try:
            delivery_boy = DeliveryBoyDetail.objects.get(id=delivery_boy_id)
            delivery_boy.latitude = latitude
            delivery_boy.longitude = longitude
            delivery_boy.save()
            return JsonResponse({'status': 'success', 'message': 'Location updated successfully'})
        except DeliveryBoyDetail.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Delivery boy not found'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def track_delivery(request, order_id):
    # Fetch the order using the given order_id
    order = get_object_or_404(Order, id=order_id)

    # Retrieve the delivery boy assigned to the order
    delivery_boy = order.assigned_delivery_boy  # Use the correct field name

    # Pass the delivery boy details and order to the template
    return render(request, 'farm/track_delivery.html', {'delivery_boy': delivery_boy, 'order': order})





def post_harvest(request):
    if request.method == 'POST':
        # Collect data from the form
        crop = request.POST.get('crop')
        temperature = request.POST.get('temperature')
        humidity = request.POST.get('humidity')
        sale_date = request.POST.get('sale_date')
        storage = request.POST.get('storage')

        # Mock response (Replace this with your ML logic or database queries)
        recommendations = {
            "spoilage_prediction": "Tomatoes will spoil in 4 days under current conditions.",
            "action": "Reduce temperature to 20°C and humidity to 50%.",
            "packaging": "Use padded crates to reduce bruising.",
            "market_price": "Sell within 5 days for Rs 2.50/kg."
        }

        # Render results on the same page or redirect to another page
        return render(request, 'post_harvest_form.html', {'recommendations': recommendations, 'submitted': True})

    # If GET request, show the form
    return render(request, 'post_harvest_form.html', {'submitted': False})


import os
import pickle
import numpy as np
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from sklearn.ensemble import RandomForestClassifier

def predict_spoilage(request):
    try:
        if request.method == 'POST':
            # Convert input values to float first
            temperature = float(request.POST.get('temperature'))
            humidity = float(request.POST.get('humidity'))
            crop = request.POST.get('crop').lower()

                        # Load the model and feature columns
            model_path = os.path.join(settings.BASE_DIR, 'ml_model', 'ml_models', 'post_harvest_model.pkl')
            feature_columns_path = os.path.join(settings.BASE_DIR, 'ml_model', 'ml_models', 'feature_columns.pkl')
            
            with open(model_path, 'rb') as file:
                model = pickle.load(file)
            
            with open(feature_columns_path, 'rb') as file:
                feature_columns = pickle.load(file)

            # Create DataFrame with explicit data types
            input_data = pd.DataFrame(0, index=[0], columns=feature_columns)
            
            # Convert numeric columns to float64
            input_data['temperature'] = input_data['temperature'].astype('float64')
            input_data['humidity'] = input_data['humidity'].astype('float64')
            
            # Set the values after converting data types
            input_data.at[0, 'temperature'] = float(temperature)
            input_data.at[0, 'humidity'] = float(humidity)
            
            # Set the crop type
            crop_column = f'crop_type_{crop}'
            if crop_column in input_data.columns:
                input_data.at[0, crop_column] = 1
            else:
                return JsonResponse({
                    'error': f"Crop type '{crop}' not found. Please enter a valid crop like " + 
                            ", ".join(col.replace('crop_type_', '') for col in feature_columns if col.startswith('crop_type_'))
                })
            
            # **Use ML model to predict spoilage risk**
            prediction = model.predict(input_data)

# The prediction should return the estimated spoilage days
            spoilage_days = int(prediction[0])  # Convert to integer


            # Define optimal ranges for different crops
            optimal_conditions = {
                'wheat': {'temp_min': 10, 'temp_max': 25, 'humidity_min': 45, 'humidity_max': 65, 'max_days': 180},
                'rice': {'temp_min': 12, 'temp_max': 28, 'humidity_min': 50, 'humidity_max': 70, 'max_days': 160},
                'maize': {'temp_min': 10, 'temp_max': 30, 'humidity_min': 40, 'humidity_max': 60, 'max_days': 150},
                # Default conditions for other crops
                'default': {'temp_min': 15, 'temp_max': 25, 'humidity_min': 45, 'humidity_max': 65, 'max_days': 90}
            }

            # Get crop conditions or use default
            crop_conditions = optimal_conditions.get(crop, optimal_conditions['default'])

            # Calculate risk based on temperature and humidity deviations
            temp_risk = 0
            humidity_risk = 0

            # Temperature risk calculation
            if temperature < crop_conditions['temp_min']:
                temp_risk = ((crop_conditions['temp_min'] - temperature) / crop_conditions['temp_min']) * 100
            elif temperature > crop_conditions['temp_max']:
                temp_risk = ((temperature - crop_conditions['temp_max']) / crop_conditions['temp_max']) * 100

            # Humidity risk calculation
            if humidity < crop_conditions['humidity_min']:
                humidity_risk = ((crop_conditions['humidity_min'] - humidity) / crop_conditions['humidity_min']) * 100
            elif humidity > crop_conditions['humidity_max']:
                humidity_risk = ((humidity - crop_conditions['humidity_max']) / crop_conditions['humidity_max']) * 100

            # Calculate overall risk (weighted average)
            overall_risk = (temp_risk * 0.6 + humidity_risk * 0.4)  # Temperature has more weight
            
            # Ensure risk doesn't exceed 100%
            overall_risk = min(100, overall_risk)

            # Calculate spoilage days based on risk
            max_days = crop_conditions['max_days']
            spoilage_days = int(max_days * (1 - (overall_risk / 100)))
            spoilage_days = max(1, spoilage_days)  # Ensure at least 1 day

            # Determine risk level text
            if overall_risk > 75:
                risk_level = "Very High"
            elif overall_risk > 50:
                risk_level = "High"
            elif overall_risk > 25:
                risk_level = "Moderate"
            else:
                risk_level = "Low"

            # Generate recommendations
            recommendations = []
            
            # Existing temperature and humidity recommendations
            if temperature < crop_conditions['temp_min']:
                recommendations.append(
                    f"Increase temperature from {temperature}°C to between "
                    f"{crop_conditions['temp_min']}°C and {crop_conditions['temp_max']}°C"
                )
            elif temperature > crop_conditions['temp_max']:
                recommendations.append(
                    f"Decrease temperature from {temperature}°C to between "
                    f"{crop_conditions['temp_min']}°C and {crop_conditions['temp_max']}°C"
                )

            if humidity < crop_conditions['humidity_min']:
                recommendations.append(
                    f"Increase humidity from {humidity}% to between "
                    f"{crop_conditions['humidity_min']}% and {crop_conditions['humidity_max']}%"
                )
            elif humidity > crop_conditions['humidity_max']:
                recommendations.append(
                    f"Decrease humidity from {humidity}% to between "
                    f"{crop_conditions['humidity_min']}% and {crop_conditions['humidity_max']}%"
                )

            # Add storage condition recommendations based on risk level
            if overall_risk > 75:
                recommendations.extend([
                    "Warning: Unfavorable conditions detected",
                    "Monitor closely",
                    "Consider immediate use",
                    "Check for signs of spoilage every 4-6 hours",
                    "Move to climate-controlled storage if available",
                    "Ensure proper ventilation",
                    "Separate affected produce from healthy ones"
                ])
            elif overall_risk > 50:
                recommendations.extend([
                    "Monitor temperature and humidity twice daily",
                    "Ensure good air circulation",
                    "Check for signs of deterioration daily",
                    "Consider using moisture-absorbing materials",
                    "Maintain cleanliness in storage area"
                ])
            elif overall_risk > 25:
                recommendations.extend([
                    "Regular monitoring recommended",
                    "Maintain current storage conditions",
                    "Check produce quality every 2-3 days",
                    "Keep storage area clean and organized"
                ])
            else:
                recommendations.extend([
                    "Optimal storage conditions",
                    "Continue regular maintenance",
                    "Weekly quality checks recommended"
                ])

            # Add crop-specific recommendations
            if crop == 'rice':
                recommendations.extend([
                    "Store in airtight containers",
                    "Keep away from direct sunlight",
                    "Use neem leaves as natural preservative",
                    "Check for insect infestation regularly",
                    "Maintain proper stacking with pallets"
                ])
            elif crop == 'wheat':
                recommendations.extend([
                    "Ensure moisture content below 12%",
                    "Use food-grade storage bags",
                    "Implement proper fumigation schedule",
                    "Keep storage area dark",
                    "Monitor for mold growth"
                ])
            elif crop == 'maize':
                recommendations.extend([
                    "Ensure proper drying before storage",
                    "Use raised platforms for storage",
                    "Check for aflatoxin development",
                    "Maintain good ventilation",
                    "Regular pest monitoring required"
                ])

            # Add general best practices
            recommendations.extend([
                "Keep storage area clean and sanitized",
                "Implement first-in-first-out (FIFO) inventory management",
                "Document storage conditions daily",
                "Train staff on proper handling procedures",
                "Have emergency response plan ready",
                f"Expected storage life: {spoilage_days} days under current conditions"
            ])

            return JsonResponse({
                'result': f"{risk_level} risk of spoilage",
                'probability': f"{overall_risk:.2f}%",
                'spoilage_days': spoilage_days,
                'details': {
                    'temperature': temperature,
                    'humidity': humidity,
                    'crop': crop,
                    'recommendations': recommendations
                }
            })

        return render(request, 'post_harvest_form.html')

    except Exception as e:
        print(f"Error in predict_spoilage: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def qr_scan_details(request, order_id):
    """Display order details after QR scan"""
    order = get_object_or_404(Order, id=order_id)
    order_items = OrderItem.objects.filter(order=order)
    
    context = {
        'order': order,
        'order_items': order_items,
        'scan_time': datetime.now()
    }
    return render(request, 'qr_scan_confirmation.html', context)

def process_delivery_confirmation(request, order_id):
    """Handle the delivery confirmation POST request"""
    if request.method == 'POST':
        order = get_object_or_404(Order, id=order_id)
        if order.status == "Out for Delivery":
            order.status = "Delivered"
            order.delivery_confirmed_at = datetime.now()
            order.is_verified = True
            order.save()
            
            # Log the status change
            OrderStatusHistory.objects.create(
                order=order,
                status="Delivered",
                location=order.place,
                timestamp=datetime.now()
            )
            
            return JsonResponse({'success': True})
    return JsonResponse({'success': False})






from django.http import JsonResponse
import pandas as pd
import joblib
import os

def predict_crop_demand(request):
    selected_crop = request.GET.get("crop")
    context = {
        'selected_crop': selected_crop,
        'predictions': []
    }

    if selected_crop:  # Only make prediction if a crop is selected
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_dir = os.path.join(base_dir, "models")
            model_path = os.path.join(model_dir, f"{selected_crop.replace(' ', '_')}_model.pkl")

            if not os.path.exists(model_path):
                context['error'] = f"No trained model found for {selected_crop}"
            else:
                # Load the trained model
                model = joblib.load(model_path)

                # Create future data for prediction
                future_data = pd.DataFrame({
                    "Month": [1, 2, 3, 4, 5],
                    "Year": [2025] * 5,
                    "Price (₹)": [50, 55, 60, 65, 70]
                })

                # Predict future demand
                future_demand = model.predict(future_data)
                future_data["Predicted_Sales_kg"] = future_demand
                
                context['predictions'] = future_data.to_dict('records')

        except Exception as e:
            context['error'] = str(e)

    return render(request, 'demand_prediction.html', context)




import matplotlib.pyplot as plt
import seaborn as sns
from django.http import HttpResponse
import io
import pandas as pd
import os
from django.conf import settings  # Import settings to handle file paths

def plot_crop_demand(request):
    crop_name = request.GET.get("crop")  # Dynamically get crop from request

    if not crop_name:
        return HttpResponse("Crop name is required.", status=400)

    # Construct the correct file path
    csv_path = os.path.join(settings.BASE_DIR, "data", "future_demand_predictions.csv")

    if not os.path.exists(csv_path):
        return HttpResponse("Prediction data not found.", status=400)

    # Read the CSV file
    try:
        future_data = pd.read_csv(csv_path)

        # Ensure column names are properly formatted
        future_data.columns = future_data.columns.str.strip()

        if "Crop Name" not in future_data.columns or "Month" not in future_data.columns or "Predicted Sales (kg)" not in future_data.columns:
            return HttpResponse("Invalid CSV format. Check column names.", status=400)

        # Filter by crop name
        future_data = future_data[future_data["Crop Name"].str.strip() == crop_name.strip()]

        if future_data.empty:
            return HttpResponse(f"No data found for {crop_name}.", status=400)

        # Create the plot
        plt.figure(figsize=(8, 4))
        sns.lineplot(x=future_data["Month"], y=future_data["Predicted Sales (kg)"], marker="o")
        plt.xlabel("Month")
        plt.ylabel("Predicted Sales (kg)")
        plt.title(f"Future Demand for {crop_name}")

        # Convert plot to HTTP response
        buf = io.BytesIO()
        plt.savefig(buf, format="png")
        plt.close()
        buf.seek(0)

        return HttpResponse(buf.getvalue(), content_type="image/png")

    except Exception as e:
        return HttpResponse(f"Error reading data: {str(e)}", status=500)



from django.shortcuts import render
from django.http import JsonResponse
from django.db.models import Sum
from .models import OrderItem, Crop

def farmer_sales_data(request):
    try:
        # Get all orders and group them by status
        order_stats = Order.objects.values('status').annotate(
            count=Count('id')
        )
        print(f"Order statistics: {order_stats}")
        
        # Prepare data for the chart
        labels = []
        counts = []
        colors = {
            'Pending': 'rgba(255, 206, 86, 0.6)',      # Yellow
            'Out for Delivery': 'rgba(54, 162, 235, 0.6)',     # Blue
            'Delivered': 'rgba(75, 192, 192, 0.6)'    # Green
        }
        background_colors = []
        
        # Define the order of statuses as you want them to appear
        status_order = ['Pending', 'Out for Delivery', 'Delivered']
        
        # Sort the data according to the defined order
        for status in status_order:
            for stat in order_stats:
                if stat['status'] == status:
                    labels.append(stat['status'])
                    counts.append(stat['count'])
                    background_colors.append(colors.get(stat['status'], 'rgba(201, 203, 207, 0.6)'))
        
        data = {
            'labels': labels,
            'counts': counts,
            'backgroundColor': background_colors
        }
        print(f"Sending data: {data}")
        
        return JsonResponse(data)
    except Exception as e:
        print(f"Error in farmer_sales_data: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
    


def sales_analytics(request):
    # Fetch all sold crops from OrderItem
    order_items = OrderItem.objects.select_related('crop')

    # Dictionary to store aggregated crop sales data
    crop_sales = {}

    for item in order_items:
        crop_name = item.crop.name
        quantity = item.quantity
        revenue = item.quantity * item.price  

        if crop_name in crop_sales:
            crop_sales[crop_name]['quantity'] += quantity
            crop_sales[crop_name]['revenue'] += revenue
        else:
            crop_sales[crop_name] = {'quantity': quantity, 'revenue': revenue}

    # Extract data for the template
    crops = list(crop_sales.keys())
    quantities = [data['quantity'] for data in crop_sales.values()]
    revenues = [data['revenue'] for data in crop_sales.values()]

    return render(request, 'sales.html', {
        'crops': crops,
        'quantities': quantities,
        'revenues': revenues,
        'total_crops': len(crops),
        'total_quantity': sum(quantities),
        'total_revenue': sum(revenues),
    })


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import BulkOrder, Crop, Registeruser

def place_bulk_order(request, crop_id):
    crop = get_object_or_404(Crop, id=crop_id)

    if request.method == "POST":
        buyer_id = request.session.get("user_id")  # Get logged-in user ID from session
        if not buyer_id:
            messages.error(request, "You must be logged in to place an order.")
            return redirect("login")

        quantity = request.POST.get("quantity")
        delivery_date = request.POST.get("delivery_date")

        if not quantity or not delivery_date:
            messages.error(request, "All fields are required.")
            return redirect("place_bulk_order", crop_id=crop.id)

        buyer = get_object_or_404(Registeruser, user_id=buyer_id)  # Fetch buyer from Registeruser model

        BulkOrder.objects.create(
            buyer=buyer,
            crop=crop,
            quantity=quantity,
            delivery_date=delivery_date,
            status="Pending"
        )

        messages.success(request, "Your bulk order request has been sent!")
        return redirect("buyer_dashboard")

    return render(request, "place_bulk_order.html", {"crop": crop})



def manage_bulk_orders(request):
    farmer_id = request.session.get("user_id")  # Get farmer ID from session
    if not farmer_id:
        return redirect("login")

    bulk_orders = BulkOrder.objects.filter(crop__farmer_id=farmer_id).order_by("-created_at")  # Sort by latest orders
    return render(request, "manage_bulk_orders.html", {"bulk_orders": bulk_orders})

def update_bulk_order_status(request, order_id, status):
    order = get_object_or_404(BulkOrder, id=order_id)

    # Ensure only the correct farmer updates the order
    if order.crop.farmer_id != request.session.get("user_id"):
        messages.error(request, "You are not authorized to update this order.")
        return redirect("manage_bulk_orders")

    # Prevent updates on already rejected or delivered orders
    if order.status in ["Rejected", "Delivered"]:
        messages.warning(request, f"You cannot update an order that is already {order.status.lower()}.")
        return redirect("manage_bulk_orders")

    order.status = status
    order.save()

    # **Add crop to cart if order is accepted**
    if status == "Accepted":
        buyer = order.buyer  # Assuming `buyer` is a ForeignKey to `Registeruser`
        crop = order.crop
        quantity = max(order.quantity, 1)  # Ensure quantity is a positive integer
        delivery_date = order.delivery_date  # Get delivery date from BulkOrder

        # Check if item already exists in the cart
        cart_item, created = Cart.objects.get_or_create(
            user=buyer, crop=crop,
            defaults={"quantity": quantity, "delivery_date": delivery_date}
        )

        if not created:
            cart_item.quantity += quantity  # Update existing quantity
            cart_item.delivery_date = delivery_date  # Update delivery date
            cart_item.save()

    # **Notify buyer about the status update via email**
    buyer_email = order.buyer.email
    if buyer_email:
        send_mail(
            subject="Bulk Order Status Update",
            message=f"Your bulk order for {order.crop.name} has been {status.lower()}. Expected delivery: {order.delivery_date}.",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[buyer_email],
            fail_silently=True,
        )

    messages.success(request, f"Order has been {status.lower()}!")
    return redirect("manage_bulk_orders")
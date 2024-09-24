from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
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
from .models import Registeruser, Adminm
from .forms import SetPasswordForm
from .tokens import custom_token_generator
from django.contrib.sites.shortcuts import get_current_site
import logging
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import logout 
from .models import Crop, CropImage
from django.views.decorators.cache import cache_control
from django.shortcuts import get_object_or_404






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
            return redirect('adminfarm')  # Replace 'admin_dashboard' with the correct URL name

        # Check if the user is a farmer or buyer
        user = Registeruser.objects.filter(email=email, password=password).first()
        if user:
            request.session['user_id'] = user.user_id
            request.session['name'] = user.name
            request.session['role'] = user.role

            # Redirect based on role
            if user.role == 'farmer':
                return redirect('farmer_dashboard')  # Replace 'farmer_dashboard' with the correct URL name
            elif user.role == 'buyer':
                return redirect('buyer_dashboard')  # Replace 'buyer_dashboard' with the correct URL name
        else:
            messages.error(request, 'Invalid email or password')
            return render(request, 'login.html')

    return render(request, 'login.html')



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_logout(request):
    request.session.flush()  # Clears the session data
    return redirect('index')  # Redirects to the login page

               
""" def password_reset_form(request):
    if request.method == "POST":
        email = request.POST['email'].strip().lower()  # Normalize the email
        try:
            user = Registeruser.objects.get(email=email)
        except User.DoesNotExist:
            return render(request, 'password_reset_form.html', {'error': 'No account found with this email.'})
        
        # Generate token and UID
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Prepare email context
        current_site = get_current_site(request)
        mail_subject = 'Password Reset Request'
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
        })
        
        # Send email
        send_mail(mail_subject, message, 'noreply@example.com', [email])
        
        return redirect('password_reset_done')
    
    return render(request, 'password_reset_form.html')



# Step 2: Password Reset Confirm View
def password_reset_confirm(request, uidb64=None, token=None):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return render(request, 'password_reset_confirm.html', {'error': 'Passwords do not match.'})

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            print(f'Decoded UID: {uid}')
            
            user_exists = User.objects.filter(pk=uid).exists()
            if not user_exists:
                print(f'User with ID {uid} does not exist.')
                raise User.DoesNotExist

            user = User.objects.get(pk=uid)
            print(f'User found: {user}')
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            print(f'Error decoding UID or retrieving user: {e}')
            return render(request, 'password_reset_confirm.html', {'error': 'User not found or UID decoding issue.'})

        is_token_valid = default_token_generator.check_token(user, token)
        print(f'Token: {token}')
        print(f'Token Validity: {is_token_valid}')

        if is_token_valid:
            user.set_password(new_password)
            user.save()
            return redirect('password_reset_complete')
        else:
            return render(request, 'password_reset_confirm.html', {'error': 'Invalid or expired token. Please request a new password reset.'})

    return render(request, 'password_reset_confirm.html', {'uid': uidb64, 'token': token})




# Step 3: Password Reset Done View
def password_reset_done(request):
    return render(request, 'password_reset_done.html')

# Step 4: Password Reset Complete View
def password_reset_complete(request):
    return render(request, 'password_reset_complete.html')
               
 """
""" def forgot_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            # Retrieve the user by email only
            user = Registeruser.objects.get(email=email)
            current_site = get_current_site(request)
            token = custom_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.user_id))  # Ensure 'id' is used

            # Reset link adjusted for your eFarming system
            reset_link = f"http://{current_site.domain}/reset/{uid}/{token}/"

            subject = 'Password Reset Request'
            html_message = render_to_string('reset_email.html', {
                'user': user,
                'reset_link': mark_safe(reset_link),
            })
            plain_message = strip_tags(html_message)

            email_message = EmailMessage(
                subject,
                html_message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email]
            )
            email_message.content_subtype = 'html'
            email_message.send(fail_silently=False)

            messages.success(request, 'A reset link has been sent to your email.')
            return redirect('login')

        except Registeruser.DoesNotExist:
            messages.error(request, 'Invalid email address.')
            return render(request, 'forgot.html')
    return render(request, 'forgot.html')

def reset_password_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = Registeruser.objects.get(user_id=uid)  # Use `id` instead of `user_id`
    except (TypeError, ValueError, OverflowError, Registeruser.DoesNotExist):
        user = None

    if user and custom_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(request.POST, user=user)
            if form.is_valid():
                new_password = form.cleaned_data.get('new_password')
                user.set_password(new_password)  # Hash the password
                user.save()

                send_mail(
                    'Password Reset Successful',
                    f'Hello {user.name}, your password in the eFarming system has been successfully reset. Thank you!',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )

                messages.success(request, 'Your password has been reset successfully.')
                return redirect('login')
        else:
            form = SetPasswordForm(user=user)
        return render(request, 'reset_password.html', {'form': form, 'valid_link': True})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('forgot')
 """

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
    if request.session.get('user_id'):
        farmer_name = request.session.get('name')  # Get farmer's name from session
        return render(request, 'farmer_dashboard.html', {'farmer_name': farmer_name})
    else:
        return redirect('login')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def buyer_dashboard(request):
    if request.session.get('user_id'):
        buyer_name = request.session.get('name')  # Get buyer's name from session
        return render(request, 'buyer_dashboard.html', {'buyer_name': buyer_name})
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
                messages.success(request, 'Password reset link has been sent to your email.')
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
                messages.success(request, 'Password reset successful. You can now log in.')
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



""" def addcrops(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        category = request.POST.get('category')
        image = request.FILES.get('image')

        # Create a new Crop instance and assign the user
        crop = Crop(
            name=name,
            description=description,
            price=price,
            category=category,
            image=image,
            added_by=request.user  # This should be a User instance
        )
        crop.save()

        return redirect('success_url')  # Redirect to a success page or wherever you want

    return render(request, 'addcrops.html')  # Render your form template

# View to list all crops
def crop_list(request):
    crops = Crop.objects.all()
    return render(request, 'crop_list.html', {'crops': crops})

# View to see crop details
def crop_detail(request, crop_id):
    crop = Crop.objects.get(id=crop_id)
    return render(request, 'crop_detail.html', {'crop': crop}) """


def farmercrops(request):
    crops = Crop.objects.all()  # Fetch all crops
    return render(request, 'farmercrops.html', {'crops': crops})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
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
            farmer=farmer  # Now this is a User instance
        )
        
        # Handle crop images
        crop_photos = request.FILES.getlist('crop_photos')  # Handling multiple image files
        for photo in crop_photos:
            CropImage.objects.create(crop=crop_instance, image=photo)  # Saving each image to CropImage

        messages.success(request, 'Crop added successfully')
        
        return redirect('addcrops')  # Redirect to the farmer dashboard after crop addition
    
    return render(request, 'addcrops.html')  # Render the crop addition form




def crops_page(request):
    crops = Crop.objects.all()  # Fetch all crops
    return render(request, 'crops_page.html', {'crops': crops})

def crop_details(request, id):
    # Fetch the crop object based on the id
    crop_instance = Crop.objects.get(id=id)
    # Render the crop details page with the fetched crop instance
    return render(request, 'crop_details.html', {'crop': crop_instance})

# View to list farmers or buyers based on role
def manage_users(request, role):
    users = Registeruser.objects.filter(role=role)
    context = {'users': users, 'role': role}
    return render(request, 'manage_users.html', context)


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


def delete_user(request, user_id):
    user = get_object_or_404(Registeruser, user_id=user_id)
    user.delete()
    return redirect('manage_users', user.role)  # Redirect to the manage users page after deletion


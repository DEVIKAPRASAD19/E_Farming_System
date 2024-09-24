from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.login, name='login'),
    path('register', views.register, name='register'),
    path('adminfarm', views.adminfarm, name='adminfarm'),
    path('adminviews', views.adminviews, name='adminviews'),
    path('about', views.about, name='about'),
    path('contact', views.contact,name='contact'),
    path('farmer_dashboard', views.farmer_dashboard, name='farmer_dashboard'),
    path('buyer_dashboard', views.buyer_dashboard, name='buyer_dashboard'),
    path('logout', views.user_logout, name='logout'),
    path('farmercrops', views.farmercrops, name='farmercrops'),
    path('salesview', views.salesview, name='salesview'),
    path('profile', views.profile, name='profile'),
    path('forgotpass', views.forgotpass, name='forgotpass'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('updateprofile', views.updateprofile, name='updateprofile'),
    path('updatebuyer', views.updatebuyer, name='updatebuyer'),
    path('addcrops', views.addcrops, name='addcrops'),
    path('crops/', views.crops_page, name='crops_page'),  # For listing all crops
    path('crops/<int:id>/', views.crop_details, name='crop_details'),  # For crop details
    
    path('manage-users/<str:role>/', views.manage_users, name='manage_users'),
    path('update-user/<int:user_id>/', views.update_user, name='update_user'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
   
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# path('password_reset/', views.password_reset_form, name='password_reset_form'),
#  path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
#   path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
#   path('reset/done/', views.password_reset_complete, name='password_reset_complete'),

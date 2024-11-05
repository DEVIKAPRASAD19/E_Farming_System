from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.index, name='index'), 
    path('login/', views.login, name='login'),
    path('register', views.register, name='register'),
    path('adminfarm', views.adminfarm, name='adminfarm'),
    path('adminviews', views.adminviews, name='adminviews'),
    path('about', views.about, name='about'),
    path('contact', views.contact,name='contact'),
    path('farmer_dashboard', views.farmer_dashboard, name='farmer_dashboard'),
    path('buyer_dashboard', views.buyer_dashboard, name='buyer_dashboard'),
    path('logout', views.logout, name='logout'),
    path('farmercrops/', views.farmercrops, name='farmercrops'),
    path('update_crop/<int:id>/', views.update_crop, name='update_crop'),
    path('salesview', views.salesview, name='salesview'),
    path('profile', views.profile, name='profile'),
    path('forgotpass', views.forgotpass, name='forgotpass'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('updateprofile', views.updateprofile, name='updateprofile'),
    path('profile/<int:user_id>/', views.view_profile, name='view_profile'),
    path('updatebuyer', views.updatebuyer, name='updatebuyer'),
    path('addcrops', views.addcrops, name='addcrops'),
    path('crops/', views.crops_page, name='crops_page'),  # For listing all crops
    path('crops/<int:id>/', views.crop_details, name='crop_details'),  # For crop details
    path('search/', views.search_crops, name='search_crops'),
    path('manage-users/<str:role>/', views.manage_users, name='manage_users'),
    path('update-user/<int:user_id>/', views.update_user, name='update_user'),
    path('deactivate_user/<int:user_id>/', views.deactivate_user, name='deactivate_user'),
    path('activate_user/<int:user_id>/', views.activate_user, name='activate_user'),
    path('deactivate_crop/<int:crop_id>/', views.deactivate_crop, name='deactivate_crop'),
    path('activate_crop/<int:crop_id>/', views.activate_crop, name='activate_crop'),
    path('verify-crops/', views.verify_crops, name='verify_crops'),
    path('approve-crop/<int:crop_id>/', views.approve_crop, name='approve_crop'),
    path('reject-crop/<int:crop_id>/', views.reject_crop, name='reject_crop'),
    path('wishlist/', views.wishlist, name='wishlist'),
    path('viewcart', views.viewcart, name='viewcart'),
    path('cart/add/<int:crop_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/update/<int:crop_id>/', views.update_cart, name='update_cart'),
    path('delete/<int:cart_id>/', views.delete_from_cart, name='delete_from_cart'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('enter-email/', views.enter_email, name='enter_email'),
    
    path('stock/', views.crop_stock_details, name='stock'),
    path('stockfarmer/', views.stockfarmer, name='stockfarmer'),
    path('checkout/step1/', views.check_out_step1, name='check_out_step1'),
    path('checkout/step2/', views.check_out_step2, name='check_out_step2'),
     path("verify-payment/", views.verify_payment, name="verify_payment"),
    
    path('update-user-details/', views.update_user_details, name='update_user_details'),
    path('place-order/', views.place_order, name='place_order'),
    path('order-summary/<int:order_id>/', views.order_summary, name='order_summary'),
    path('order-history/', views.order_history, name='order_history'),

    path('weather/', views.weather_update, name='weather_update'),
    path('consultation/', views.expert_consultation, name='expert_consultation'),
    path('notifications/', views.farmer_notifications, name='farmer_notifications'),
    path('buy/<int:crop_id>/', views.buy_crop, name='buy_crop'),  # Add this line

    path('order_details/<int:order_id>/', views.order_details, name='order_details'),
    path('cancel_order/<int:order_id>/', views.cancel_order, name='cancel_order'),  # Cancel Order View
    path('crop/<int:crop_id>/feedback/submit/', views.submit_feedback, name='submit_feedback'),
    path('crop/<int:crop_id>/feedback/', views.display_feedback, name='display_feedback'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# path('password_reset/', views.password_reset_form, name='password_reset_form'),
#  path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
#   path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
#   path('reset/done/', views.password_reset_complete, name='password_reset_complete'),

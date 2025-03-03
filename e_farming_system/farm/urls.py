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
    path('deactivatecrop/<int:crop_id>/', views.deactivatecrop, name='deactivatecrop'),
    path('activatecrop/<int:crop_id>/', views.activatecrop, name='activatecrop'),
    path('about', views.about, name='about'),
    path('contact', views.contact,name='contact'),
    path('farmer_dashboard', views.farmer_dashboard, name='farmer_dashboard'),
    path('buyer_dashboard', views.buyer_dashboard, name='buyer_dashboard'),
    path('logout', views.logout, name='logout'),
    path('farmercrops/', views.farmercrops, name='farmercrops'),
    path('update_crop/<int:crop_id>/', views.update_crop, name='update_crop'),
    path('delete_crop/<int:crop_id>/', views.delete_crop, name='delete_crop'),
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
    path('adminfeedback/', views.admin_feedback_page, name='admin_feedback'),
    path('dashboard/feedback/', views.farmer_feedback, name='farmer_feedback'),
    path('government-schemes/', views.government_schemes, name='government_schemes'),
    path('chat/', views.chat_with_bot, name='chat_with_bot'),
    path('chat-interface/', views.chatbot_page, name='chatbot_page'),
   
    
    path('manage-delivery-requests/', views.manage_delivery_boy_requests, name='manage_delivery_boy_requests'),
    path('complete-delivery-details/<int:user_id>/', views.complete_delivery_boy_details, name='complete_delivery_boy_details'),
    path('delivery-boy-dashboard/', views.delivery_boy_dashboard, name='delivery_boy_dashboard'),
    path('assign-delivery-boy/', views.assign_delivery_boy, name='assign_delivery_boy'),
    path('delivery-boy/<int:delivery_boy_id>/orders/', views.delivery_boy_orders, name='delivery_boy_orders'),
    path('update-order-status/', views.update_order_status, name='update_order_status'),
    path('check-new-orders/', views.check_new_orders, name='check_new_orders'),


    path('unassign-delivery-boy/<int:order_id>/', views.unassign_delivery_boy, name='unassign_delivery_boy'),

    path('predict-price/', views.get_predicted_price, name='predict-price'),
    path('predict-price-form/', views.show_predict_form, name='predict-price-form'),
   
    path('get-subcategories/', views.get_subcategories, name='get_subcategories'),

    path('generate_qr/<int:order_id>/', views.generate_qr_code, name='generate_qr_code'),
    path('verify_qr/<int:order_id>/', views.verify_qr, name='verify_qr'),
    path("confirm-delivery/<int:order_id>/", views.confirm_delivery, name="confirm_delivery"),

    path('track_delivery/<int:order_id>/', views.track_delivery, name='track_delivery'),
    path('send_location/', views.send_location, name='send_location'),

    path('predict_spoilage/', views.predict_spoilage, name='predict_spoilage'),

    path('qr-scan/<int:order_id>/', views.qr_scan_details, name='qr_scan_details'),
    path('confirm-delivery-scan/<int:order_id>/', views.process_delivery_confirmation, name='process_delivery_confirmation'),

    path("demand-prediction/", views.predict_crop_demand, name="demand_prediction"),
    path('demand-prediction/', views.predict_crop_demand, name='predict_crop_demand'),
    path('plot-crop-demand/', views.plot_crop_demand, name='plot_crop_demand'),

    path('farmer-sales-data/', views.farmer_sales_data, name='farmer_sales_data'),



]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# path('password_reset/', views.password_reset_form, name='password_reset_form'),
#  path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
#   path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
#   path('reset/done/', views.password_reset_complete, name='password_reset_complete'),

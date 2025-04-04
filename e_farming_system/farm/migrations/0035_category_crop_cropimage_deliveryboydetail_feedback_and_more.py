# Generated by Django 5.0 on 2025-02-05 09:40

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0034_remove_crop_category_remove_subcategory_category_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Crop',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('stock', models.IntegerField(default=0)),
                ('status', models.BooleanField(default=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.category')),
                ('farmer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='CropImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(upload_to='crop_images/')),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='images', to='farm.crop')),
            ],
        ),
        migrations.CreateModel(
            name='DeliveryBoyDetail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('contact', models.CharField(max_length=15)),
                ('place', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('vehicle_type', models.CharField(blank=True, choices=[('bike', 'Bike'), ('car', 'Car'), ('van', 'Van'), ('truck', 'Truck'), ('other', 'Other')], max_length=20, null=True)),
                ('vehicle_number', models.CharField(blank=True, max_length=20, null=True)),
                ('license_number', models.CharField(blank=True, max_length=50, null=True)),
                ('area_of_service', models.TextField(blank=True, null=True)),
                ('additional_documents', models.FileField(blank=True, null=True, upload_to='delivery_docs/')),
                ('completed_registration', models.BooleanField(default=False)),
                ('verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='delivery_details', to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feedback_text', models.TextField()),
                ('rating', models.IntegerField(choices=[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)], default=5)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_read', models.BooleanField(default=False)),
                ('crop', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
                ('farmer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('contact', models.CharField(max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('place', models.CharField(max_length=255)),
                ('pincode', models.CharField(max_length=6)),
                ('delivery_address', models.TextField()),
                ('total_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('payment_method', models.CharField(choices=[('cod', 'Cash on Delivery'), ('online', 'Online Payment')], max_length=10)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Accepted', 'Accepted'), ('Out for Delivery', 'Out for Delivery'), ('Delivered', 'Delivered')], default='Pending', max_length=20)),
                ('order_date', models.DateTimeField(auto_now_add=True)),
                ('is_accepted', models.BooleanField(default=False)),
                ('assigned_delivery_boy', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_orders', to='farm.deliveryboydetail')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='OrderItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField()),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='order_items', to='farm.order')),
            ],
        ),
        migrations.CreateModel(
            name='SubCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subcategories', to='farm.category')),
            ],
            options={
                'unique_together': {('category', 'name')},
            },
        ),
        migrations.AddField(
            model_name='crop',
            name='subcategory',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='farm.subcategory'),
        ),
        migrations.CreateModel(
            name='Wishlist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('added_date', models.DateTimeField(auto_now_add=True)),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
        migrations.CreateModel(
            name='Cart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField()),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
            ],
            options={
                'unique_together': {('user', 'crop')},
            },
        ),
        migrations.AlterUniqueTogether(
            name='crop',
            unique_together={('name', 'farmer')},
        ),
    ]

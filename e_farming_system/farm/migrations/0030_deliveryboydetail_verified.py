# Generated by Django 5.0 on 2025-01-22 05:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0029_order_assigned_delivery_boy'),
    ]

    operations = [
        migrations.AddField(
            model_name='deliveryboydetail',
            name='verified',
            field=models.BooleanField(default=False),
        ),
    ]

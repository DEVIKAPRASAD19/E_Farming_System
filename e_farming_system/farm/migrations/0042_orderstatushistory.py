# Generated by Django 5.0 on 2025-02-13 10:24

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0041_deliveryboydetail_latitude_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='OrderStatusHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Accepted', 'Accepted'), ('Out for Delivery', 'Out for Delivery'), ('Delivered', 'Delivered')], max_length=20)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('location', models.CharField(blank=True, max_length=255, null=True)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='status_history', to='farm.order')),
            ],
        ),
    ]

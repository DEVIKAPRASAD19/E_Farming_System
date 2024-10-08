# Generated by Django 5.0 on 2024-10-08 04:41

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0027_delete_wishlist'),
    ]

    operations = [
        migrations.CreateModel(
            name='Wishlist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('added_date', models.DateTimeField(auto_now_add=True)),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
    ]

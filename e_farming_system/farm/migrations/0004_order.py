# Generated by Django 5.0 on 2024-10-16 10:47

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0003_delete_order'),
    ]

    operations = [
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('items', models.ManyToManyField(to='farm.cart')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.registeruser')),
            ],
        ),
    ]

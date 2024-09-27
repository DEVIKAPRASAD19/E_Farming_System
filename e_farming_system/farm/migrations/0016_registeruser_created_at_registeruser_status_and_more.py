# Generated by Django 5.0 on 2024-09-26 15:11

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0015_adminm'),
    ]

    operations = [
        migrations.AddField(
            model_name='registeruser',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='registeruser',
            name='status',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='registeruser',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
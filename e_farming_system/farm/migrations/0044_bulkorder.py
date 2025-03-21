# Generated by Django 5.0 on 2025-03-11 03:56

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0043_cropviewhistory'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BulkOrder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField()),
                ('delivery_date', models.DateField()),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Accepted', 'Accepted'), ('Rejected', 'Rejected'), ('Delivered', 'Delivered')], default='Pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('buyer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('crop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='farm.crop')),
            ],
        ),
    ]

# Generated by Django 5.0 on 2024-10-20 15:59

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('farm', '0020_alter_crop_unique_together'),
    ]

    operations = [
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
    ]

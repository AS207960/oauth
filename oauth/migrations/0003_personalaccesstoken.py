# Generated by Django 3.1.2 on 2020-10-19 15:42

import as207960_utils.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oauth', '0002_oauthclient_realm'),
    ]

    operations = [
        migrations.CreateModel(
            name='PersonalAccessToken',
            fields=[
                ('id', as207960_utils.models.TypedUUIDField(data_type='oauth_pat', primary_key=True, serialize=False)),
                ('revoked', models.BooleanField(blank=True)),
                ('name', models.CharField(max_length=255)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
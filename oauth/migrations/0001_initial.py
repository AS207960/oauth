# Generated by Django 3.0.8 on 2020-07-24 12:20

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='OAuthClient',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('client_id', models.CharField(max_length=255)),
                ('resource_id', models.UUIDField(null=True)),
            ],
            options={
                'verbose_name': 'OAuth Client',
                'verbose_name_plural': 'OAuth Clients',
            },
        ),
    ]

# Generated by Django 3.2.5 on 2021-12-02 17:53

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_qa'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='fields',
            field=models.ForeignKey(db_column='fieldKnow', null=True, on_delete=django.db.models.deletion.CASCADE, to='users.qa'),
        ),
    ]

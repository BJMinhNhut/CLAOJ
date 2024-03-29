# Generated by Django 2.2.24 on 2022-04-04 10:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('judge', '0130_add_filetype_statement'),
    ]

    operations = [
        migrations.AddField(
            model_name='solution',
            name='pdf_url',
            field=models.CharField(blank=True, help_text='URL to PDF solution. The PDF file must be embeddable (Mobile web browsersmay not support embedding). Fallback included.', max_length=200, verbose_name='PDF solution URL'),
        ),
    ]

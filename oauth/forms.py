from django import forms
from django.core import validators
import crispy_forms.helper
import crispy_forms.layout
import crispy_forms.bootstrap


class ClientCreateForm(forms.Form):
    realm = forms.ChoiceField(choices=(
        ("test", "Test"),
        ("master", "Production"),
    ))
    client_name = forms.CharField(required=True)
    client_description = forms.CharField(required=True, widget=forms.Textarea(), validators=[
        validators.MinLengthValidator(100)
    ])
    client_website = forms.URLField()
    client_type = forms.ChoiceField(choices=(
        ("public", "Public (you can't protect the client secret)"),
        ("confidential", "Confidential (you store the client secret on your own server)"),
    ))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9'
        self.helper.layout = crispy_forms.layout.Layout(
            'realm',
            'client_name',
            'client_description',
            'client_website',
            'client_type'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class PATCreateForm(forms.Form):
    pat_name = forms.CharField(required=True, max_length=255, label="Token name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9'
        self.helper.layout = crispy_forms.layout.Layout(
            'pat_name',
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class ClientEditForm(forms.Form):
    client_name = forms.CharField(required=True)
    client_description = forms.CharField(required=True, widget=forms.Textarea(), validators=[
        validators.MinLengthValidator(100)
    ])
    client_website = forms.URLField()
    client_type = forms.ChoiceField(choices=(
        ("public", "Public (you can't protect the client secret)"),
        ("confidential", "Confidential (you store the client secret on your own server)"),
    ))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9'
        self.helper.layout = crispy_forms.layout.Layout(
            'client_name',
            'client_description',
            'client_website',
            'client_type'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Save'))


class ClientRedirectUriForm(forms.Form):
    redirect_uri = forms.URLField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9'
        self.helper.layout = crispy_forms.layout.Layout(
            'redirect_uri',
        )

        self.helper.add_input(crispy_forms.layout.Submit('add_redirect_uri', 'Add'))


class ClientWebOriginForm(forms.Form):
    web_origin = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9'
        self.helper.layout = crispy_forms.layout.Layout(
            'web_origin',
        )

        self.helper.add_input(crispy_forms.layout.Submit('add_web_origin', 'Add'))

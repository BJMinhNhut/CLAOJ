import json
import os
from operator import attrgetter, itemgetter

import pyotp
import webauthn
from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator, RegexValidator
from django.db.models import Q
from django.forms import BooleanField, CharField, ChoiceField, DateInput, Form, ModelForm, \
    MultipleChoiceField, TextInput, inlineformset_factory
from django.forms.widgets import DateTimeInput
from django.template.defaultfilters import filesizeformat
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _

from django_ace import AceWidget
from judge.models import BlogPost, Contest, ContestProblem, Language, Organization, Problem, Profile, Solution, \
    Submission, WebAuthnCredential
from judge.utils.subscription import newsletter_id
from judge.widgets import HeavyPreviewPageDownWidget, HeavySelect2MultipleWidget, HeavySelect2Widget, MartorWidget, \
    Select2MultipleWidget, Select2Widget


TOTP_CODE_LENGTH = 6

two_factor_validators_by_length = {
    TOTP_CODE_LENGTH: {
        'regex_validator': RegexValidator(
            f'^[0-9]{{{TOTP_CODE_LENGTH}}}$',
            _(f'Two-factor authentication tokens must be {TOTP_CODE_LENGTH} decimal digits.'),
        ),
        'verify': lambda code, profile: not profile.check_totp_code(code),
        'err': _('Invalid two-factor authentication token.'),
    },
    16: {
        'regex_validator': RegexValidator('^[A-Z0-9]{16}$', _('Scratch codes must be 16 base32 characters.')),
        'verify': lambda code, profile: code not in json.loads(profile.scratch_codes),
        'err': _('Invalid scratch code.'),
    },
}


def fix_unicode(string, unsafe=tuple('\u202a\u202b\u202d\u202e')):
    return string + (sum(k in unsafe for k in string) - string.count('\u202c')) * '\u202c'


class ProfileForm(ModelForm):
    if newsletter_id is not None:
        newsletter = forms.BooleanField(label=_('Subscribe to contest updates'), initial=False, required=False)
    test_site = forms.BooleanField(label=_('Enable experimental features'), initial=False, required=False)

    class Meta:
        model = Profile
        fields = ['about', 'organizations', 'timezone', 'language', 'ace_theme', 'user_script']
        widgets = {
            'user_script': AceWidget(theme='github'),
            'timezone': Select2Widget(attrs={'style': 'width:200px'}),
            'language': Select2Widget(attrs={'style': 'width:200px'}),
            'ace_theme': Select2Widget(attrs={'style': 'width:200px'}),
        }

        has_math_config = bool(settings.MATHOID_URL)
        if has_math_config:
            fields.append('math_engine')
            widgets['math_engine'] = Select2Widget(attrs={'style': 'width:200px'})

        if HeavyPreviewPageDownWidget is not None:
            widgets['about'] = HeavyPreviewPageDownWidget(
                preview=reverse_lazy('profile_preview'),
                attrs={'style': 'max-width:700px;min-width:700px;width:700px'},
            )

    def clean_about(self):
        if 'about' in self.changed_data and not self.instance.has_any_solves:
            raise ValidationError(_('You must solve at least one problem before you can update your profile.'))
        return self.cleaned_data['about']

    def clean(self):
        organizations = self.cleaned_data.get('organizations') or []
        max_orgs = settings.DMOJ_USER_MAX_ORGANIZATION_COUNT

        if sum(org.is_open for org in organizations) > max_orgs:
            raise ValidationError(
                _('You may not be part of more than {count} public organizations.').format(count=max_orgs))

        return self.cleaned_data

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super(ProfileForm, self).__init__(*args, **kwargs)
        if not user.has_perm('judge.edit_all_organization'):
            self.fields['organizations'].queryset = Organization.objects.filter(
                Q(is_open=True) | Q(id__in=user.profile.organizations.all()),
            )
        if not self.fields['organizations'].queryset:
            self.fields.pop('organizations')


class ProposeProblemSolutionForm(ModelForm):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(ProposeProblemSolutionForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Solution
        fields = ('is_public', 'publish_on', 'authors', 'pdf_url', 'content')
        widgets = {
            'authors': HeavySelect2MultipleWidget(data_view='profile_select2', attrs={'style': 'width: 100%'}),
            'content': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('solution_preview')}),
            'publish_on': DateInput(attrs={'type': 'date'}),
            'pdf_url': TextInput(attrs={'style': 'width: 100%'}),
        }


class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['first_name']


class ProblemEditForm(ModelForm):
    required_css_class = 'required'
    statement_file = forms.FileField(
        required=False,
        validators=[FileExtensionValidator(allowed_extensions=settings.PDF_SAFE_EXTS)],
        help_text=_('Maximum file size is %s.') % filesizeformat(settings.PDF_MAX_FILE_SIZE),
        widget=forms.FileInput(attrs={'accept': 'application/pdf'}),
        label=_('Statement file'),
    )

    def clean_statement_file(self):
        content = self.files.get('statement_file', None)
        if content is not None and content.size > settings.PDF_MAX_FILE_SIZE:
            raise forms.ValidationError(_("File size is too big! Maximum file size is %s") %
                                        filesizeformat(settings.PDF_MAX_FILE_SIZE))
            if self.user and not self.user.has_perm('judge.upload_file_statement'):
                raise forms.ValidationError(_("You don't have permission to upload file-type statement."),
                                            'pdf_upload_permission_denined')

        return content

    def clean_time_limit(self):
        has_high_perm = self.user and self.user.has_perm('high_problem_timelimit')
        if self.cleaned_data['time_limit'] > settings.CLAOJ_PROBLEM_TIMELIMIT_LIMIT and not has_high_perm:
            raise forms.ValidationError(_('You cannot set time limit higher than %d seconds')
                                        % settings.CLAOJ_PROBLEM_TIMELIMIT_LIMIT,
                                        'problem_timelimit_too_long')
        return self.cleaned_data['time_limit']

    def __init__(self, *args, **kwargs):
        self.org_pk = org_pk = kwargs.pop('org_pk', None)
        self.user = kwargs.pop('user', None)
        super(ProblemEditForm, self).__init__(*args, **kwargs)

        if org_pk:
            self.fields['testers'].label = _('Private users')
            self.fields['testers'].help_text = _('If private, only these users may see the problem.')
            self.fields['testers'].widget.data_view = None
            self.fields['testers'].widget.data_url = reverse('organization_profile_select2',
                                                             args=(org_pk, ))

        self.fields['testers'].help_text = \
            str(self.fields['testers'].help_text) + ' ' + \
            str(_('You can paste a list of usernames into this box.'))

        if self.user and not self.user.has_perm('judge.upload_file_statement'):
            self.fields.pop('statement_file')

    def clean_code(self):
        code = self.cleaned_data['code']
        if self.org_pk is None:
            return code
        org = Organization.objects.get(pk=self.org_pk)
        prefix = ''.join(x for x in org.slug.lower() if x.isalpha()) + '_'
        if not code.startswith(prefix):
            raise forms.ValidationError(_('Problem id code must starts with `%s`') % (prefix, ),
                                        'problem_id_invalid_prefix')
        return code

    class Meta:
        model = Problem
        fields = ['code', 'name', 'authors', 'testers', 'is_public', 'time_limit', 'memory_limit', 'points',
                  'partial', 'testcase_visibility_mode', 'types', 'group', 'statement_file', 'description']
        widgets = {
            'name': TextInput(attrs={'style': 'width: 100%'}),
            'authors': HeavySelect2MultipleWidget(data_view='profile_select2', attrs={'style': 'width: 100%'}),
            'testcase_visibility_mode': Select2Widget(attrs={'style': 'min-width: 250px'}),
            'date': DateInput(attrs={'type': 'date'}),
            'types': Select2MultipleWidget(attrs={'style': 'width: 100%'}),
            'group': Select2Widget,
            'description': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('problem_preview'),
                                               'style': 'font-size: 14px'}),
            'testers': HeavySelect2MultipleWidget(
                data_view='profile_select2',
                attrs={'style': 'width: 100%'},
            ),
        }
        help_texts = {
            'is_public': _(
                'If public, all members in organization can view it. <strong>Set it as private '
                'if you want to use it in a contest, otherwise, users can see the problem '
                'even if they do not join the contest!</strong>'),
            'code': _('Problem code, e.g: voi19_post'),
            'name': _('The full name of the problem, '
                      'as shown in the problem list. For example: VOI19 - A cong B.'),
        }
        error_messages = {
            'code': {
                'invalid': _('Only accept alphanumeric characters (a-z, 0-9) and underscore (_)'),
            },
        }


class ProposeProblemSolutionFormSet(inlineformset_factory(Problem, Solution, form=ProposeProblemSolutionForm)):
    pass


class DownloadDataForm(Form):
    comment_download = BooleanField(required=False, label=_('Download comments?'))
    submission_download = BooleanField(required=False, label=_('Download submissions?'))
    submission_problem_glob = CharField(initial='*', label=_('Filter by problem code glob:'), max_length=100)
    submission_results = MultipleChoiceField(
        required=False,
        widget=Select2MultipleWidget(
            attrs={'style': 'width: 260px', 'data-placeholder': _('Leave empty to include all submissions')},
        ),
        choices=sorted(map(itemgetter(0, 0), Submission.RESULT)),
        label=_('Filter by result:'),
    )

    def clean(self):
        can_download = ('comment_download', 'submission_download')
        if not any(self.cleaned_data[v] for v in can_download):
            raise ValidationError(_('Please select at least one thing to download.'))
        return self.cleaned_data

    def clean_submission_problem_glob(self):
        if not self.cleaned_data['submission_download']:
            return '*'
        return self.cleaned_data['submission_problem_glob']

    def clean_submission_result(self):
        if not self.cleaned_data['submission_download']:
            return ()
        return self.cleaned_data['submission_result']


class ProblemSubmitForm(ModelForm):
    source = CharField(max_length=65536, required=False, widget=AceWidget(theme='tomorrow', no_ace_media=True))
    submission_file = forms.FileField(
        label=_('Source file'),
        required=False,
    )
    judge = ChoiceField(choices=(), widget=forms.HiddenInput(), required=False)

    def clean(self):
        cleaned_data = super(ProblemSubmitForm, self).clean()
        self.check_submission()
        return cleaned_data

    def check_submission(self):
        source = self.cleaned_data.get('source', '')
        content = self.files.get('submission_file', None)
        language = self.cleaned_data.get('language', None)
        lang_obj = Language.objects.get(name=language)

        if (source != '' and content is not None) or (source == '' and content is None) or \
                (source != '' and lang_obj.file_only) or (content == '' and not lang_obj.file_only):
            raise forms.ValidationError(_('Source code/file is missing or redundant. Please try again'))

        if content:
            max_file_size = lang_obj.file_size_limit * 1024 * 1024
            ext = os.path.splitext(content.name)[1][1:]

            if ext.lower() != lang_obj.extension.lower():
                raise forms.ValidationError(_('Wrong file type for language %(lang)s, expected %(lang_ext)s'
                                              ', found %(ext)s')
                                            % {'lang': language, 'lang_ext': lang_obj.extension, 'ext': ext})

            elif content.size > max_file_size:
                raise forms.ValidationError(_('File size is too big! Maximum file size is %s')
                                            % filesizeformat(max_file_size))

    def __init__(self, *args, judge_choices=(), **kwargs):
        super(ProblemSubmitForm, self).__init__(*args, **kwargs)
        self.fields['language'].empty_label = None
        self.fields['language'].label_from_instance = attrgetter('display_name')
        self.fields['language'].queryset = Language.objects.filter(judges__online=True).distinct()

        if judge_choices:
            self.fields['judge'].widget = Select2Widget(
                attrs={'style': 'width: 150px', 'data-placeholder': _('Any judge')},
            )
            self.fields['judge'].choices = judge_choices

    class Meta:
        model = Submission
        fields = ['language']


class OrganizationForm(ModelForm):
    class Meta:
        model = Organization
        fields = ['name', 'slug', 'is_open', 'about', 'logo_override_image']
        widgets = {'admins': Select2MultipleWidget(attrs={'style': 'width: 100%'})}
        if HeavyPreviewPageDownWidget is not None:
            widgets = {'about': HeavyPreviewPageDownWidget(preview=reverse_lazy('organization_preview'))}


class CustomAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(CustomAuthenticationForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'placeholder': _('Username')})
        self.fields['password'].widget.attrs.update({'placeholder': _('Password')})

        self.has_google_auth = self._has_social_auth('GOOGLE_OAUTH2')
        self.has_facebook_auth = self._has_social_auth('FACEBOOK')
        self.has_github_auth = self._has_social_auth('GITHUB_SECURE')

    def _has_social_auth(self, key):
        return (getattr(settings, 'SOCIAL_AUTH_%s_KEY' % key, None) and
                getattr(settings, 'SOCIAL_AUTH_%s_SECRET' % key, None))


class NoAutoCompleteCharField(forms.CharField):
    def widget_attrs(self, widget):
        attrs = super(NoAutoCompleteCharField, self).widget_attrs(widget)
        attrs['autocomplete'] = 'off'
        return attrs


class TOTPForm(Form):
    TOLERANCE = settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES

    totp_or_scratch_code = NoAutoCompleteCharField(required=False)

    def __init__(self, *args, **kwargs):
        self.profile = kwargs.pop('profile')
        super().__init__(*args, **kwargs)

    def clean(self):
        totp_or_scratch_code = self.cleaned_data.get('totp_or_scratch_code')
        try:
            validator = two_factor_validators_by_length[len(totp_or_scratch_code)]
        except KeyError:
            raise ValidationError(_('Invalid code length.'))
        validator['regex_validator'](totp_or_scratch_code)
        if validator['verify'](totp_or_scratch_code, self.profile):
            raise ValidationError(validator['err'])


class TOTPEnableForm(TOTPForm):
    def __init__(self, *args, **kwargs):
        self.totp_key = kwargs.pop('totp_key')
        super().__init__(*args, **kwargs)

    def clean(self):
        totp_validate = two_factor_validators_by_length[TOTP_CODE_LENGTH]
        code = self.cleaned_data.get('totp_or_scratch_code')
        totp_validate['regex_validator'](code)
        if not pyotp.TOTP(self.totp_key).verify(code, valid_window=settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES):
            raise ValidationError(totp_validate['err'])


class TwoFactorLoginForm(TOTPForm):
    webauthn_response = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        self.webauthn_challenge = kwargs.pop('webauthn_challenge')
        self.webauthn_origin = kwargs.pop('webauthn_origin')
        super().__init__(*args, **kwargs)

    def clean(self):
        totp_or_scratch_code = self.cleaned_data.get('totp_or_scratch_code')
        if self.profile.is_webauthn_enabled and self.cleaned_data.get('webauthn_response'):
            if len(self.cleaned_data['webauthn_response']) > 65536:
                raise ValidationError(_('Invalid WebAuthn response.'))

            if not self.webauthn_challenge:
                raise ValidationError(_('No WebAuthn challenge issued.'))

            response = json.loads(self.cleaned_data['webauthn_response'])
            try:
                credential = self.profile.webauthn_credentials.get(cred_id=response.get('id', ''))
            except WebAuthnCredential.DoesNotExist:
                raise ValidationError(_('Invalid WebAuthn credential ID.'))

            user = credential.webauthn_user
            # Work around a useless check in the webauthn package.
            user.credential_id = credential.cred_id
            assertion = webauthn.WebAuthnAssertionResponse(
                webauthn_user=user,
                assertion_response=response.get('response'),
                challenge=self.webauthn_challenge,
                origin=self.webauthn_origin,
                uv_required=False,
            )

            try:
                sign_count = assertion.verify()
            except Exception as e:
                raise ValidationError(str(e))

            credential.counter = sign_count
            credential.save(update_fields=['counter'])
        elif totp_or_scratch_code:
            if self.profile.is_totp_enabled and self.profile.check_totp_code(totp_or_scratch_code):
                return
            elif self.profile.scratch_codes and totp_or_scratch_code in json.loads(self.profile.scratch_codes):
                scratch_codes = json.loads(self.profile.scratch_codes)
                scratch_codes.remove(totp_or_scratch_code)
                self.profile.scratch_codes = json.dumps(scratch_codes)
                self.profile.save(update_fields=['scratch_codes'])
                return
            elif self.profile.is_totp_enabled:
                raise ValidationError(_('Invalid two-factor authentication token or scratch code.'))
            else:
                raise ValidationError(_('Invalid scratch code.'))
        else:
            raise ValidationError(_('Must specify either totp_token or webauthn_response.'))


class ProblemCloneForm(Form):
    code = CharField(max_length=32, validators=[RegexValidator('^[a-z0-9_]+$', _('Problem code must be ^[a-z0-9_]+$'))])

    def clean_code(self):
        code = self.cleaned_data['code']
        if Problem.objects.filter(code=code).exists():
            raise ValidationError(_('Problem with code already exists.'))
        return code


class ContestCloneForm(Form):
    key = CharField(max_length=32, validators=[RegexValidator('^[a-z0-9_]+$', _('Contest id must be ^[a-z0-9_]+$'))])

    def clean_key(self):
        key = self.cleaned_data['key']
        if Contest.objects.filter(key=key).exists():
            raise ValidationError(_('Contest with key already exists.'))
        return key


class ProposeContestProblemForm(ModelForm):
    class Meta:
        model = ContestProblem
        verbose_name = _('Problem')
        verbose_name_plural = 'Problems'
        fields = (
            'problem', 'points', 'order', 'max_submissions',
        )

        widgets = {
            'problem': HeavySelect2Widget(data_view='problem_select2', attrs={'style': 'width: 100%'}),
        }


class ProposeContestProblemFormSet(
        inlineformset_factory(
            Contest,
            ContestProblem,
            form=ProposeContestProblemForm,
            can_delete=True,
        )):

    def clean(self) -> None:
        """Checks that no Contest problems have the same order."""
        super(ProposeContestProblemFormSet, self).clean()
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
        orders = []
        for form in self.forms:
            if self.can_delete and self._should_delete_form(form):
                continue
            order = form.cleaned_data.get('order')
            if order and order in orders:
                raise ValidationError(_("Problems must have distinct order."))
            orders.append(order)


class BlogPostForm(ModelForm):
    def __init__(self, *args, **kwargs):
        kwargs.pop('org_pk', None)
        super(BlogPostForm, self).__init__(*args, **kwargs)

    class Meta:
        model = BlogPost
        fields = ['title', 'publish_on', 'visible', 'content']
        widgets = {
            'content': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('blog_preview')}),
            'summary': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('blog_preview')}),
            'publish_on': DateTimeInput(format='%Y-%m-%d %H:%M:%S', attrs={'class': 'datetimefield'}),
        }


class ContestForm(ModelForm):
    required_css_class = 'required'

    def __init__(self, *args, **kwargs):
        self.org_pk = org_pk = kwargs.pop('org_pk', None)
        self.user = kwargs.pop('user', None)
        super(ContestForm, self).__init__(*args, **kwargs)

        # cannot use fields[].widget = ...
        # because it will remove the old values
        # just update the data url is fine
        if org_pk:
            self.fields['private_contestants'].widget.data_view = None
            self.fields['private_contestants'].widget.data_url = reverse('organization_profile_select2',
                                                                         args=(org_pk, ))

        self.fields['private_contestants'].help_text = \
            str(self.fields['private_contestants'].help_text) + ' ' + \
            str(_('You can paste a list of usernames into this box.'))

    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')

        has_long_perm = self.user and self.user.has_perm('long_contest_duration')
        if (end_time - start_time).days > settings.CLAOJ_CONTEST_DURATION_LIMIT and not has_long_perm:
            raise forms.ValidationError(_('Contest duration cannot be longer than %d days')
                                        % settings.CLAOJ_CONTEST_DURATION_LIMIT,
                                        'contest_duration_too_long')
        return cleaned_data

    def clean_key(self):
        key = self.cleaned_data['key']
        if self.org_pk is None:
            return key
        org = Organization.objects.get(pk=self.org_pk)
        prefix = ''.join(x for x in org.slug.lower() if x.isalpha()) + '_'
        if not key.startswith(prefix):
            raise forms.ValidationError(_('Contest id must starts with `%s`') % (prefix, ),
                                        'contest_id_invalid_prefix')
        return key

    class Meta:
        model = Contest
        fields = [
            'key', 'name',
            'start_time', 'end_time', 'is_visible',
            'use_clarifications',
            'hide_problem_tags',
            'hide_problem_authors',
            'scoreboard_visibility',
            'description',
            'is_private',
            'private_contestants',
        ]

        widgets = {
            'start_time': DateTimeInput(format='%Y-%m-%d %H:%M:%S', attrs={'class': 'datetimefield'}),
            'end_time': DateTimeInput(format='%Y-%m-%d %H:%M:%S', attrs={'class': 'datetimefield'}),
            'description': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('contest_preview')}),
            'scoreboard_visibility': Select2Widget(),
            'private_contestants': HeavySelect2MultipleWidget(
                data_view='profile_select2',
                attrs={'style': 'width: 100%'},
            ),
        }
        help_texts = {
            'end_time': _('Users are able to pratice contest problems even if the contest has ended, '
                          "so don't set the contest time too high if you don't really need it."),
        }
        error_messages = {
            'key': {
                'invalid': _('Only accept alphanumeric characters (a-z, 0-9) and underscore (_)'),
            },
        }

from django.db import models
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import get_user_model
import uuid
import django_keycloak_auth.clients
import as207960_utils.models


def sync_resource_to_keycloak(self, display_name, resource_type, scopes, urn, view_name, super_save, args, kwargs):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    created = False

    if not self.pk:
        created = True
    super_save(*args, **kwargs)

    create_kwargs = {
        "name": f"{resource_type}_{self.id}",
        "displayName": f"{display_name}: {str(self)}",
        "ownerManagedAccess": True,
        "scopes": scopes,
        "type": urn,
        "uri": reverse(view_name, args=(self.id,)) if view_name else None,
    }

    if created or not self.resource_id:
        if self.user:
            create_kwargs['owner'] = self.user.username

        d = uma_client.resource_set_create(
            token,
            **create_kwargs
        )
        self.resource_id = d['_id']
        super_save(*args, **kwargs)
    else:
        uma_client.resource_set_update(
            token,
            id=self.resource_id,
            **create_kwargs
        )


def delete_resource(resource_id):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    uma_client.resource_set_delete(token, resource_id)


def get_object_ids(access_token, resource_type, action):
    scope_name = f"{action}-{resource_type}"
    permissions = django_keycloak_auth.clients.get_authz_client().get_permissions(access_token)
    permissions = permissions.get("permissions", [])
    permissions = filter(
        lambda p: scope_name in p.get('scopes', []) and p.get('rsname', "").startswith(f"{resource_type}_"),
        permissions
    )
    object_ids = list(map(lambda p: p['rsname'][len(f"{resource_type}_"):], permissions))
    return object_ids


def eval_permission(token, resource, scope, submit_request=False):
    resource = str(resource)
    permissions = django_keycloak_auth.clients.get_authz_client().get_permissions(
        token=token,
        resource_scopes_tuples=[(resource, scope)],
        submit_request=submit_request
    )

    for permission in permissions.get('permissions', []):
        for scope in permission.get('scopes', []):
            if permission.get('rsid') == resource and scope == scope:
                return True

    return False


def get_resource_owner(resource_id):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    resource = uma_client.resource_set_read(token, resource_id)
    owner = resource.get("owner", {}).get("id")
    user = get_user_model().objects.filter(username=owner).first()
    return user


class OAuthClient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm = models.CharField(max_length=255)
    client_id = models.CharField(max_length=255)
    resource_id = models.UUIDField(null=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    class Meta:
        verbose_name = "OAuth Client"
        verbose_name_plural = "OAuth Clients"

    def __str__(self):
        return self.client_id

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(pk__in=get_object_ids(access_token, 'oauth-client', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-oauth-client"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"oauth-client", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-oauth-client"
        return eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        sync_resource_to_keycloak(
            self,
            display_name="OAuth Client", resource_type="oauth-client", scopes=[
                'view-oauth-client',
                'edit-oauth-client',
                'delete-oauth-client',
            ],
            urn="urn:as207960:domains:oauth_client", super_save=super().save, view_name='view_client',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        delete_resource(self.resource_id)


class PersonalAccessToken(models.Model):
    id = as207960_utils.models.TypedUUIDField("oauth_pat", primary_key=True)
    revoked = models.BooleanField(blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

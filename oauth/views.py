from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
import django_keycloak_auth.clients
from . import forms, models
import uuid
import json
import concurrent.futures


@login_required
def index(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    kc_client = django_keycloak_auth.clients.get_keycloak_client()
    admin_client = kc_client.admin
    admin_client.set_token(django_keycloak_auth.clients.get_access_token)

    clients = models.OAuthClient.get_object_list(access_token)

    with concurrent.futures.ThreadPoolExecutor() as e:
        client_data = e.map(lambda c: {
            "obj": c,
            "client": admin_client.get(
                admin_client.get_full_url(f"auth/admin/realms/{c.realm}/clients/{c.client_id}"),
            )
        }, clients)

    return render(request, "oauth/index.html", {
        "clients": client_data
    })


@login_required
def create_client(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    if not models.OAuthClient.has_class_scope(access_token, 'create'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.ClientCreateForm(request.POST)
        if form.is_valid():
            realm = form.cleaned_data['realm']

            kc_client = django_keycloak_auth.clients.get_keycloak_client()
            admin_client = kc_client.admin
            admin_client.set_token(django_keycloak_auth.clients.get_access_token)
            r = admin_client._realm.client.session.post(
                admin_client.get_full_url(f"auth/admin/realms/{realm}/clients"),
                json.dumps({
                    "name": form.cleaned_data["client_name"],
                    "description": form.cleaned_data["client_description"],
                    "baseUrl": form.cleaned_data["client_website"],
                    "protocol":	"openid-connect",
                    "enabled": True,
                    "consentRequired": True,
                    "clientId": str(uuid.uuid4()),
                    "attributes": {},
                    "redirectUris": [],
                    "clientAuthenticatorType": "client-secret",
                    "bearerOnly": False,
                    "standardFlowEnabled": True,
                    "implicitFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "serviceAccountsEnabled": True,
                    "publicClient": form.cleaned_data["client_type"] == "public",
                    "fullScopeAllowed": False,
                    "defaultClientScopes": [],
                    "optionalClientScopes": [
                        "offline_access"
                    ],
                    "authorizationServicesEnabled": False
                }),
                headers=admin_client._add_auth_header(headers=None)
            )
            r.raise_for_status()
            client_id = r.headers["Location"].split("/")[-1]

            client_obj = models.OAuthClient(
                client_id=client_id,
                realm=realm,
                user=request.user
            )
            client_obj.save()
            return redirect('view_client', client_obj.id)
    else:
        form = forms.ClientCreateForm()

    return render(request, "oauth/create_client.html", {
        "client_form": form
    })


@login_required
def view_client(request, client_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    client_obj = get_object_or_404(models.OAuthClient, id=client_id)

    if not client_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    kc_client = django_keycloak_auth.clients.get_keycloak_client()
    admin_client = kc_client.admin
    admin_client.set_token(django_keycloak_auth.clients.get_access_token)

    r = admin_client.get(
        admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
    )

    if "regen_client_secret" in request.POST:
        admin_client.post(
            admin_client.get_full_url(
                f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}/client-secret"
            ), None
        )

    if "delete_redirect_uri" in request.POST:
        r["redirectUris"].remove(request.POST["delete_redirect_uri"])
        admin_client.put(
            admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
            json.dumps({
                "redirectUris": r["redirectUris"]
            }),
        )

    if "delete_web_origin" in request.POST:
        r["webOrigins"].remove(request.POST["delete_web_origin"])
        admin_client.put(
            admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
            json.dumps({
                "webOrigins": r["webOrigins"]
            }),
        )

    if "add_redirect_uri" in request.POST:
        redirect_uri_form = forms.ClientRedirectUriForm(request.POST)
        if redirect_uri_form.is_valid():
            r["redirectUris"].append(redirect_uri_form.cleaned_data["redirect_uri"])
            admin_client.put(
                admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
                json.dumps({
                    "redirectUris": r["redirectUris"]
                }),
            )
    else:
        redirect_uri_form = forms.ClientRedirectUriForm()

    if "add_redirect_uri" in request.POST:
        web_origin_form = forms.ClientWebOriginForm(request.POST)
        if web_origin_form.is_valid():
            r["webOrigins"].append(web_origin_form.cleaned_data["web_origin"])
            admin_client.put(
                admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
                json.dumps({
                    "webOrigins": r["webOrigins"]
                }),
            )
    else:
        web_origin_form = forms.ClientWebOriginForm()

    svc_account = None
    client_secret = None

    if r["serviceAccountsEnabled"]:
        svc_account = admin_client.get(
            admin_client.get_full_url(
                f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}/service-account-user"
            ),
        )

    if not r["publicClient"]:
        client_secret = admin_client.get(
            admin_client.get_full_url(
                f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}/client-secret"
            ),
        )

    return render(request, "oauth/view_client.html", {
        "client_id": client_obj.id,
        "client": r,
        "svc_account": svc_account,
        "client_secret": client_secret,
        "redirect_uri_form": redirect_uri_form,
        "web_origin_form": web_origin_form
    })


@login_required
def edit_client(request, client_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    client_obj = get_object_or_404(models.OAuthClient, id=client_id)

    if not client_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    kc_client = django_keycloak_auth.clients.get_keycloak_client()
    admin_client = kc_client.admin
    admin_client.set_token(django_keycloak_auth.clients.get_access_token)
    r = admin_client.get(
        admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
    )

    initial_data = {
        "client_name": r["name"],
        "client_description": r["description"],
        "client_website": r["baseUrl"],
        "client_type": "public" if r["publicClient"] else "confidential"
    }

    if request.method == "POST":
        form = forms.ClientEditForm(request.POST, initial=initial_data)
        if form.is_valid():
            admin_client.put(
                admin_client.get_full_url(f"auth/admin/realms/{client_obj.realm}/clients/{client_obj.client_id}"),
                json.dumps({
                    "name": form.cleaned_data["client_name"],
                    "description": form.cleaned_data["client_description"],
                    "baseUrl": form.cleaned_data["client_website"],
                    "publicClient": form.cleaned_data["client_type"] == "public",
                }),
            )
            return redirect('view_client', client_obj.id)
    else:
        form = forms.ClientEditForm(initial=initial_data)

    return render(request, "oauth/edit_client.html", {
        "client_id": client_obj.id,
        "client": r,
        "client_form": form
    })

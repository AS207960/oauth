from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse, HttpResponseForbidden
import django_keycloak_auth.clients
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from . import forms, models
import keycloak.exceptions
import uuid
import json
import concurrent.futures
import jose.jwt
import jose.backends
import jose.constants


REALMS = {
    "test": "Test",
    "master": "Production"
}

PAT_JWK = jose.backends.ECKey(settings.PAT_PRIV, algorithm=jose.constants.ALGORITHMS.ES256)


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
            "realm": REALMS.get(c.realm),
            "client": admin_client.get(
                admin_client.get_full_url(f"auth/admin/realms/{c.realm}/clients/{c.client_id}"),
            )
        }, clients)

    return render(request, "oauth/index.html", {
        "clients": client_data
    })


@login_required
def personal_tokens(request):
    pats = models.PersonalAccessToken.objects.filter(user=request.user)

    active_pats = pats.filter(revoked=False)
    revoked_pats = pats.filter(revoked=True)

    new_token = None
    if "new_token" in request.session:
        new_token = request.session.pop("new_token")

    return render(request, "oauth/personal_tokens.html", {
        "active_pats": active_pats,
        "revoked_pats": revoked_pats,
        "new_token": new_token
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


@login_required
def create_pat(request):
    if request.method == "POST":
        pat_form = forms.PATCreateForm(request.POST)
        if pat_form.is_valid():
            new_pat = models.PersonalAccessToken(
                user=request.user,
                name=pat_form.cleaned_data['pat_name'],
                revoked=False
            )
            new_pat.save()

            pat_token = jose.jwt.encode({
                "sub": request.user.username,
                "jti": new_pat.id,
                "iat": timezone.now(),
                "nbf": timezone.now(),
            }, key=PAT_JWK.to_dict(), algorithm="ES256", headers={
                "iss": "as207960.net"
            })
            request.session["new_token"] = pat_token

            return redirect('personal_tokens')
    else:
        pat_form = forms.PATCreateForm()

    return render(request, "oauth/create_pat.html", {
        "pat_form": pat_form
    })


@login_required
def revoke_pat(request, pat_id):
    pat = get_object_or_404(models.PersonalAccessToken, id=pat_id)

    if pat.user != request.user:
        raise PermissionDenied()

    if request.method == "POST" and request.POST.get("revoke") == "true":
        pat.revoked = True
        pat.save()
        return redirect('personal_tokens')

    return render(request, "oauth/revoke_pat.html", {
        "token": pat
    })


def pat_jwks(request):
    return HttpResponse(json.dumps({
        "keys": [PAT_JWK.public_key().to_dict()]
    }), content_type="application/json")


@csrf_exempt
@require_POST
def verify_pat(request):
    auth = request.META.get("HTTP_AUTHORIZATION")
    if not auth or not auth.startswith("Bearer "):
        return HttpResponseForbidden()

    try:
        claims = django_keycloak_auth.clients.verify_token(
            auth[len("Bearer "):].strip()
        )
    except keycloak.exceptions.KeycloakClientError:
        return HttpResponseForbidden()

    if "verify-pat" not in claims.get("resource_access", {}).get(
            settings.OIDC_CLIENT_ID, {}
    ).get("roles", []):
        return HttpResponseForbidden()

    pat = request.POST.get("token")

    if not pat:
        return HttpResponseForbidden()

    inactive_resp = HttpResponse(json.dumps({
            "active": False
    }), content_type="application/json")

    try:
        pat_data = jose.jwt.decode(pat, PAT_JWK.public_key().to_dict(), algorithms="ES256")
    except jose.jwt.JWSError:
        return inactive_resp

    if "jti" not in pat_data:
        return inactive_resp

    pat = models.PersonalAccessToken.objects.filter(id=pat_data["jti"]).first()
    if not pat:
        return inactive_resp

    if pat.revoked:
        return inactive_resp

    return HttpResponse(json.dumps({
        "active": True,
        "jti": pat.id,
        "sub": pat.user.username
    }), content_type="application/json")

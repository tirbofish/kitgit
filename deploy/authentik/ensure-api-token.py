#!/bin/sh
# Ensure kitgit API token exists in Authentik (idempotent).
# Usage: docker compose exec -T authentik-server ak shell < ensure-api-token.py
# Or: python manage.py shell < this file via ak shell
from authentik.core.models import Token, TokenIntents, User

KEY = "changeme-kitgit-authentik-api-token"
IDENT = "kitgit-api"

user = User.objects.filter(username="akadmin").first()
if user is None:
    raise SystemExit("akadmin user not found yet")

tok = Token.objects.filter(identifier=IDENT).first()
if tok is None:
    tok = Token(identifier=IDENT, user=user, intent=TokenIntents.INTENT_API, expiring=False)
    tok.key = KEY
    tok.save()
    print(f"created token {IDENT}")
else:
    tok.key = KEY
    tok.expiring = False
    tok.user = user
    tok.intent = TokenIntents.INTENT_API
    tok.save()
    print(f"updated token {IDENT}")

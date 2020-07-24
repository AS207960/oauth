#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "as207960/oauth-management:$VERSION" . || exit
docker push "as207960/oauth-management:$VERSION" || exit

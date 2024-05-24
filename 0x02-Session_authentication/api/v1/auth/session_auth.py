#!/usr/bin/env python3


from uuid import uuid4

from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    user_id_by_session_id = {}

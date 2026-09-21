"""Permission checks are injected; this core creates no identities or sessions."""


class AccessDenied(PermissionError):
    def __init__(self):
        super().__init__("Not Found")


class DenyAccess:
    def require_owner(self, context):
        raise AccessDenied()

    def require_recordings(self, context):
        raise AccessDenied()

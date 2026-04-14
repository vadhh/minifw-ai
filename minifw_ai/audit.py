# Dummy functions for audit to allow web panel to run
def audit_policy_change(*args, **kwargs):
    pass

def audit_user_mgmt(*args, **kwargs):
    pass

def audit_login_success(*args, **kwargs):
    pass

def audit_login_failed(*args, **kwargs):
    pass

def audit_2fa_success(*args, **kwargs):
    pass

def audit_2fa_failed(*args, **kwargs):
    pass

def audit_logout(*args, **kwargs):
    pass

def audit_password_change(*args, **kwargs):
    pass

def audit_daemon_start(*args, **kwargs):
    pass

def audit_daemon_stop(*args, **kwargs):
    pass

def audit_config_loaded(*args, **kwargs):
    pass

def audit_firewall_init(*args, **kwargs):
    pass

def audit_firewall_init_failed(*args, **kwargs):
    pass

def audit_state_transition(*args, **kwargs):
    pass

def audit_ip_block(*args, **kwargs):
    pass

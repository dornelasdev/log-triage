from logtriage.parsers.cron import parse_message_cron
from logtriage.parsers.ssh import parse_message_ssh
from logtriage.parsers.sudo import parse_message_sudo


CRON_SERVICES = {"CRON", "cron", "crond"}
SUPPORTED_SERVICE_KEYS = {"sshd", "sudo", "cron"}


def normalize_service(service):
    return "cron" if service in CRON_SERVICES else service


def parse_message_by_service(service, message, selected_type):
    parsed_message, _ = route_message(service, message, selected_type)
    return parsed_message


def route_message(service, message, selected_type):
    service_key = normalize_service(service)
    if selected_type != "all" and service_key != selected_type:
        return None, "service_filtered_by_type"
    if service_key not in SUPPORTED_SERVICE_KEYS:
        return None, "unknown_service"

    if service == "sshd":
        parsed_message = parse_message_ssh(message)
    elif service == "sudo":
        parsed_message = parse_message_sudo(message)
    elif service in CRON_SERVICES:
        parsed_message = parse_message_cron(message)
    else:
        return None, "unknown_service"

    if parsed_message is None:
        return None, "message_no_match"

    return parsed_message, None

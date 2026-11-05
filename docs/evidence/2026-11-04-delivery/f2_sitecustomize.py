import faulthandler
import logging
import signal
import minifw_ai.collector_dnsmasq as dns

faulthandler.register(signal.SIGUSR1, all_threads=True)
parse = dns.parse_dnsmasq
def traced(line):
    result = parse(line)
    logging.warning("F2_DNS_READ result=%r line=%r", result, line)
    return result
dns.parse_dnsmasq = traced
import minifw_ai.main as main
original_stream = main.stream_collector_events
def stream(sources):
    for source, event in original_stream(sources):
        if source == "dns":
            logging.warning("F2_DNS_CONSUMED %r", event)
        yield source, event
main.stream_collector_events = stream
original_score = main.score_and_decide
def score(*args, **kwargs):
    result = original_score(*args, **kwargs)
    if args[0]:
        logging.warning("F2_SCORE input=%r flags=%r result=%r", args[:4], kwargs, result)
    return result
main.score_and_decide = score
original_add = main.ipset_add
def add(*args, **kwargs):
    result = original_add(*args, **kwargs)
    logging.warning("F2_NFT_ADD %r result=%r", args, result)
    return result
main.ipset_add = add

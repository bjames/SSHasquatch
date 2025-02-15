import logging

logging.basicConfig(
    filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(message)s"
)


def log_event(event):
    logging.info(event)
    print(event)

from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception, RetryCallState
import time
import logging

logger = logging.getLogger("iocscanner.retry")

def log_retry(retry_state: RetryCallState):
    last_exc = retry_state.outcome.exception()
    logger.warning(
        f"[{retry_state.fn.__name__}] retrying in {retry_state.next_action.sleep} sec due to {last_exc}"
    )

def is_throttling_error(exception):
    return (
        hasattr(exception, 'response') and
        getattr(exception.response, 'status_code', None) in (429, 503)
    )

retry_on_throttle = retry(
    wait=wait_exponential(multiplier=2, min=2, max=10),
    stop=stop_after_attempt(5),
    retry=retry_if_exception(is_throttling_error),
    before_sleep=log_retry,
    reraise=True
)

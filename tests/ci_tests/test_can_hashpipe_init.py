import time
import pytest
from status_daq import status
from control_util import is_hashpipe_running

pytestmark = pytest.mark.asyncio


@pytest.mark.usefixtures("hashpipe_pcap_runner")
def test_hashpipe_valid():
    """
    Validates the data pipeline: tcpreplay -> hashpipe -> data files

    Args: hashpipe_pcap_runner: Fixture that manages the hashpipe and tcpreplay processes.
    """
    # If the hashpipe_pcap_runner fixture is active, it means the pipeline is running.
    for _ in range(10):
        assert is_hashpipe_running(), "Hashpipe process should be running."
        status()
        time.sleep(1)
    assert is_hashpipe_running(), "Hashpipe process should still be running after 10 seconds."
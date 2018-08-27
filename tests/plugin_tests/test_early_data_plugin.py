import unittest

import pickle

from sslyze.plugins.early_data_plugin import EarlyDataPlugin, EarlyDataScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.openssl_server import ModernOpenSslServer


class EarlyDataPluginTestCase(unittest.TestCase):

    def test_early_data_enabled(self):
        with ModernOpenSslServer(max_early_data=256) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        self.assertTrue(plugin_result.is_early_data_supported)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

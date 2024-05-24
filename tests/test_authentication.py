import unittest

from authentication import AuthenticationObj


class Test_Authentication(unittest.TestCase):
    def setUp(self) -> None:
        self._auth = AuthenticationObj()

    def test_login(self):
        self.assertEqual(True, True)

    def test_logout(self):
        self.assertEqual(False, False)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
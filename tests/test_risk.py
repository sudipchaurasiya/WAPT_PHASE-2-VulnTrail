
import unittest
from vulntrail import calculate_risk


class RiskCalculationTests(unittest.TestCase):

    def test_critical_risk(self):
        self.assertEqual(calculate_risk(5, 5), (25, "Critical"))

    def test_high_risk(self):
        self.assertEqual(calculate_risk(5, 3), (15, "High"))

    def test_medium_risk(self):
        self.assertEqual(calculate_risk(4, 2), (8, "Medium"))

    def test_low_risk(self):
        self.assertEqual(calculate_risk(2, 2), (4, "Low"))


if __name__ == "__main__":
    unittest.main()

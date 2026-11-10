"""Check generated payload consistency without loading AstrBot configuration."""

import importlib.util
import json
import math
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "campus_generation", Path(__file__).resolve().parents[1] / "generation.py"
)
generation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generation)


class GenerationTests(unittest.TestCase):
    def test_geometry_statistics_and_time_remain_consistent(self):
        end = datetime(2026, 11, 10, 12, 0, 0, 999999)
        for _ in range(10):
            data, sensor = generation.generate_data("Name", "123", "activity", end)
            begin = datetime.strptime(data["beginTime"], "%Y-%m-%d %H:%M:%S")
            finish = datetime.strptime(data["endTime"], "%Y-%m-%d %H:%M:%S")
            hours, minutes, seconds = map(int, data["activeTime"].split(":"))
            duration = hours * 3600 + minutes * 60 + seconds
            self.assertEqual((finish - begin).total_seconds(), duration)
            self.assertEqual(finish, end.replace(microsecond=0))
            self.assertEqual(len(sensor), duration * 20)
            self.assertTrue(all(math.isfinite(sample) for sample in sensor))
            points = data["coordinate"]
            self.assertEqual(points[0]["t"], 0)
            self.assertEqual(data["sportId"], "activity")
            self.assertEqual(data["xh"], "123")
            self.assertEqual(data["name"], "Name")
            self.assertGreaterEqual(points[-1]["da"], 2150)
            self.assertAlmostEqual(
                sum(point["d"] for point in points), points[-1]["da"], places=3
            )
            begin_ms = int(
                begin.replace(tzinfo=generation.CHINA_TIME).timestamp() * 1000
            )
            end_ms = int(
                finish.replace(tzinfo=generation.CHINA_TIME).timestamp() * 1000
            )
            self.assertTrue(
                all(begin_ms <= point["t"] <= end_ms for point in points[1:])
            )
            for previous, point in zip(points[1:], points[2:]):
                self.assertGreater(point["t"], previous["t"])
                self.assertGreaterEqual(point["da"], previous["da"])
                geometric = generation.haversine_distance(
                    (previous["a"], previous["o"]), (point["a"], point["o"])
                )
                self.assertAlmostEqual(geometric, point["d"], places=5)
                speed = point["d"] / ((point["t"] - previous["t"]) / 1000) * 3.6
                self.assertAlmostEqual(point["s"], speed, delta=max(0.02, speed * 0.02))
            distance_km = points[-1]["da"] / 1000
            self.assertAlmostEqual(float(data["odometer"]), distance_km, delta=0.0051)
            self.assertAlmostEqual(
                float(data["avgSpeed"]), distance_km / (duration / 3600), delta=0.01
            )
            self.assertAlmostEqual(
                float(data["stepMinute"]),
                data["stepCount"] / (duration / 60),
                delta=0.051,
            )
            self.assertEqual([entry["km"] for entry in data["pace"]], ["1", "2"])
            previous_seconds = 0
            for entry in data["pace"]:
                parts = entry["t"].replace("''", "").split("'")
                pace_seconds = int(parts[0]) * 60 + int(parts[1])
                self.assertEqual(pace_seconds, entry["kmdlsj"] - previous_seconds)
                previous_seconds = entry["kmdlsj"]
            json.dumps(data, allow_nan=False)

    def test_aware_end_time_is_converted_to_campus_timezone(self):
        end = datetime(2026, 11, 10, 4, 0, tzinfo=timezone.utc)
        data, _ = generation.generate_data("Name", "123", "id", end)
        self.assertEqual(data["endTime"], "2026-11-10 12:00:00")

    def test_malformed_and_zero_length_routes_are_rejected(self):
        for route in [[], [[30, 114]], [[91, 114], [30, 114]], [[30, 114], [30, 114]]]:
            with (
                self.subTest(route=route),
                patch.object(Path, "read_text", return_value=json.dumps(route)),
            ):
                with self.assertRaises(ValueError):
                    generation.generate_data("Name", "123", "id", datetime.now())

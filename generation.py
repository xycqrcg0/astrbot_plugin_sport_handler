"""Generate campus payloads from the bundled HUST track route."""

import bisect
import json
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

CHINA_TIME = timezone(timedelta(hours=8))


def haversine_distance(
    first: tuple[float, float], second: tuple[float, float]
) -> float:
    """Calculate the spherical distance between two geographic coordinates.

    Args:
        first: Latitude and longitude in degrees.
        second: Latitude and longitude in degrees.

    Returns:
        Distance in meters.
    """
    lat_a, lat_b = math.radians(first[0]), math.radians(second[0])
    delta_lat = lat_b - lat_a
    delta_lon = math.radians(second[1] - first[1])
    value = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat_a) * math.cos(lat_b) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * 6_371_000 * math.asin(min(1.0, math.sqrt(value)))


def generate_data(
    name: str, student_id: str, sport_id: str, end_time: datetime
) -> tuple[dict, list[float]]:
    """Generate a 2.15 km activity ending at the supplied campus-local time.

    Args:
        name: Campus account display name.
        student_id: Campus student number.
        sport_id: Server-issued activity ID, or an empty placeholder before issuance.
        end_time: Activity end time. Naive datetimes are interpreted as UTC+8.

    Returns:
        Complete activity payload and 20 Hz acceleration samples.

    Raises:
        ValueError: The bundled route is malformed or has zero length.
        OSError: The bundled route cannot be read.
    """
    route = json.loads(
        (Path(__file__).parent / "routes" / "route_track.json").read_text(
            encoding="utf-8-sig"
        )
    )
    if not isinstance(route, list) or len(route) < 2:
        raise ValueError("Invalid bundled route")
    points = []
    for item in route:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("Invalid route coordinate")
        latitude, longitude = float(item[0]), float(item[1])
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError("Invalid geographic coordinate")
        points.append((latitude, longitude))
    if haversine_distance(points[0], points[-1]) < 20 and points[0] != points[-1]:
        points.append(points[0])
    # Preserve the upstream three-pass Chaikin smoothing before interpolation.
    for _ in range(3):
        smoothed = []
        closed = points[0] == points[-1]
        if not closed:
            smoothed.append(points[0])
        for first, second in zip(points, points[1:]):
            smoothed.extend(
                [
                    (
                        0.75 * first[0] + 0.25 * second[0],
                        0.75 * first[1] + 0.25 * second[1],
                    ),
                    (
                        0.25 * first[0] + 0.75 * second[0],
                        0.25 * first[1] + 0.75 * second[1],
                    ),
                ]
            )
        smoothed.append(smoothed[0] if closed else points[-1])
        points = smoothed
    cumulative = [0.0]
    for first, second in zip(points, points[1:]):
        cumulative.append(cumulative[-1] + haversine_distance(first, second))
    if cumulative[-1] <= 0:
        raise ValueError("Bundled route has zero length")

    rng = random.Random()
    base_speed = rng.uniform(4.15, 4.85)
    amplitude = rng.uniform(0.18, 0.35)
    period = rng.uniform(55, 95)
    phase = rng.uniform(0, 2 * math.pi)
    drift_period = rng.uniform(30, 70)
    drift_phase = rng.uniform(0, 2 * math.pi)
    coordinate = [
        {
            "a": round(points[0][0], 6),
            "o": round(points[0][1], 6),
            "v": 1,
            "s": 0.0,
            "t": 0,
            "ac": 0.0,
            "da": 0.0,
            "d": 0.0,
            "st": 0,
            "sta": 0,
        }
    ]
    elapsed, travelled, distance = 2.0, 0.0, 0.0
    previous_position = None
    previous_ms = 0
    while distance < 2150:
        speed = (
            base_speed
            + amplitude * math.sin(2 * math.pi * elapsed / period + phase)
            + rng.gauss(0, 0.05)
        )
        speed = min(5.0, max(4.0, speed))
        interval = 1 + rng.uniform(-0.05, 0.05)
        travelled += speed * interval
        route_distance = travelled % cumulative[-1]
        index = min(
            bisect.bisect_right(cumulative, route_distance) - 1, len(points) - 2
        )
        first, second = points[index], points[index + 1]
        segment_length = cumulative[index + 1] - cumulative[index]
        fraction = (
            (route_distance - cumulative[index]) / segment_length
            if segment_length
            else 0
        )
        latitude = first[0] + (second[0] - first[0]) * fraction
        longitude = first[1] + (second[1] - first[1]) * fraction
        lat_a, lat_b = math.radians(first[0]), math.radians(second[0])
        delta_lon = math.radians(second[1] - first[1])
        bearing = math.atan2(
            math.sin(delta_lon) * math.cos(lat_b),
            math.cos(lat_a) * math.sin(lat_b)
            - math.sin(lat_a) * math.cos(lat_b) * math.cos(delta_lon),
        )
        lateral = 0.7 * math.sin(2 * math.pi * elapsed / drift_period + drift_phase)
        latitude = round(latitude - math.sin(bearing) * lateral / 111_320, 6)
        longitude = round(
            longitude
            + math.cos(bearing)
            * lateral
            / (111_320 * math.cos(math.radians(latitude))),
            6,
        )
        current_ms = round(elapsed * 1000)
        segment = 0.0
        reported = speed
        if previous_position is not None:
            segment = haversine_distance(previous_position, (latitude, longitude))
            reported = (
                segment
                / max(0.2, (current_ms - previous_ms) / 1000)
                * rng.uniform(0.985, 1.015)
            )
        distance += segment
        coordinate.append(
            {
                "a": latitude,
                "o": longitude,
                "v": 1,
                "s": round(reported * 3.6, 2),
                "t": current_ms,
                "ac": round(rng.uniform(4, 12), 1),
                "da": round(distance, 6),
                "d": round(segment, 6),
                "st": 0,
                "sta": 0,
            }
        )
        previous_position, previous_ms = (latitude, longitude), current_ms
        elapsed += interval

    duration = math.ceil(previous_ms / 1000)
    local_end = (
        end_time.replace(tzinfo=CHINA_TIME)
        if end_time.tzinfo is None
        else end_time.astimezone(CHINA_TIME)
    )
    local_end = local_end.replace(microsecond=0)
    local_start = local_end - timedelta(seconds=duration)
    start_ms = int(local_start.timestamp()) * 1000
    pace, minute_speed = [], {}
    next_km, previous_seconds = 1, 0
    first_movement = next(point["t"] // 1000 for point in coordinate if point["d"] > 0)
    for point in coordinate[1:]:
        seconds = round(point["t"] / 1000)
        if point["da"] >= next_km * 1000:
            minutes, remainder = divmod(max(1, seconds - previous_seconds), 60)
            pace.append(
                {
                    "km": str(next_km),
                    "kmTotallength": float(next_km),
                    "kmdlsj": seconds,
                    "t": f"{minutes:02d}'{remainder:02d}''",
                }
            )
            next_km += 1
            previous_seconds = seconds
        minute = point["t"] // 60000 + 1
        minute_speed.setdefault(minute, []).append(point["s"])
        point["t"] += start_ms
    distance_km = distance / 1000
    average_speed = distance_km / (duration / 3600)
    pace_minutes, pace_seconds = divmod(max(1, round(duration / distance_km)), 60)
    steps = round(rng.uniform(155, 172) * duration / 60)
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    data = {
        "activeTime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "alreadyPassPoint": "",
        "alreadyPassPointResult": "",
        "avgPace": f"{pace_minutes:02d}'{pace_seconds:02d}''",
        "avgSpeed": f"{average_speed:.2f}".rstrip("0").rstrip("."),
        "beganPoint": f"{coordinate[0]['a']}|{coordinate[0]['o']}",
        "beginTime": local_start.strftime("%Y-%m-%d %H:%M:%S"),
        "calorie": round(distance_km * rng.uniform(53, 60), 1),
        "coordinate": coordinate,
        "endPoint": f"{coordinate[-1]['a']}|{coordinate[-1]['o']}",
        "endTime": local_end.strftime("%Y-%m-%d %H:%M:%S"),
        "indoor": 0,
        "isValid": 1,
        "isValidReason": "",
        "lastOdometerTime": f"00:{first_movement // 60:02d}:{first_movement % 60:02d}",
        # Match the upstream app-profile fields while deriving all statistics together.
        "maxSpeedPerHour": f"{average_speed:.2f}".rstrip("0").rstrip("."),
        "minSpeedPerHour": "6.0",
        "minuteSpeed": [
            {
                "min": str(minute),
                "v": f"{sum(values) / len(values):.2f}".rstrip("0").rstrip("."),
            }
            for minute, values in sorted(minute_speed.items())
        ],
        "modementMode": "3",
        "name": name,
        "needPassPointCount": "0",
        "odometer": f"{distance_km:.2f}".rstrip("0").rstrip("."),
        "pace": pace,
        "phoneVersion": "Android 16",
        "planRouteName": "跑步-男生",
        "routeId": "7",
        "sportId": sport_id,
        "stepCount": steps,
        "stepMinute": f"{steps / (duration / 60):.1f}".rstrip("0").rstrip("."),
        "xh": student_id,
    }
    sensor = []
    sensor_phase = rng.uniform(0, 2 * math.pi)
    for index in range(20 * duration):
        sample_time = index / 20
        stride = 5.2 * math.sin(
            2 * math.pi * rng.uniform(2.6, 2.9) * sample_time + sensor_phase
        )
        sway = 0.8 * math.sin(2 * math.pi * 0.35 * sample_time)
        sensor.append(round(9.8 + stride + sway + rng.gauss(0, 0.45), 6))
    return data, sensor

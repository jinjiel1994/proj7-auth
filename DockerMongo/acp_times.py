"""
Open and close time calculations
for ACP-sanctioned brevets
following rules described at https://rusa.org/octime_alg.html
and https://rusa.org/pages/rulesForRiders
"""
import arrow

#  Note for CIS 322 Fall 2016:
#  You MUST provide the following two functions
#  with these signatures, so that I can write
#  automated tests for grading.  You must keep
#  these signatures even if you don't use all the
#  same arguments.  Arguments are explained in the
#  javadoc comments.
#
from math import modf


def open_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
       brevet_dist_km: number, the nominal distance of the brevet
           in kilometers, which must be one of 200, 300, 400, 600,
           or 1000 (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string indicating
           the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control open time.
       This will be in the same time zone as the brevet start time.
    """
    TIME_TABLE = [(1000, 26), (600, 28), (400, 30), (200, 32), (0, 34)]
    dist_left = control_dist_km
    for element in TIME_TABLE:
        if element[0] > brevet_dist_km:
            continue
        else:
            if dist_left > element[0]:
                min ,hour = modf((dist_left - element[0]) * 1.0 / element[1])
                min = min * 60
                brevet_start_time = brevet_start_time.shift(hours=int(round(hour)), minutes=int(round(min)))
                dist_left = element[0]

    return brevet_start_time.isoformat()


def close_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
          brevet_dist_km: number, the nominal distance of the brevet
          in kilometers, which must be one of 200, 300, 400, 600, or 1000
          (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string indicating
           the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control close time.
       This will be in the same time zone as the brevet start time.
    """
    TIME_TABLE = [(1000, 1300, 13.333), (600, 1000, 11.428), (400, 600, 15), (200, 400, 15), (0, 200, 15), (0, 0, 15)]
    dist_left = control_dist_km
    threshold = False
    for element in TIME_TABLE:
        if element[0] > brevet_dist_km:
            continue
        else:
            if not threshold:
                if dist_left > element[0]:
                    min, hour = modf((dist_left - element[0]) * 1.0 / element[2])
                    min = min * 60
                    brevet_start_time = brevet_start_time.shift(hours=int(round(hour)), minutes=int(round(min)))
                    threshold = True
            else:
                min, hour = modf(element[1] * 1.0 / element[2])
                min = min * 60
                brevet_start_time = brevet_start_time.shift(hours=int(round(hour)), minutes=int(round(min)))
                break

    return brevet_start_time.isoformat()

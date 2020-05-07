# -*- coding: UTF-8 -*-
# Copyright (C) 2020 Brandon M. Pace
#
# This file is part of routeparser
#
# routeparser is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# routeparser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with routeparser.
# If not, see <https://www.gnu.org/licenses/>.

"""
The routeparser package provides a way to convert text output of routing information into Python objects.
"""


__author__ = "Brandon M. Pace"
__copyright__ = "Copyright 2020 Brandon M. Pace"
__license__ = "GNU LGPL 3+"
__maintainer__ = "Brandon M. Pace"
__status__ = "Development"
__version__ = "0.0.1"


import ipaddress
import logging
import re

from typing import Callable, List, Optional, Union


logger = logging.getLogger(__name__)

dotted_ip_re = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){0,3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
netstat_line_re = rf"^({dotted_ip_re}|default)\s+({dotted_ip_re}|\*)\s+({dotted_ip_re})\s+\w+\s+\d+\s\d+\s+\d+\s([\w\d\-\.\:]+)"
netstat_line_rec = re.compile(netstat_line_re)
linux_route_line_re = rf"^({dotted_ip_re}|default)\s+({dotted_ip_re}|\*)\s+({dotted_ip_re})\s+\w+\s+(\d+)\s\s+\d+\s+\d+\s([\w\d\-\.\:]+)"
linux_route_line_rec = re.compile(linux_route_line_re)
windows_route_print_v4_line_re = rf"^\s+({dotted_ip_re})\s+({dotted_ip_re})\s+({dotted_ip_re}|On-link)\s+({dotted_ip_re})\s+(\d+)"
windows_route_print_v4_line_rec = re.compile(windows_route_print_v4_line_re)


def is_ip_route_line(line: str) -> bool:
    """For 'ip route' on Linux"""
    if (" dev " in line) and (" proto " in line):
        return True
    else:
        return False


def is_linux_route_line(line: str) -> bool:
    """For output of 'route' or 'route -n' on Linux"""
    if linux_route_line_rec.match(line):
        return True
    else:
        return False


def is_netstat_route_line(line: str) -> bool:
    """For output of 'netstat -r', 'netstat -rn' or 'netstat -rnv' on Linux"""
    if netstat_line_rec.match(line):
        return True
    else:
        return False


def is_route_print_v4_line(line: str) -> bool:
    """For IPv4 lines in 'route print' on Windows"""
    if windows_route_print_v4_line_rec.match(line):
        return True
    else:
        return False


class Route:
    def __init__(self, network: str, interface: str, gateway: str = "", metric: int = 0):
        self._network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(network)
        self._interface = interface
        if gateway:
            self._gateway: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = ipaddress.ip_address(gateway)
            if self._gateway.version != self._network.version:
                raise ValueError(
                    f"IP version mismatch! Network: {self._network.version} Gateway: {self._gateway.version}"
                )
        else:
            self._gateway = None

        if isinstance(metric, int):
            self._metric = metric
        else:
            raise ValueError(f"expected int for metric, got {type(metric)}")

    def __contains__(
            self,
            item: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network]
    ) -> bool:
        if isinstance(item, str):
            try:
                ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = ipaddress.ip_address(item)
            except Exception:
                try:
                    ip_network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(item)
                except Exception:
                    return False
                else:
                    if ip_network.version == self._network.version:
                        return ip_network.subnet_of(self._network)
                    else:
                        return False
            else:
                return ip_address in self._network
        elif isinstance(item, ipaddress.IPv4Address) or isinstance(item, ipaddress.IPv6Address):
            return item in self._network
        elif isinstance(item, ipaddress.IPv4Network) or isinstance(item, ipaddress.IPv6Network):
            if item.version == self._network.version:
                return item.subnet_of(self._network)
            else:
                return False

    def __eq__(self, other: 'Route') -> bool:
        if self is other:
            return True
        elif type(self) != type(other):
            return NotImplemented
        else:
            return hash(self) == hash(other)

    def __ge__(self, other: 'Route') -> bool:
        if self is other:
            return True
        elif type(self) != type(other):
            return NotImplemented
        elif self._network.netmask > other._network.netmask:
            return True
        elif self._network.netmask == other._network.netmask:
            if self._network > other._network:
                return True
            elif self._network == other._network:
                return self._metric <= other._metric  # sort lower metric as more preferred
            else:
                return False
        else:
            return False

    def __gt__(self, other: 'Route') -> bool:
        if self is other:
            return False
        elif type(self) != type(other):
            return NotImplemented
        elif self._network.netmask > other._network.netmask:
            return True
        elif self._network.netmask == other._network.netmask:
            if self._network > other._network:
                return True
            elif self._network == other._network:
                return self._metric < other._metric  # sort lower metric as more preferred
            else:
                return False
        else:
            return False

    def __hash__(self):
        return hash(
            (
                self._network.exploded,
                self._gateway.exploded if self._gateway else "None",
                self._metric,
                self._interface
            )
        )

    def __le__(self, other: 'Route') -> bool:
        if self is other:
            return False
        elif type(self) != type(other):
            return NotImplemented
        elif self._network.netmask < other._network.netmask:
            return True
        elif self._network.netmask == other._network.netmask:
            if self._network < other._network:
                return True
            elif self._network == other._network:
                return self._metric >= other._metric  # sort lower metric as more preferred
            else:
                return False
        else:
            return False

    def __lt__(self, other: 'Route') -> bool:
        if self is other:
            return False
        elif type(self) != type(other):
            return NotImplemented
        elif self._network.netmask < other._network.netmask:
            return True
        elif self._network.netmask == other._network.netmask:
            if self._network < other._network:
                return True
            elif self._network == other._network:
                return self._metric > other._metric  # sort lower metric as more preferred
            else:
                return False
        else:
            return False

    def __ne__(self, other: 'Route') -> bool:
        if self is other:
            return False
        elif type(self) != type(other):
            return NotImplemented
        else:
            return hash(self) != hash(other)

    def __repr__(self):
        return "%s(%r, %r, ...)" % (self.__class__.__name__, self._network, self._gateway)

    @property
    def gateway(self) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        return self._gateway

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def metric(self) -> int:
        return self._metric

    @property
    def netmask(self) -> str:
        return str(self._network.netmask)

    @property
    def network(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        return self._network

    @property
    def prefix(self) -> int:
        return self._network.prefixlen

    @property
    def version(self) -> int:
        return self._network.version

    @classmethod
    def from_ip_route_line(cls, line: str, safe: bool = False) -> Optional['Route']:
        """Handles a single output line of 'ip route' and converts to a Route object"""
        if not is_ip_route_line(line):
            logger.debug(f"line does not appear to be relevant: '{line}'")
            return None

        split_line = line.split()
        if "via" in split_line:
            gateway = split_line[split_line.index("via") + 1]
        else:
            gateway = ""

        if split_line[0] == "default":
            if ":" in gateway:
                network = "::/0"
            else:
                network = "0.0.0.0/0"
        else:
            network = split_line[0]

        if "dev" in split_line:
            interface = split_line[split_line.index("dev") + 1]
        else:
            logger.error(f"could not find interface in line: '{line}'")
            interface = ""

        try:
            new_route = Route(network, interface, gateway)
        except Exception:
            if safe:
                logger.exception(f"exception while creating Route instance")
                return None
            else:
                raise
        else:
            return new_route

    @classmethod
    def from_ip_route_lines(cls, lines: List[str], safe: bool = False) -> List['Route']:
        """Handles output of 'ip route' and converts to Route objects"""
        return cls.parse_lines(cls.from_ip_route_line, lines, safe)

    @classmethod
    def from_linux_netstat_line(cls, line: str, safe: bool = False) -> Optional['Route']:
        """
        Handles single output line of LINUX 'netstat -r', 'netstat -rn' or 'netstat -rnv' and converts to a Route object
        """
        if not is_netstat_route_line(line):
            logger.debug(f"line does not appear to be relevant: '{line}'")
            return None

        split_line = line.split()

        network = "0.0.0.0" if split_line[0] == "default" else split_line[0]
        netmask = split_line[2]

        gateway_part = split_line[1]
        if (gateway_part == "0.0.0.0") or (gateway_part == "*"):
            gateway = ""
        else:
            gateway = gateway_part

        interface = split_line[-1]

        try:
            new_route = Route(f"{network}/{netmask}", interface, gateway)
        except Exception:
            if safe:
                logger.exception(f"exception while creating Route instance")
                return None
            else:
                raise
        else:
            return new_route

    @classmethod
    def from_linux_netstat_lines(cls, lines: List[str], safe: bool = False) -> List['Route']:
        """
        Handles output of LINUX 'netstat -r', 'netstat -rn' or 'netstat -rnv' and converts to Route objects
        """
        return cls.parse_lines(cls.from_linux_netstat_line, lines, safe)

    @classmethod
    def from_linux_route_line(cls, line: str, safe: bool = True) -> Optional['Route']:
        """
        Handles single output line of LINUX 'route' or 'route -n' and converts to a Route object
        """
        if not is_linux_route_line(line):
            logger.debug(f"line does not appear to be relevant: '{line}'")
            return None

        split_line = line.split()

        network = "0.0.0.0" if split_line[0] == "default" else split_line[0]
        netmask = split_line[2]

        gateway_part = split_line[1]
        if (gateway_part == "0.0.0.0") or (gateway_part == "*"):
            gateway = ""
        else:
            gateway = gateway_part

        interface = split_line[-1]

        metric = int(split_line[4])

        try:
            new_route = Route(f"{network}/{netmask}", interface, gateway, metric)
        except Exception:
            if safe:
                logger.exception(f"exception while creating Route instance")
                return None
            else:
                raise
        else:
            return new_route

    @classmethod
    def from_linux_route_lines(cls, lines: List[str], safe: bool = False) -> List['Route']:
        """Handles output of LINUX 'route' or 'route -n' and converts to Route objects"""
        return cls.parse_lines(cls.from_linux_route_line, lines, safe)

    @classmethod
    def from_windows_route_print_line(cls, line: str, safe: bool = False) -> Optional['Route']:
        """
        Handles single output line of WINDOWS 'route print' or 'netstat -r' and converts to a Route object
        """
        # TODO: add IPv6 support for Windows output
        if not is_route_print_v4_line(line):
            logger.debug(f"line does not appear to be relevant: '{line}'")
            return None

        split_line = line.split()

        network = split_line[0]
        netmask = split_line[1]

        if split_line[2] == "On-link":
            gateway = ""
        else:
            gateway = split_line[2]

        interface = split_line[3]

        metric = int(split_line[4])

        try:
            new_route = Route(f"{network}/{netmask}", interface, gateway, metric)
        except Exception:
            if safe:
                logger.exception(f"exception while creating Route instance")
                return None
            else:
                raise
        else:
            return new_route

    @classmethod
    def from_windows_route_print_lines(cls, lines: List[str], safe: bool = False) -> List['Route']:
        return cls.parse_lines(cls.from_windows_route_print_line, lines, safe)

    @classmethod
    def parse_lines(cls, parser: Callable, lines: List[str], safe: bool = False) -> List['Route']:
        """
        Used internally for parsing functionality, but can be used with custom external parsers.
        """
        routes: List[Route] = []

        for line in lines:
            result = parser(line, safe)
            if result is None:
                continue
            routes.append(result)

        return routes


class RoutingTable:
    def __init__(self, routes: List[Route], prefer_lowest_metric: bool = True):
        self._routes = routes
        self._prefer_lowest_metric = prefer_lowest_metric
        self._routes.sort()

    @classmethod
    def from_ip_route_lines(
            cls, lines: List[str], safe: bool = False, prefer_lowest_metric: bool = True
    ) -> 'RoutingTable':
        return cls(Route.from_ip_route_lines(lines, safe=safe), prefer_lowest_metric=prefer_lowest_metric)

    @classmethod
    def from_linux_route_lines(
            cls, lines: List[str], safe: bool = False, prefer_lowest_metric: bool = True
    ) -> 'RoutingTable':
        return cls(Route.from_linux_route_lines(lines, safe=safe), prefer_lowest_metric=prefer_lowest_metric)

    @classmethod
    def from_linux_netstat_lines(
            cls, lines: List[str], safe: bool = False, prefer_lowest_metric: bool = True
    ) -> 'RoutingTable':
        return cls(Route.from_linux_netstat_lines(lines, safe=safe), prefer_lowest_metric=prefer_lowest_metric)

    @classmethod
    def from_windows_route_print_lines(
            cls, lines: List[str], safe: bool = False, prefer_lowest_metric: bool = True
    ) -> 'RoutingTable':
        return cls(Route.from_windows_route_print_lines(lines, safe=safe), prefer_lowest_metric=prefer_lowest_metric)

    def match(
            self,
            item: Union[str, ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network]
    ) -> Optional[Route]:
        """
        Return the most narrow matching route (if any)
        :param item: an address or network object from the ipaddress module or a string compatible with those objects
        """
        matches = self.matches(item)
        if matches:
            if len(matches) == 1:
                return matches[0]
            else:
                final_match = matches[-1]
                for match in matches[:-1]:
                    if match.netmask < final_match.netmask:
                        continue
                    elif match.netmask > final_match.netmask:
                        logger.warning(f"POSSIBLE BUG: the list is likely not sorted properly!")
                        final_match = match
                    elif (match.network == final_match.network) and (match.netmask == final_match.netmask):
                        if self._prefer_lowest_metric:
                            if match.metric < final_match.metric:
                                final_match = match
                        else:
                            if match.metric > final_match.metric:
                                final_match = match
                return final_match
        else:
            return None

    def matches(
            self,
            item: Union[str, ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network]
    ) -> List[Route]:
        """
        Return a list of any matching route objects with the most narrow match being the last item
        :param item: an address or network object from the ipaddress module or a string compatible with those objects
        """
        ip_address: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
        ip_network: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None

        if isinstance(item, str):
            try:
                ip_address = ipaddress.ip_address(item)
            except Exception:
                try:
                    ip_network = ipaddress.ip_network(item)
                except Exception:
                    raise ValueError(f"'{item}' does not appear to be an IPv4 or IPv6 address or network")

        elif isinstance(item, ipaddress.IPv4Address) or isinstance(item, ipaddress.IPv6Address):
            ip_address = item
        elif isinstance(item, ipaddress.IPv4Network) or isinstance(item, ipaddress.IPv6Network):
            ip_network = item
        else:
            raise ValueError(f"type is not supported: '{type(item)}'")

        matches: List[Route] = []
        if ip_address is not None:
            for route in self._routes:
                if ip_address in route:
                    matches.append(route)
        elif ip_network is not None:
            for route in self._routes:
                if ip_network in route:
                    matches.append(route)
        else:
            raise ValueError("Did not find a relevant object!")

        matches.sort()
        return matches

    @property
    def prefer_lowest_metric(self):
        return self._prefer_lowest_metric

    @property
    def routes(self):
        return self._routes.copy()

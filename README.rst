routeparser:
A route command output text parser

It provides:  
  * Reading text output of routes into Python objects
  * Simple identification of routes that match hosts or networks
  

Installation:  
  * pip install routeparser


Usage:
    * example (where `netstat_rn.txt` is full output from 'netstat -rn' on Linux)::

        import routeparser

        # read lines from a file
        with open('netstat_rn.txt', 'r') as file_handle:
            lines = file_handle.readlines()

        # You can just get objects representing the routes if you wish:
        routes = routeparser.Route.from_linux_netstat_lines(lines)

        # These have attributes such as gateway, interface and network.
        # Some example values as in-line comments:
        routes[0].gateway  # ipaddress.IPv4Address('192.168.1.1')
        routes[0].interface  # 'eth0'
        routes[0].network  # ipaddress.IPv4Network('10.10.0.0/16')

        # Route objects support membership testing:
        '10.10.10.1' in routes[0]  # would return True, given the above example route

        # You can get a RoutingTable object from the lines:
        table = routeparser.RoutingTable.from_linux_netstat_lines(lines)

        # which you can then use to check for specific route matches:
        table.match('10.10.10.1')  # would result in a matching Route object, if any

        # It supports string or Address/Network objects from the ipaddress module:
        import ipaddress
        table.match(ipaddress.ip_network('10.10.10.0/24'))

        # You can even get a list of all matching routes:
        table.matches('10.10.10.10')

        # Currently supported outputs and associated methods (for Route and RoutingTable)
        # Windows:
        #  - 'route print': from_windows_route_print_lines
        # Linux:
        #  - 'ip route': from_ip_route_lines
        #  - 'netstat -r[nv]': from_linux_netstat_lines
        #  - 'route [-n]': from_linux_route_lines


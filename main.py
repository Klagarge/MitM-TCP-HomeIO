import packet_monitor as mitm

if __name__ == "__main__":
    # Add IP addresses to monitor
    mitm.add_ip('192.168.39.110')  # Simulation
    mitm.add_ip('192.168.37.163')  # Controller

    # Add monitoring for discrete inputs
    mitm.add_monitor_discrete_input(5, 15, 0)
    mitm.add_monitor_discrete_input(5, 14, 1)
    mitm.add_monitor_discrete_input(5, 13, 1)

    # Start monitoring
    mitm.start_monitoring()

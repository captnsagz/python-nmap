import nmap
import nmap3
import sys
import subprocess


def clear_screen():
    subprocess.call('clear', shell='True')
try:
    subprocess.call("clear",shell="True")
    host = input("Enter the host to scan :")
    start_port = 21
    end_port = 40
    scanner = nmap.PortScanner()
    nmp = nmap3.Nmap() 
    #response = scanner.scan(host)
    #ipaddr = list(response['scan'])[0]
    exit_counter = 0

    while exit_counter == 0 :
        print("""
        PRESS 1 TO PERFORM A RANGE PORT(S) SCAN
        PRESS 2 TO PERFORM A TOP PORTS SCAN
        PRESS 3 TO PERFORM AN OS SCAN 
        PRESS 4 TO PERFORM A SERVICE IDENTIFICATION SCAN
        PRESS 5 TO PERFORM A SELECT NMAP SCAN TECHNIQUE
        PRESS 6 TO PERFORM A DNS-BRUTE-SCRIPT (GET SUBDOMAINS)
        PRESS 7 TO CHANGE HOST OR DOMAIN
        PRESS 8 TO EXIT PROGRAM
        """)
        choice = int(input("Enter your choice :"))
        if choice == 1:
            subprocess.call('clear', shell='True')
            for i in range(start_port,end_port+1):
                try:
                    response = scanner.scan(host, str(i))
                    ipaddr = list(response['scan'])[0]
                    service_state = response['scan'][ipaddr]['tcp'][i]['state']
                    print(f'port {i} is {service_state}')
                except:
                    print(f'Error scanning port {i}')

        elif choice == 2:
            top_ports = nmp.scan_top_ports(host)
            ipaddr = list(top_ports)[0]
            port_keys = list(top_ports[ipaddr]['ports'][0])
            for i in range(len(top_ports[ipaddr]['ports'])):
                for j in port_keys:
                    if top_ports[ipaddr]['ports'][i][j] == 'service':
                        print(f'{j}',top_ports[ipaddr]['ports'][i][j]['name'])
                    else:
                        print(f'{j} : ', top_ports[ipaddr]['ports'][i][j])
            

        elif choice == 3:
            try:
                os_variable = nmp.nmap_os_detection(host)
                ipaddr = list(os_variable)[0]
                os_keys = list(os_variable[ipaddr]['osmatch'][0])
                subprocess.call('clear', shell='True')
                for i in range(len(list(os_variable[ipaddr]['osmatch']))):
                    for j in os_keys:
                        print(f'{j} is :', os_variable[ipaddr]['osmatch'][i][j])
            except Exception as e:
                print(f'Error : {e}')

        elif choice == 4:
            clear_screen()
            Top_ports = [21,22,23,25,80,110,139,443,445,3389]
            top_portskeys = ['state', 'reason', 'name', 'product', 'version', 'extrainfo', 'conf', 'cpe']
            for i in Top_ports:
                for j in top_portskeys:
                    try:
                            
                        response = scanner.scan(host, str(i))
                        ipaddr = list(response['scan'])[0]
                        print(f'{j} : ', response['scan'][ipaddr]['tcp'][i][j])
                    except:
                        print(f'Error scanning port {i}')
        elif choice == 5:
            scan = nmap3.NmapScanTechniques()
            select = 0
            clear_screen()
            while select  != 7:
                print("""
                PRESS 1 TO PERFORM A FIN SCAN
                PRESS 2 TO PERFORM AN IDLE SCAN
                PRESS 3 TO PERFORM A PING SCAN 
                PRESS 4 TO PERFORM A SYN SCAN
                PRESS 5 TO PERFORM A TCP SCAN
                PRESS 6 TO PERFORM A UDP SCAN
                press 7 TO EXIT TO MAIN MENU
                """)
                select = int(input("CHOOSE AN OPTION :"))
                if select == 1:
                    fin_scan = scan.nmap_fin_scan(host)
                    print(fin_scan)
                elif select == 2:
                    idle_scan = scan.nmap_idle_scan(host)
                    print(idle_scan)
                elif select == 3:
                    ping_scan = scan.nmap_ping_scan(host)
                    print(ping_scan)
                elif select == 4:
                    syn_scan = scan.nmap_syn_scan(host)
                    print(syn_scan)
                elif select == 5:
                    tcp_scan = scan.nmap_tcp_scan(host)
                    print(tcp_scan)
                elif select == 6:
                    try:
                        udp_scan = scan.nmap_udp_scan(host)
                        print(udp_scan)
                    except Exception as e:
                        print(f'Error : {e}')
                elif select == 7:
                    print('Exiting to main menu')
                else:
                    print('SELECT A VALID OPTION PLEASE!')


        elif choice == 6:
            dns_bruteScan = nmp.nmap_dns_brute_script(host)
            key_length = int(len(dns_bruteScan))
            for i in range(key_length):
                print(f'Hostname is : {dns_bruteScan[i]["hostname"]}')
                print(f'Address is : {dns_bruteScan[i]["address"]}')
            

        elif choice == 7:
            host = input("Enter the host to scan :")
            response = scanner.scan(host)
            ipaddr = list(response['scan'])[0]

        elif choice == 8:
            print(f"\nExiting program {sys.argv[0]}")
            exit_counter = exit_counter + 1
            
except Exception as e:
    print(f'Error: {e}')

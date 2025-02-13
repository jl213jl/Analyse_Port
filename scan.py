import nmap

def scaner(ip):
    nm = nmap.PortScanner()
    print(f'Scanning Ip : {ip}')

    try:
        nm.scan(ip, '1-1024')
        print(f'Scan of {ip} succesfull')

        for host in nm.all_hosts():
            print(f'Host: {host}')
            print(f'Etat scsan : {nm[host].state()} ')
            for protocol in nm[host].all_protocols():
                print(f'Protocole : {protocol}')
                try :
                    
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        service = nm[host][protocol][port]['name']
                        print(f'Port {port} est ouvert dans le service {service}')
                except Exception as e :
                    print(f'Problemes acces de données au port {port} pour {protocol}')
    except Exception as e:
        print(f'Erreur scan {e}')
        
ip_scan = input('Entrée Adresse Ip: ')
scaner(ip_scan)
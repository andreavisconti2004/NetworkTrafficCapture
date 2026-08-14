#IMPORTAZIONE DELLE LIBRERIE
import sys  #Caricamento delle funzioni di sistema per leggere gli argomenti passati da terminale (nome del file .PCAP)
import argparse #Utile per il Parsing
import csv #Funzioni per creare e scrivere file in formato .csv
#Import Scapy, necessaria per lavorare con i pacchetti di rete
from scapy.all import rdpcap, IP, TCP, UDP, DNSRR, DNSQR, Raw, load_layer 
load_layer("tls")   #Per caricare i protocolli di crittografia (HTTPS)
from scapy.layers.tls.handshake import TLSClientHello
from ipwhois import IPWhois #Per interrogare WhoIs
from ipwhois.exceptions import IPDefinedError   #Per gestire i casi in cui l'IP è privato



#LETTURA DA FILE
def carica_pcap(file_pcap):
    print(f"[*] Caricamento del file PCAP: {file_pcap}...")
    try:
        pacchetti = rdpcap(file_pcap)   #Scapy legge il file binario e lo trasforma in pacchetti analizzabili
        print(f"[+] File caricato. Numero di pacchetti: {len(pacchetti)}")
        return pacchetti
    except FileNotFoundError:   #File non trovato (Eccezzione)
        print(f"[!] Errore: Il file {file_pcap} non è stato trovato.")
        return None



#ESTRAZIONE BIFLUSSI
def estrazione_biflussi(pacchetti):
    print("[*] Sto estraendo le conversazioni (biflussi)...")
    biflussi = {} # Creiamo un dizionario
    for pacchetto in pacchetti:
        if IP in pacchetto and (TCP in pacchetto or UDP in pacchetto): #Filtro solo gli indirizzi IP che usano TCP o UDP
            protocollo_str = "TCP" if TCP in pacchetto else "UDP"   #Protocollo di livello trasporto del pacchetto
            protocollo_layer = pacchetto[TCP] if TCP in pacchetto else pacchetto[UDP]   #Puntatore allo strato del pacchetto
            #Estraiamo i 4 dati chiave: Indirizzo IP e porta, sorgente e destinazione
            ip_sorgente = pacchetto[IP].src
            ip_destinazione = pacchetto[IP].dst
            porta_sorgente = protocollo_layer.sport
            porta_destinazione = protocollo_layer.dport

            #Per identificare i biflussi usiamo una funzione di normalizzazione.
            #Ordino alfabeticamente tramite la funzione sorted() la coppia (IP, porta) sorgente e destinazione.
            #In questo modo sia per la direzione A->B che per B->A, l'ordine sarà identico. 
            #La funzione tuple() genera una chiave univoca per ciascun biflusso, necessaria per salavare la conversazione nel dizionario
            chiave_biflusso = tuple(sorted(((ip_sorgente, porta_sorgente), (ip_destinazione, porta_destinazione)))) + (protocollo_str,)

            #Prima estrazione
            if chiave_biflusso not in biflussi:
                biflussi[chiave_biflusso] = {'pacchetti_totali': 0, 'byte_totali': 0}
            #Aggiorniamo il numero di pacchetti e byte totali se non è la prima estrazione
            biflussi[chiave_biflusso]['pacchetti_totali'] += 1
            biflussi[chiave_biflusso]['byte_totali'] += len(pacchetto) #Aggiungiamo la dimensione del pacchetto

    print(f"[+] Trovate {len(biflussi)} biflussi.")
    return biflussi # Restituisce il dizionario



#RISOLUZIONE DNS, CAMPO SNI E CAMPO HOST HTTP
def analisi_dettagli_pacchetti(pacchetti):
    print("[*] Analisi per DNS, SNI e Host HTTP...")
    risoluzioni_dns = {} # Dizionario DNS
    richieste_sni = {}   # Dizionario SNI
    host_http = {}     # Dizionario HTTP

    for pacchetto in pacchetti:
        # 1. RICERCA DNS: 
        #Verifico se si ha una risposta da un server DNS (type 1 per indicare l'assoziazione di nome a un indirizzo IPv4)
        if pacchetto.haslayer(DNSRR) and pacchetto.getlayer(DNSRR).type == 1:   
            try:
                nome_dominio = pacchetto[DNSQR].qname.decode() # "google.com"
                indirizzo_ip = pacchetto[DNSRR].rdata        # "142.250.184.14"
                risoluzioni_dns[nome_dominio] = indirizzo_ip # Associa nome a IP
            except:
                continue # Ignora se c'è un errore

        # 2. RICERCA SNI:
        # Verifico se il pacchetto è un "ClientHello" di TLS
        if pacchetto.haslayer(TLSClientHello) and pacchetto.haslayer(IP):
            tls_layer = pacchetto.getlayer(TLSClientHello)
            # Usiamo getattr per controllare in modo sicuro se 'extensions' esiste
            extensions = getattr(tls_layer, 'extensions', None) #Se non esiste scrivi None
            
            if extensions:
                for ext in extensions:
                    # Il tipo 0 corrisponde al Server Name Indication (SNI)
                    if getattr(ext, 'type', None) == 0: 
                        try:
                            server_name = ext.servernames[0].servername.decode()
                            richieste_sni[pacchetto[IP].dst] = server_name
                        except:
                            continue
            
        # 3. RICERCA HTTP:
        #Lo strato Raw in Scapy contiene il payload del pacchetto
        if pacchetto.haslayer(Raw) and pacchetto.haslayer(IP) and b"Host: " in pacchetto[Raw].load: #Controllo se è presente una stringa host
            try:
                # Estrae il nome host dopo "Host: "
                host = pacchetto[Raw].load.split(b"Host: ")[1].split(b"\r\n")[0].decode() #Poiché le intestazioni HTTP finiscono sempre con un a capo prendo solo la prima riga
                host_http[pacchetto[IP].dst] = host # Associa l'IP al nome host
            except:
                continue
    print("[+] Analisi DNS, SNI e Host HTTP completata.")
    return risoluzioni_dns, richieste_sni, host_http



#INTERROGAZIONE WHOIS
def whois(ip_address):
    try:
        obj = IPWhois(ip_address) # Creo l'oggetto per la ricerca
        risultati = obj.lookup_whois() # Fa la ricerca online
        #Cerco la sezione "nets", Se non la trova, usa una lista vuota [{}] per evitare di andare in crash
        return risultati.get('nets', [{}])[0].get('name', 'N/A')    #Cerco il campo name dell'organizzazione
    except IPDefinedError:
        return "IP Privato/Riservato" # In eccezzione se ho un indirizzo riservato o privato
    except Exception:
        return "Errore WHOIS" # Se la ricerca fallisce


#MAIN
def main(file_pcap):
    #LETTURA DA FILE:
    pacchetti = carica_pcap(file_pcap)
    if not pacchetti:   #Se non ci sono pacchetti nella cattura
        return
    #ESTRAZIONE BIFLUSSI:
    biflussi = estrazione_biflussi(pacchetti)
    #ESTRAZIONE DNS, SNI E HTTP:
    risoluzioni_dns, richieste_sni, host_http = analisi_dettagli_pacchetti(pacchetti)

    # Lo script ha raccolto i DNS come {Nome: IP}, ma per il report ci serve l'opposto.
    # Usiamo una 'dictionary comprehension' per invertire chiavi e valori.
    # Questo trasforma il dizionario in {IP: Nome}, permettendo allo script di
    # trovare istantaneamente il nome del sito partendo dall'indirizzo IP incontrato ni biflussi
    dns_ip_map = {ip: nome for nome, ip in risoluzioni_dns.items()}
    print("[*] Generazione del report CSV: report_analisi_traffico.csv...")

    #Apertura File CSV in modalità scrittura:
    with open('report_analisi_traffico.csv', 'w', newline='', encoding='utf-8') as file_csv:
        #Nome delle colonne:
        fieldnames = ['IP_1', 'Porta_1', 'IP_2', 'Porta_2', 'Protocollo', 'Pacchetti_Totali', 'Byte_Totali', 
                      'Nome_Dominio_Associato', 'SNI_TLS', 'Host_HTTP', 
                      'Organizzazione_WHOIS_IP_1', 'Organizzazione_WHOIS_IP_2']
        #Creazione dello scrittore:
        writer = csv.DictWriter(file_csv, fieldnames=fieldnames)
        writer.writeheader() # Scrittura delle colonne sulla prima riga

        #LOGICA DI ASSEMBLAGGIO DATI PER IL REPORT
        #Per ogni conversazione identificata, identifichiamo i dati per il CSV:
        #1. 'Spacchettiamo' la chiave composta per ottenere IP, Porte dei due host e protocollo di livello trasporto.
        #2. Utilizziamo la mappa DNS invertita (dns_ip_map) per cercare se a quegli IP
        #   corrisponde un nome di dominio scoperto precedentemente.
        #3. Usiamo il metodo .get() con valore di default 'N/A' per gestire in sicurezza
        #   gli IP che non hanno una risoluzione DNS associata, evitando interruzioni.
        for chiave_biflusso, dati in biflussi.items():
            ip_porta_1, ip_porta_2, protocollo = chiave_biflusso
            ip1, porta1 = ip_porta_1
            ip2, porta2 = ip_porta_2
            nome_dominio1 = dns_ip_map.get(ip1, 'N/A')
            nome_dominio2 = dns_ip_map.get(ip2, 'N/A')

        # Scrittura di una riga nel file CSV
            writer.writerow({
                'IP_1': ip1,
                'Porta_1': porta1,
                'IP_2': ip2,
                'Porta_2': porta2,
                'Protocollo': protocollo,
                'Pacchetti_Totali': dati['pacchetti_totali'],
                'Byte_Totali': dati['byte_totali'],
                'Nome_Dominio_Associato': f"{nome_dominio1} | {nome_dominio2}",
                'SNI_TLS': richieste_sni.get(ip1, 'N/A') + " | " + richieste_sni.get(ip2, 'N/A'),
                'Host_HTTP': host_http.get(ip1, 'N/A') + " | " + host_http.get(ip2, 'N/A'),
                #INTERROFAZIONE WHOIS:
                'Organizzazione_WHOIS_IP_1': whois(ip1),
                'Organizzazione_WHOIS_IP_2': whois(ip2),
            })

    print("[+] Report generato con successo! Salvato come: 'report_analisi_traffico.csv'")

#LOGICA DI AVVIO E GESTIONE ARGOMENTI DA TERMINALE
# 1. 'if __name__ == "__main__":' assicura che lo script parta solo se eseguito direttamente.
# 2. Definiamo un argomento obbligatorio (il file .pcap) che l'utente deve fornire.
# 3. 'parse_args()' preleva il nome del file digitato nel terminale dall'utente.
# 4. Infine, chiamiamo la funzione main() passando il file da analizzare.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analizzatore di traffico di rete da file PCAP.")
    parser.add_argument("file_pcap", help="Il percorso del file .pcap da analizzare.")
    args = parser.parse_args()
    main(args.file_pcap)
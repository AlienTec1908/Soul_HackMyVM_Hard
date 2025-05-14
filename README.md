# Soul - HackMyVM (Hard)
 
![Soul.png](Soul.png)

## Übersicht

*   **VM:** Soul
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Soul)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 17. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Soul_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der Challenge "Soul" war es, User- und Root-Rechte auf einer als "Hard" eingestuften Maschine zu erlangen. Der Weg begann mit der Entdeckung von Steganographie in einer Bilddatei auf dem Webserver, was zum Passwort `lionsarebigcats` führte. Dieses Passwort wurde zusammen mit dem Benutzernamen `daniel` für einen erfolgreichen SSH-Login verwendet. Die initiale Shell war eine Restricted Bash (`rbash`), die umgangen wurde. Die Enumeration der Nginx-Konfiguration offenbarte einen VHost (`lonelysoul.hmv`), der PHP-Ausführung erlaubte. Eine PHP-Reverse-Shell wurde hochgeladen, um Zugriff als `www-data` zu erhalten. Die Privilegieneskalation erfolgte dann in mehreren Schritten: Zuerst von `www-data` zu `gabriel` durch eine unsichere `sudo`-Regel (`/tmp/whoami`), dann von `gabriel` zu `peter` durch eine weitere unsichere `sudo`-Regel (`hping3`), und schließlich von `peter` zu `root` durch Ausnutzung eines fehlerhaft konfigurierten SUID/SGID `agetty`-Binaries.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `vi`
*   `curl`
*   `wget`
*   `stegseek`
*   `cat`
*   `steghide`
*   `hydra`
*   `ssh`
*   `echo`
*   `ls`
*   `grep`
*   `cp`
*   `python3`
*   `nc` (netcat)
*   `export`
*   `stty`
*   `fg`
*   `sudo`
*   `chmod`
*   `bash`
*   `hping3`
*   `find`
*   `agetty`
*   `id`
*   `cd`
*   `pwd`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Soul" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.152`).
    *   `nmap`-Scan identifizierte offene Ports 22 (SSH - OpenSSH 7.9p1) und 80 (HTTP - Nginx 1.14.2).
    *   `gobuster` auf Port 80 fand `/index.html`, `/robots.txt` (enthielt `/nothing`) und `/saint.jpg`.

2.  **Web/Service Enumeration & Steganographie:**
    *   Herunterladen von `saint.jpg`.
    *   `stegseek` mit `rockyou.txt` fand eine mit leerer Passphrase versteckte Datei `pass.txt` in `saint.jpg`.
    *   Inhalt von `pass.txt`: `lionsarebigcats`.

3.  **Initial Access (SSH Brute Force & rbash Bypass):**
    *   `hydra` mit der Benutzerliste `names.txt` und dem Passwort `lionsarebigcats` fand gültige SSH-Credentials: `daniel`:`lionsarebigcats`.
    *   SSH-Login als `daniel`. Die Shell war `rbash`.
    *   Bypass der `rbash` durch `ssh daniel@192.168.2.152 -t "bash --noprofile"`.

4.  **Post-Exploitation (Nginx Konfiguration & PHP Shell als `www-data`):**
    *   Untersuchung der Nginx-Konfiguration `/etc/nginx/sites-available/default` zeigte einen VHost `lonelysoul.hmv`, der PHP-Ausführung über `php7.3-fpm.sock` erlaubte. Webroot: `/var/www/html`.
    *   Erstellen eines Eintrags für `lonelysoul.hmv` in der lokalen `/etc/hosts`-Datei.
    *   `daniel` hatte Schreibrechte in `/var/www/html`.
    *   Hochladen einer PHP-Reverse-Shell (`rev.php`, lauscht auf Port 9001) nach `/var/www/html` via `wget` von einem lokalen Python HTTP-Server.
    *   Auslösen der PHP-Shell mit `curl http://lonelysoul.hmv/rev.php`, was zu einer Reverse Shell als `www-data` führte.
    *   Stabilisierung der `www-data`-Shell.

5.  **Privilege Escalation (von `www-data` zu `gabriel`):**
    *   `sudo -l` als `www-data` zeigte: `(gabriel) NPASSWD: /tmp/whoami`.
    *   Erstellen einer Datei `/tmp/whoami` mit Inhalt `bash` und Ausführen als `gabriel` via `sudo -u gabriel /tmp/whoami`.
    *   Erlangung einer Shell als Benutzer `gabriel`. User-Flag in `/home/gabriel/user.txt` gelesen.

6.  **Privilege Escalation (von `gabriel` zu `peter`):**
    *   `sudo -l` als `gabriel` zeigte: `(peter) NPASSWD: /usr/sbin/hping3`.
    *   Ausführen von `sudo -u peter hping3` und Eingabe von `/bin/bash` am `hping3>`-Prompt.
    *   Erlangung einer Shell als Benutzer `peter`.

7.  **Privilege Escalation (von `peter` zu `root`):**
    *   `find / -perm -u=s -type f 2>/dev/null` identifizierte `/usr/sbin/agetty` als SUID Root und SGID `peter` (`-rwsrws--- 1 root peter ...`).
    *   Ausnutzung von `agetty` mit `/usr/sbin/agetty -o -p -a root -l /bin/bash tty`.
    *   Automatischer Login als `root` und Erlangung einer Root-Shell. Root-Flag in `/root/rootflag.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Steganographie (saint.jpg):** Verstecken von Credentials in einer Bilddatei mit einer schwachen (leeren) Passphrase.
*   **SSH Brute Force:** Erfolgreicher Angriff auf SSH mit einem gefundenen Passwort und einer Namensliste.
*   **rbash Bypass:** Umgehung der eingeschränkten Shell durch Anfordern einer anderen Shell beim SSH-Login.
*   **Unsichere Nginx/PHP-Konfiguration:** PHP-Ausführung auf einem VHost und Schreibrechte im Webroot für einen unprivilegierten Benutzer erlaubten das Hochladen und Ausführen einer Webshell.
*   **Unsichere `sudo`-Regeln:**
    *   Ausführung eines Befehls (`/tmp/whoami`) aus einem world-writable Verzeichnis (`/tmp`) als anderer Benutzer.
    *   Ausführung eines interaktiven Tools (`hping3`) mit Shell-Escape-Möglichkeit als anderer Benutzer.
*   **Fehlerhafte SUID/SGID-Berechtigungen (agetty):** Das Setzen des SUID-Root-Bits und SGID-Benutzer-Bits auf `/usr/sbin/agetty` ermöglichte eine direkte Privilegieneskalation zu Root.
*   **World-Writable Directories (`/tmp`):** Ausnutzung der Schreibrechte in `/tmp` zum Platzieren eines bösartigen Skripts für die `sudo`-Eskalation.

## Flags

*   **User Flag (`/home/gabriel/user.txt`):** `HMViwazhere`
*   **Root Flag (`/root/rootflag.txt`):** `HMVohmygod`

## Tags

`HackMyVM`, `Soul`, `Hard`, `Steganography`, `SSH Brute Force`, `rbash Bypass`, `Nginx`, `PHP`, `Sudo Exploitation`, `SUID Exploitation`, `agetty`, `hping3`, `Linux`, `Web`, `Privilege Escalation`

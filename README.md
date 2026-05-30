# Net Manager Alfa

**Net Manager Alfa** è un'applicazione centralizzata per l'automazione, il backup delle configurazioni e il Vulnerability Check dei dispositivi di rete. Il sistema recupera automaticamente le versioni dei firmware in esecuzione e le confronta con il database europeo delle minacce e vulnerabilità ENISA EUVD, fornendo una console di gestione unificata tramite un'interfaccia grafica Web (Web UI).

---

## Caratteristiche Principali
* 🔄 **Backup Automatico**: Esegue il salvataggio automatico della configurazione running degli switch Cisco e HPE in file di testo locali.
* 🛡️ **Triage Firmware & Vulnerabilità**: Rileva la versione corrente del firmware e la interfaccia con il proxy del database europeo ENISA EUVD.
* 🖥️ **Web UI Triage & Form**: Interfaccia grafica completa per l'inserimento rapido di nuovi apparati e la consultazione dello stato di rete.
* ⌨️ **Terminale CLI Rapido**: Console interattiva per l'invio diretto e in tempo reale di comandi CLI arbitrari ad apparati selezionati.
* 🔒 **Sicurezza per il Cloud**: Le credenziali dei dispositivi e i file di configurazione scaricati sono esclusi dal tracciamento Git tramite regole dedicate.

---

## Struttura del Progetto
* `app_server.py`: L'entrypoint web principale dell'applicazione. Gestisce le rotte HTTP statiche, le API di backend e il proxy CORS trasparente verso l'ENISA.
* `core_engine.py`: Il motore di automazione. Gestisce le connessioni SSH via Netmiko con switch Cisco e HPE.
* `inventory_manager.py`: Modulo per la persistenza ed elaborazione dei dati locali (inventario CSV e database JSON temporaneo).
* `templates/dashboard.html`: L'interfaccia utente Web in stile premium con pannelli di controllo e console in tempo reale.
* `requirements.txt`: Elenco delle dipendenze del progetto.
* `.gitignore`: Configurazione delle esclusioni per non committare dati sensibili.

---

## Requisiti e Installazione

Il progetto utilizza **`netmiko`** per le sessioni SSH, **`ping3`** per la raggiungibilità e **`requests`** per le chiamate HTTP.

### Configurazione Rapida con `uv` (Consigliato)
Se utilizzi `uv` per la gestione di Python:

1. **Crea l'ambiente virtuale:**
   ```bash
   uv venv
   ```

2. **Installa le dipendenze:**
   ```bash
   uv pip install -r requirements.txt
   ```

### Configurazione con standard `pip`
Se preferisci utilizzare il gestore pacchetti standard:
```bash
pip install -r requirements.txt
```

---

## Come Avviare l'Applicazione

Esegui il server web principale tramite il comando:

* Se utilizzi **`uv`**:
  ```bash
  uv run app_server.py
  ```
* Se utilizzi **`python`** standard:
  ```bash
  python app_server.py
  ```

L'applicazione aprirà automaticamente il tuo browser predefinito all'indirizzo **`http://localhost:8765/`**.

---

## Sicurezza delle Credenziali
Il file `network_hosts.csv` contiene le credenziali degli apparati fisici di rete ed è configurato all'interno di `.gitignore` per **non essere mai committato** su GitHub.
Prima di pubblicare il repository online, assicurati che la cartella `backup-config/` e i file `network_hosts.csv` e `detected_versions.json` siano esclusi.

# ORCH-IDS
___
This is the repository of my final paper for B.Sc. in Computer Science which consists in an simple yet powerful Intrusion Detection System, in the following lines I will explain its architecture and how to deploy it.

## Architecture
The system is centered around it's database which in this case is a mongoDB, every part of the system communicates with the database.

### Services
Basically we have 3 services:
- ### Agent
  It is the data collector, you can deploy it wherever you want and how many you want (be aware that running more than one instance on the same network will lead to duplicate packets), it is important that you set your network interface to promiscuous mode if you want to analyze every network packet that travels in the same network or else you will only analyze yours which is not a problem if that is what you desire.  
  All data captured will be sent to the database

- ### App
  It is the web interface that retrieves and insert information on the database. Here is where you can:

    - Access the **Home** page which has brief information about all the pages

    - Access the **Rules** page, where you can:
        - See all rules
        - Add new rules
        - Delete rules

    - Access the **Blacklist** page, where you can:
        - See every IP blacklisted and the reason for it
        - Blacklist new IPs
        - Remove any IP from the blacklist

    - Access the **Alerts** page, where you can:
        - See every Alert ordered by most recent and severity
        - Delete alerts

    - Access the **Configurations** page, this is more like a test page, where you can:
        - Set up the database
        - Purge values from any collection
        - Populate any collection with dummy data

- ### Enforcer
  It is the rule enforcer, it will analyze every entry in the packets collection with the rules set in the rules collection and will alert for blacklisted IPs as well

### Database Schema
There are 4 collections: `rules`, `blacklist`, `alerts`, `packets`, the schema is as follows:

Rules:
```yml
name: string NOT NULL UNIQUE,
description: string NOT NULL,
severity: number NOT NULL,
direction: boolean NOT NULL,
source_ip: string,
destination_ip: string,
ip_version: number,
max_length: number,
min_length: number,
protocol: string,
source_port: number
destination_port: number,
count: number,
interval: number,
track': string,
flags: string
```

Blacklist:
```yml
ip: string NOT NULL UNIQUE,
ip_version: number NOT NULL,
reason: string NOT NULL
```

Alerts:
```yml
name: string NOT NULL,
severity: number NOT NULL,
timestamp: number NOT NULL,
protocol: string NOT NULL,
source_ip: string NOT NULL,
destination_ip: string NOT NULL,
length: number,
source_port: number,
destination_port: number
```

Packets:
```yml
timestamp: number NOT NULL,
source_ip: string NOT NULL,
destination_ip': string NOT NULL,
ip_version': number NOT NULL,
length': number NOT NULL,
protocol': string  NOT NULL,
source_port': number,
destination_port': number,
flags: string,
captured_by': string NOT NULL
```

___

## Setting up
For easy set up I will list everything in the needed order

1. ### Database (Mongo)
   You can easily create your own Mongo instance locally with docker:
    ```sh
       docker run -dp 27017:27017 -v local-mongo:/data/db --name local-mongo --restart=always mongo:latest  
    ```
   This block is what I used and will create a Mongo instance locally, I will explain every parameter:

    - ``-dp 27017:27017``: Create a detached container and expose the port `27017`
    - ``-v local-mongo:/data/db``: Mount a volume to persist data (it will create if it does not exist)
    - ``--name local-mongo``: It will name the container as `local-mongo`
    - ``--restart-always``: This will make my container always start when the host machine is up
    - ``mongo:latest``: The container image, it will search locally first then dockerhub

   If you want more information regarding this, I suggest that you refer to [Docker docs run](https://docs.docker.com/engine/reference/run/)

2. ### App
   First of all, you need to have `python3`, `pip` and`venv` installed, if you use a Debian-based Operational System you will execute this:
    ```sh
      sudo apt install python3 python3-pip python3.8-venv
    ```
   Inside the app folder you can create a python virtual environment if you want more isolation, to create and activate:
    ```sh
      python -m venv .
      source bin/activate
    ```
   Install all the necessary libs:
    ```sh
      pip install -r requirements.txt
    ```
   Copy `.env.example` to `.env` and configure it, you can copy the  with:
    ```sh 
      cp .env.example .env
    ```
   Now just make sure the values are correct and after that it is time to launch the app:
    ```sh
      python3 app.py 
    ```

3. ### Agent
   First of all, you need to have `pcap`, `python3`, `pip` and`venv` installed, if you use a Debian-based Operational System you will execute this:
    ```sh
      sudo apt install python3 python3-pip python3.8-venv libpcap-dev
    ```
   Inside the agent folder you can create a python virtual environment if you want more isolation, to create and activate:
    ```sh
      python -m venv .
      source bin/activate
    ```
   Install all the necessary libs:
    ```sh
      pip install -r requirements.txt
    ```
   Copy `.env.example` to `.env` and configure it, you can copy the  with:
    ```sh 
      cp .env.example .env
    ```
   **IMPORTANT**: You should set your network interface to promiscuous mode if you want to capture all the network packets not just the ones addressed to you, to do that:
    ```sh
      #change [interface] with the same value as NETWORK_INTERFACE inserted in .env file
      ip link set [interface] promisc on 
    ```
   Now just make sure the values are correct and after that it is time to launch the agent with `sudo`:
    ```sh
      sudo python3 agent.py 
    ```
   PS: You can run as many agents as you want on the network, just watch out to not overlap any agent coverage, or you will have duplicate packets recorded and that will surely mess your alerts

4. ### Enforcer
   First of all, you need to have `python3`, `pip` and`venv` installed, if you use a Debian-based Operational System you will execute this:
    ```sh
      sudo apt install python3 python3-pip python3.8-venv
    ```
   Inside the enforcer folder you can create a python virtual environment if you want more isolation, to create and activate:
    ```sh
      python -m venv .
      source bin/activate
    ```
   Install all the necessary libs:
    ```sh
      pip install -r requirements.txt
    ```
   Copy `.env.example` to `.env` and configure it, you can copy the  with:
    ```sh 
      cp .env.example .env
    ```
   Now just make sure the values are correct and after that it is time to launch the app:
    ```sh
      python3 enforcer.py 
    ```
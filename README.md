# Detecting Network Intrusion with Suricata and Wazuh

### 1. Description

This home lab project focuses on implementing Network Intrusion Detection using Suricata and Wazuh. Suricata is an open-source and high performance Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) with capable of network analysis and threat detection software, and Wazuh is an open-source security monitoring solution. suricata will be installed on an Ubuntu 24.04 server to monitor its traffic. It is crucial to monitor the network to detect some anomalies on the traffic, as it can be an indication of an attack. We will use one kali machine to emulate some attacks (nmap and ping) and check if Suricata will be able to detect them with the Suricata network traffic inspection capabilities.


### 2. Objectives

- Set up a Wazuh server to collect and analyze security data.
- Set up and configure Suricata to capture network activity and Wazuh agent to send logs to Wazuh manager.


### 3. Tools and Technologies Used

- **VirtualBox**: Used for creating virtual machines for the lab environment.
- **Wazuh**: SIEM tool for log management and security monitoring;
- **Ubuntu Server 24.04 LTS**: Where we will install Suricata and Wazuh agent.
- **Kali Linux**: Used as an attacker system;


### 4. Lab Setup
   - **Network Diagram**:
   
The diagram below illustrates how the components will be interconnected all together, along with their description and IP addresses details.

<p align="center">
<img width="300" alt="Network Diagram" src="https://github.com/user-attachments/assets/51d355b5-144f-4478-b466-f8704964ecec">
</p>


   - **Components**:
     - **Wazuh Manager**: Centralized management console.
     - **Suricata and Wazuh agent**: Installed on target systems to capture network activity and collect logs, respectively.

### 5. Installation Steps
   - **5.1. Setting up VirtualBox**

For setting up VirtualBox, refer to <a href="https://github.com/Muhate/Setting-Up-VirtualBox">this guide</a>
<br>
<br>
   
   - **5.2: Setting up Kali Linux on VirtualBox**

For setting up Kali Linux on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Windows-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.3: Setting up Ubuntu Server 24.04.LTS on VirtualBox**

For setting up Ubuntu Server on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Ubuntu-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.4: Setting up Wazuh Manager on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Wazuh Manager and all other components:
       ```bash
       curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
       ```

   - **5.5: Setting up Suricata on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Suricata - It's important to use the OISF Personal Package Archives (PPA) because OISF maintains a PPA **suricata-stable** that always contains the latest stable release of Suricata:
       ```bash
       sudo apt install software-properties-common
       sudo add-apt-repository ppa:oisf/suricata-stable
       sudo apt update && sudo apt upgrade -y
       sudo apt install suricata jq -y
       ```

     - Enable and start Suricata:
       ```bash
       sudo systemctl enable suricata.service
       sudo systemctl start suricata.service
       ```

     - Create **rules** directory, download the Suricata rules to that directory and extract them:
       ```bash
       cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
       sudo tar -xvzf emerging.rules.tar.gz && sudo mkdir /etc/suricata/rules && sudo mv rules/*.rules /etc/suricata/rules/
       sudo chmod 640 /etc/suricata/rules/*.rules
       ```

     - Edit the Suricata settings in the **/etc/suricata/suricata.yaml** file and set the following variables accordingly:
       ```bash
       HOME_NET: "<YOUR_MACHINE_IP>"
       EXTERNAL_NET: "any"

       default-rule-path: /etc/suricata/rules
       rule-files:
       - "*.rules"

       # Global stats configuration
       stats:
       enabled: yes

       # Linux high speed capture support
       af-packet:
       - interface: enp0s3
       ```

     - Restart and check the status of Suricata service:
       ```bash
       sudo systemctl restart suricata.service
       sudo systemctl status suricata.service
       ```

   - **5.6: Add the following code inside the file */var/ossec/etc/ossec.conf* on Wazuh agent**

       ```bash
       <ossec_config>
         <localfile>
           <log_format>json</log_format>
           <location>/var/log/suricata/eve.json</location>
         </localfile>
       </ossec_config>
       ```

- Restart Wazuh agent

       ```bash
       sudo systemctl restart wazuh-agent
       ```

To check whether our configuration are working or no, we open one machine with NMAP installed and run the command below, then we check if that scan will be triggered.


       ```bash
       nmap -A 192.168.10.4
       ```

As can be seen on the image below, the scan was triggered

<p align="center">
<img width="812" alt="Scan triggered" src="https://github.com/user-attachments/assets/b045789e-441b-4f99-906f-b757d2f6c5a4">
</p>


### 6. **Conclusion**
   - This project successfully demonstrated:
<p>
-- The deployment of wazuh server, along with manager, indexer and dashboard, on Ubuntu 24.04 Server;
</p>
<p>
-- The deployment of wazuh agent on Ubuntu 24.04 Server and Windows Server 2022;
</p>
<p>
-- The File Integrity Monitoring on both Windows and Ubuntu.
</p>


### 7. **Contact Information**
   - **Name**: Rogério Muhate
   - **Email**: rbmuhate@gmail.com
   - **LinkedIn**: [LinkedIn Profile](https://www.linkedin.com/in/rmuhate)

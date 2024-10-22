# Detecting Network Intrusion with Suricata and Wazuh

### 1. Description

This home lab project focuses on implementing Network Intrusion Detection using Suricata and Wazuh. Suricata is an open-source and high performance Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) with capable of network analysis and threat detection software, and Wazuh is an open-source security monitoring solution. suricata will be installed on an Ubuntu 24.04 server to monitor its traffic. It is crucial to monitor the network to detect some anomalies on the traffic, as it can be an indication of an attack. We will use one kali machine to emulate some attacks (nmap and ping) and check if Suricata will be able to detect them with the Suricata network traffic inspection capabilities.


### 2. Objectives

- Set up a Wazuh server to collect and analyze security data.
- Set up and configure agents on target systems (Windows and Ubuntu) to monitor specific files and directories for changes.
- Implement alerting mechanisms to notify administrators of any detected file changes.
- Generate reports to track changes over time and assess compliance with security policies.


### 3. Tools and Technologies Used

- **VirtualBox**: Used for creating virtual machines for the lab environment.
- **Wazuh**: SIEM tool for log management and security monitoring;
- **Windows Server 2022**: Used as a monitored system;
- **Ubuntu Server 24.04 LTS**: Used as a monitored system.


### 4. Lab Setup
   - **Network Diagram**:
   
The diagram below illustrates how the components will be interconnected all together, along with their description and IP addresses details.

<p align="center">
<img width="300" alt="Network Diagram" src="https://github.com/user-attachments/assets/d4e4da42-b979-432c-a39f-8d0aa15bf3a8">
</p>

   - **Components**:
     - **Wazuh Manager**: Centralized management console.
     - **Agent Nodes**: Installed on target systems (Windows and Ubuntu Servers) to collect logs.

### 5. Installation Steps
   - **5.1. Setting Up VirtualBox**

For setting up VirtualBox, refer to <a href="https://github.com/Muhate/Setting-Up-VirtualBox">this guide</a>
<br>
<br>
   
   - **5.2: Setting Up Windows 2022 on VirtualBox**

For setting up Windows 2022 on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Windows-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.3: Setting Up Ubuntu Server 24.04.LTS on VirtualBox**

For setting up Ubuntu Server on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Ubuntu-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.4: Setting Up Wazuh Manager on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Wazuh Manager and all other components:
       ```bash
       curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
       ```
       
   - **5.5: File Integrity Monitoring on Windows Server 2022**
     
     - After logging into the wazuh dashboard, deploy the agent following the steps indicated in the image below and then hit the button **Deploy new agent**:

<p align="center">
<img width="643" alt="Agent deployment" src="https://github.com/user-attachments/assets/075b542a-1a3e-400e-95ce-61b0e59aed0f">
</p>

After clicking the **Deploy new agent** button, choose the operating system and fill all the details asked in the following screen as shown in the images below:

<p align="center">
<img width="643" alt="details filled" src="https://github.com/user-attachments/assets/25feca57-5086-4d69-93db-4a9a0d366562">
</p>

After running all the given commands on your windows machine, click the **Close** button and check for the connectivity between the manager and the agent, the screen should look like the image below.

<p align="center">
<img width="643" alt="Agent showing in the manager" src="https://github.com/user-attachments/assets/f0bde5d7-4bd3-45d4-b328-493762fbce9b">
</p>

If not showing as **active** wait for some minutes and refresh the page.

   - **5.6: Configure the agent to monitor the files or folders you intend to moniotr**
Now that we already deployed the agent, let configure it. The configurations will be made on the file **ossec.conf** located at **C:\Program Files (x86)\ossec-agent**. Before we change any configuration on it, it is a best practice to make a backup of the file, so copy and rename the file so that anything going wrong we can be able to revert to our functional version. For this demonstration we will be monitoring the folder **C:\Users\Public**, but you are free to choose another directory. So locate the section with **File integrity monitoring** and add the content below inside of that:

       ```bash
       <directories check_all="yes" whodata="yes" report_changes="yes">C:\Users\Public</directories>
       ```

After editing the configuration file, save it and restart the agent. Go to **seacrh bar**, type **services** and hit **ENTER**. Locate the service called **wazuh**, right click on it and choose **restart**, or on powerShell run the below commands:

```
       NET STOP WazuhSvc
       NET START WazuhSvc
```


After that, check if is there any event on the manager, following the steps shown in the image below, then go to **Events**.

<p align="center">
<img width="643" alt="Check events" src="https://github.com/user-attachments/assets/ef71fc09-fa99-4f2e-a1b7-8472940853da">
</p>

If you followed everything from the beginning, you will notice that there is no event triggered, that because we didn't make any modification yet. Let us create a file inside the folder **C:\Users\Public** and check if we will have any event.
Inside, we created one folder and one file, called **Test Folder** and **Test file**, as shown below. Go and see again the **Events** under **File Integrity Monitoring**.

<p align="center">
<img width="421" alt="File and Folder created" src="https://github.com/user-attachments/assets/f254378e-caea-4189-80fa-17047581cc8b">
</p>


Now you can see the changes, see how we can see the file created.

<p align="center">
<img width="643" alt="File created" src="https://github.com/user-attachments/assets/c29dae44-92a4-4d37-affe-4150fc112139">
</p>

Down below we can see the details given by the **whodata** feature enabled. 1 - We can see the user, 2 - we see the operation made by the user and 3 - we see the file created.

<p align="center">
<img width="457" alt="Details about whodata" src="https://github.com/user-attachments/assets/1f926183-a0f7-4547-995c-f527015ae70d">
</p>

Let now make some changes on the file and see if the wazuh will trigger them.
So, open the file and type any text, in this case the example will be ***This is an example of adding some text on the file***


<p align="center">
<img width="457" alt="File modification example" src="https://github.com/user-attachments/assets/83adc4c0-ec55-47e2-b3eb-78ce4d7c2746">
</p>

As can be seen in the image above, we can see even when the file is edited. We still see number 1 - the user, number 2 - the content added, number 3 - the operation, number 4 - the amount of characters after the modification and number 5 - the amount of characters before the modification.



   - **5.6: File Integrity Monitoring on Ubuntu 24.04 Server**

To deploy the agent on Ubuntu, we follow the same steps as for Windows, we just change the Operating System we choose and run the commands that will be shown.
On the wazuh manager server, we change the file **ossec.conf** at the directory **/var/ossec/etc** and we change the below values from **no** to **yes**

<p align="center">
<img width="200" alt="logall change" src="https://github.com/user-attachments/assets/d3346007-c641-4e39-8cb7-f44b90c7bbaf">
</p>

If we want to monitor the changes and know the user that made them, we need to install the audit daemon on the monitored system, if not installed yet. For that, we use the commands below on the machine being monitored:

```
       apt install auditd audispd-plugins -y
       systemctl restart auditd
```

After all, we edit the file **ossec.conf** located at **/var/ossec/etc** directory and in the section **File Integrity Moniotring** we add the line below:

```
       <directories check_all="yes" whodata="yes" report_changes="yes">/home</directories>
```

After the configuration made, we can now go to our machine and add some file so that we can see the manager trigger this addition, run the following commands:

```
cd /home
touch test.txt
```
Then go to the manager and check the file created

<p align="center">
<img width="852" alt="File added" src="https://github.com/user-attachments/assets/8f0ee502-807d-4307-be60-5178a1337e85">
</p>

Now, modify the file, or add some text on it. Go back to the manager and you will see the action, see the image below.

<p align="center">
<img width="853" alt="File added" src="https://github.com/user-attachments/assets/807ff532-3f78-47c7-8dfe-b0f2a6a72d23">
</p>

Expanding the trigger, you can see the text added. Number 1 - The user who made the change, number 2 - the directory on which the change was made, number 3 - the text added and number 4 - the operation.

<p align="center">
<img width="410" alt="File added" src="https://github.com/user-attachments/assets/b8c1c2ad-f602-4d30-aee7-95f2601a8741">
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

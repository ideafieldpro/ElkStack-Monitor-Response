# ELK Stack, Security Monitoring, and Incident Response

A comprehensive hands-on training project focused on developing practical Security Operations Center (SOC) analyst skills through real-world scenarios and industry-standard tools.

## Project Overview

This project demonstrates practical experience with essential SOC analyst tools and methodologies, including:

- Deploying and managing cloud-based security infrastructure on leading platforms
- Setting up and managing the ELK (Elasticsearch, Logstash, Kibana) Stack for log aggregation and analysis
- Implementing security monitoring for brute force attack detection
- Understanding Command and Control (C2) infrastructure and attack patterns using Mythic
- Working with enterprise ticketing systems for incident management

## Technical Environment

- Cloud Infrastructure: Vultr-based virtual machines and networking
- Security Tools: ELK Stack, Fleet Server, OSTicket, Mythic
- Operating Systems: Windows Server 2022, Ubuntu Linux
- Monitoring: Custom dashboards and alert configurations

## Key Achievements

- Designed and implemented a complete SOC monitoring infrastructure
- Created logical network diagrams for security infrastructure visualization
- Developed automated alert systems for threat detection
- Established incident response workflows using industry-standard ticketing systems

This project showcases my ability to set up, configure, and maintain essential SOC analyst tools while implementing security monitoring best practices in a simulated environment.

---

# Steps

## 1. Using Draw.io for Diagram Creation

**Getting Started**:
- Visit [draw.io](https://draw.io/) to create visual diagrams easily.
- Rename the default diagram from "Untitled Diagram" to something more descriptive and memorable.

### Building the Infrastructure

- **Creating Servers**:
    - Search for "server" icons and create six servers using the Vulture cloud provider.
    - Types of servers included:
        - Elastic and Kibana servers
        - Windows server (RDP enabled)
        - Ubuntu server (SSH enabled)
        - Fleet server
        - OS Ticket server
        - Command and Control (C2) server
- **Diagram Structure**:
    - Use rounded rectangles to represent cloud providers and label them appropriately (e.g., Vulture).
    - Color coding is used for visual clarity (e.g., red for the C2 server).
- **Linking Servers**:
    - Connect servers using arrows to show communication paths.
    - Use directional arrows to indicate data flow between servers.
- **Private Network Setup**:
    - Specify a private network range (e.g., 172.31.0.0/24) for virtual machines within the VPC.
- **Adding Internet Gateway**:
    - Include an internet gateway and connect it to the VPC and external internet.
- **SOC Analyst Laptop**:
    - Introduce a "SOC Analyst Laptop" and an "Attacker Laptop" that represent different roles in the environment.
    - Connect these laptops to the internet and relevant servers.

### Finalizing the Diagram

- Save your work in Draw.io to keep a record of the diagram.
  ![Test Environment update2 drawio](https://github.com/user-attachments/assets/9f4bed59-7e69-4ccc-ad5e-d72cda9de7ed)

---

## 2. Elastic Setup

### **Creating a Virtual Private Cloud (VPC)**
- **Platform:** Vultr.com
- **Sign Up:** Users can sign up and utilize a $300 credit if they are following these steps.
- **VPC Setup:**
    - Navigate to the "Products" section.
    - Click on "Network" and select "VPC 2.0".
    - Create a new VPC ensuring that the location matches the virtual machines to be created (e.g., Osaka).
    - Configure the IP range (e.g., `172.31.0.0/24`) and name it "ideafieldpro analyst".

### **Deploying a Virtual Machine**
- **Deployment:**
    - Click "Deploy" and select a new server.
    - Use Ubuntu with specified resources (e.g., 4 virtual CPUs, 16 GB RAM).
    - Disable auto backups and IPv6.
      ![brave_P2TmUPxxgv](https://github.com/user-attachments/assets/d512a003-699d-4a80-a457-5fdaf76dc30e)
    - Ensure that the virtual machine is in the correct VPC.
      ![brave_Evy4ZGcMot](https://github.com/user-attachments/assets/7a5b1498-0138-4e17-85f6-8e75d2191342)

### **SSH Access to the Virtual Machine**

- Use PowerShell to SSH into the VM using the provided username and public IP address.
  ![WindowsTerminal_NA8i3xTdp5](https://github.com/user-attachments/assets/cd70bf79-252f-428c-b60c-a8cc53a9f532)
  
- Update system repositories with:
    ```bash
    apt-get update
    apt-get upgrade
    
    ```
    
### **Installing Elasticsearch**

- **Download Installation:**
    - Find the appropriate Elasticsearch package and download it using `wget`.
- **Installation Command:**
    
    ```bash
    dpkg -i elasticsearch*.deb
    
    ```
    
- **Security Configuration:**
    - Save the security auto-configuration information containing the built-in superuser's password.
    - **This step is very important!**

### **Configuring Elasticsearch**

- Edit the configuration file located at `/etc/elasticsearch/elasticsearch.yml`:
    - Change `network.host` to allow access from the SOC analyst laptop.
- Ensure to set HTTP ports correctly for access.

### **Starting Elasticsearch Service**

- Start and enable the service using:
    
    ```bash
    systemctl daemon-reload
    systemctl enable elasticsearch.service
    systemctl start elasticsearch.service
    
    ```
    
- Check the status to confirm it is running with:
    
    ```bash
    systemctl status elasticsearch.service
    
    ```

---

## 3. Kibana Setup

### Installation Steps

- **Download Kibana**:
    - Go to [elastic.co](https://www.elastic.co/downloads).
    - Select the appropriate version for your system (e.g., Debian x86_64).
    - Copy the download link and use an SSH session to download Kibana with the command:
        
        ```bash
        wget <KIBANA_DOWNLOAD_LINK>
        
        ```
        
- **Install Kibana**:
    - After downloading, use the following command to install Kibana:
        
        ```bash
        dpkg -i <KIBANA_PACKAGE>
        
        ```
      ![WindowsTerminal_O61V8GFKKm](https://github.com/user-attachments/assets/e64089d3-63c0-4414-92d9-0f7fc4f3962d)

        
- **Configuration Changes**:
    - Open the configuration file located at `/etc/kibana/kibana.yml` using:
        
        ```bash
        nano /etc/kibana/kibana.yml
        
        ```
        
    - Make necessary changes for `server.port` and `server.host`:
        - Remove the `#` for `server.host` and set it to your public IP address.
    - Save and exit the editor.
      ![WindowsTerminal_ko01MKj5CX](https://github.com/user-attachments/assets/731d352c-7578-4395-8e31-beab58d38e09)

- **Start Kibana Service**:
    - Reload the system daemon and start Kibana using:
        
        ```bash
        systemctl daemon-reload
        systemctl enable kibana
        systemctl start kibana
        
        ```
        
- **Check Kibana Status**:
    - Verify that Kibana is running with:
        
        ```bash
        systemctl status kibana
        
        ```
      ![WindowsTerminal_35jNWn8M5p](https://github.com/user-attachments/assets/b5953a68-f8ae-41ab-bcd2-0193ba4cd8ad)

### Generate Elasticsearch Enrollment Token

- Navigate to the binaries directory for Elasticsearch and generate an enrollment token:
    
    ```bash
    cd /usr/share/elasticsearch/bin
    ./elasticsearch-create-enrollment-token --scope kibana
    
    ```
    
- Copy the generated token for later use.

### Firewall Configuration

- **Adjust Firewall Rules**:
    - Ensure that the firewall allows access to port 5601 (Kibana's default port).
    - Use the following command to allow incoming connections:
        
        ```bash
        ufw allow 5601
        
        ```
        ![WindowsTerminal_NGjMrhO3Xh](https://github.com/user-attachments/assets/31f3bbd1-89c1-4979-93b8-8a5d0c787f87)
        
        
- **Vultr Firewall Settings**:
    - In your Vultr instance, configure firewall rules to allow TCP traffic on ports 1-65535 for your public IP address.
      ![brave_gPZx8QGMhc](https://github.com/user-attachments/assets/8717be63-7ef9-4932-a513-1282982d3c66)


### Verification and Key Management

- Access Kibana through a web browser using your public IP and port 5601.
- Use the enrollment token to configure Elasticsearch.

### Adding Encryption Keys

- Generate and add encryption keys in Kibana for saved objects and security settings.
  ![WindowsTerminal_SiLNCDmJTk](https://github.com/user-attachments/assets/8f8b7e58-c188-4913-924e-d3445fbf79d4)
  
  ![WindowsTerminal_arqwJ3bX9w](https://github.com/user-attachments/assets/d4889a20-61cb-4276-9888-eca32a50a708)

- Restart Kibana after adding these keys:
    
    ```bash
    systemctl restart kibana
    
    ```

---

## 4. Windows Server 2022 Installation

### Steps to Deploy Windows Server

- **Accessing the Cloud Provider**:
    - Navigate to the Vultr platform.
    - Log in to your account.
  
- **Deploying a New Server**:
    - Select "Deploy" and then "Deploy New Server."
    - Choose "Cloud Compute" with shared CPU, as a high-performance server isn't necessary for this task.
    - Set the server location to "Osaka" (the same region as before) and select the latest Windows Server 2022 image.
    - Opt for the $24/month plan, which has 1 vCPU and 2 GB of memory to save money/credits.

- **Network Configuration**:
    - It is important to keep the Windows Server isolated from the broader network to prevent unauthorized access.
    - Instead of using a Virtual Private Cloud (VPC), the server will be set up without it to allow public access.

- **Server Naming Convention**:
    - Follow a specific naming convention for the server.
    - For instance, if your username is ideafieldpro, name your server `socanalyst-win2022-ideafieldpro`.

- **Deployment Process**:
    - After naming the server, click "Deploy".
    - Wait for the server status to change to "Running".
    - Access the console to log in by sending a Control-Alt-Delete command and entering the password copied from the dashboard.

- **RDP Connection**:
    - Copy the public IP address and open Remote Desktop.
    - Paste the IP and connect successfully to the Windows Server.

---

## 5. Elastic Agent and Fleet Server Setup 

### Setup Process

- **Creating the Fleet Server**:
    - A new server is deployed in "Osaka" (the same location as before) using Ubuntu 22.04 with 4 GB of RAM.
    - The server is set up without auto-backups and IPv6.
    - The public IP address for the Fleet server is noted.
      ![brave_pxf58YQwKC](https://github.com/user-attachments/assets/4269792a-3425-4075-81c9-b0780603288b)

- **Web GUI Access**:
    - Access the Elastic web GUI at `http://<public_IP>:5601`.
    - Navigate to Fleet management and select "Add Fleet Server."
    - Opt for the "Quick Start" setup.
      ![brave_lEXaSjB85z](https://github.com/user-attachments/assets/ee473e92-6b1b-4dc6-a4ff-b732d25fe0aa)

- **Fleet Server Policy Creation**:
    - Enter the public IP of the virtual machine and ensure it uses `https://` protocol.
      ![brave_NV6EWPGanM](https://github.com/user-attachments/assets/fd05f439-40e9-4bf4-973d-af62c96dfe14)

    - Generate the Fleet server policy and copy the provided token for installation.
      ![brave_8LPjvE04if](https://github.com/user-attachments/assets/0edefe7e-48e8-4bd5-b9fd-2dfe8568af83)

- **SSH into Fleet Server**:
    - Use PowerShell to SSH into the Fleet server using the root account.
    - Update repository lists and install the Elastic Agent by pasting the policy.
      
- **Firewall Configuration**:
    - Adjust firewall rules to allow communication between the Fleet server and Elasticsearch (which listens on port 9200).
    - Use `ufw` to allow incoming connections on necessary ports.'
      
      ![WindowsTerminal_QLHotBrP4B](https://github.com/user-attachments/assets/c9ae1ef1-d3b2-44b3-a2d5-ae2738e2290f)

### Enrollment of Elastic Agent

- The Elastic agent was installed on the Windows server.
- The installation process required administrative privileges, and multiple commands were run in PowerShell.
   ![brave_KW6QUvaiCU](https://github.com/user-attachments/assets/5799bdf8-ab13-4368-b453-413a67c0b9c8)

- A few errors were encountered during enrollment, mainly related to port configurations and firewall settings.
  ![WindowsTerminal_JiCHPLdZ5i](https://github.com/user-attachments/assets/2b52a1eb-cdbf-4f49-8d4b-7063addaa949)
  
  ![brave_Bqd3z83hIX](https://github.com/user-attachments/assets/3ab31b2b-c57c-4de5-8944-97093fe3d3c5)


### Successful Installation

- The agent began collecting logs from the Windows server, including authentication failure events (Event Code 4625).

---

## 6. Sysmon Setup

### Step-by-Step Process

- Preparation
    - The server's public IP address and password is used for remote desktop connection.

- Connecting to the Server
    - Use Remote Desktop Protocol (RDP) to connect to the Windows Server.
    - Enter the administrator credentials to access the server.

- Downloading Sysmon
    - Open a web browser and search for Sysmon.
    - Download Sysmon version 15.15 from Microsoft's website.
    - It's advised to scroll down the page to understand various event IDs for later investigations.

- Extracting Files

- After downloading, extract the Sysmon files from the zip folder.

- Downloading Configuration File
    - Search for Olaf’s Sysmon Configuration file on GitHub.
    - Save the configuration file `sysmonconfig.xml` in the Sysmon directory.

- Using PowerShell
    - Open PowerShell with administrative privileges.
    - Change the directory to where Sysmon is located.
    - Confirm you are in the correct directory by typing `dir`.

- Installing Sysmon
    - Use the command line to install Sysmon:
        
        ```bash
        sysmon64.exe -accepteula -i sysmonconfig.xml
        
        ```
        
    - This command installs Sysmon as a service and begins capturing logs.

- Verifying Installation
    - Open Windows Event Viewer to confirm that Sysmon is running.
    - Navigate through the Event Viewer to check for Sysmon events under "Microsoft" > "Windows" > "Sysmon" > "Operational".
      ![mstsc_Npsf48wRgC](https://github.com/user-attachments/assets/c2a753bb-e8c9-4b16-8e0b-90c6b39f6757)


---

## 7. Elasticsearch Ingest Data 

### Steps to Ingest Logs

- Logging into Elasticsearch
    - Start by logging into your Elasticsearch instance.
    - Select the blue "Add Integrations" button on the homepage.

- Installing Sysmon Integration
    - Search for "Windows Event" and choose the "Custom Windows Event Log" package.
    - This package allows the ingestion of events from the Windows Event log channel.

### Field Mapping

- Look for the field mappings provided in this package, which includes details like `winlog.computer_name`.

- Configuring Sysmon Logs
    - Open Event Viewer on your Windows Server and navigate to `Applications and Services Logs > Microsoft > Windows > Sysmon`.
    - Right-click on "Operational" to view its properties and copy the full channel name for integration.

- Adding Sysmon Integration
    - In Elasticsearch, add the integration with a custom name (e.g., `ideafieldpro-win-Sysmon`) and paste the copied channel name.
    - Save and deploy changes to complete the Sysmon integration.

### Installing Microsoft Defender Integration

- Setting Up Defender Logs
    - Expand the "Windows Defender" logs in Event Viewer and choose "Operational."
    - Filter event IDs to include only those relevant for monitoring (e.g., `1116`, `1117`, and `5004`).

### Important Event IDs

- Event ID `1116`: Indicates actions taken on potentially unwanted software.
- Event ID `1117`: Shows actions taken to protect the system from detected malware.
- Event ID `5004`: Indicates when real-time protection is disabled.

- Adding Microsoft Defender Integration
    - Similar to Sysmon, add a new integration for Microsoft Defender with a custom name (e.g., `ideafieldpro-win-Defender`).
    - Specify the relevant channel names and event IDs to include or exclude as needed.
      ![brave_4Zd8VxlqgZ](https://github.com/user-attachments/assets/d0e6ca7a-b598-4072-a8f0-9c5706ff4c76)

### Testing & Troubleshooting

- Verifying Ingested Logs
    - Use the Discover feature in Elasticsearch to check if any Sysmon or Defender logs are showing up.
    - If no data appears, troubleshooting steps include checking agent status and ensuring firewall rules allow connections to port 9200.

- Firewall Configuration
    - Ensure that your firewall permits incoming connections on port `9200` for Elasticsearch.

- Restart the Elastic Agent service if logs do not appear after configuration.
  ![brave_FeC3yALvl7](https://github.com/user-attachments/assets/4718c220-4ea7-4c2d-b2b7-83ad4a32d08f)

---

## 8. Setting Up the Ubuntu Server & Reviewing Logs

- **Vultr Setup**:
    - Visit [Vultr.com](https://vultr.com/) and sign in.
    - Click on "Deploy" in the top right corner and select "Deploy New Server."
    - Choose a shared CPU plan; the host selects Ubuntu version 24.0.
    - Opt for a basic configuration: 1 CPU and 1 GB memory, without auto backups or IPv6.
    - Name the server appropriately (e.g., `ideafieldpro-linux`).
    
- **Deployment**:
    - Once the server is running, access it via PowerShell using SSH:
        
        ```bash
        ssh root@<IP_ADDRESS>
        ```
        
    - Update the server's repositories:
        
        ```bash
        apt-get update
        apt-get upgrade
        ```

### Reviewing Authentication Logs

- **Location of Logs**:
    - Authentication logs are stored in `/var/log`.
    - The specific log file of interest is `auth.log`.
      
- **Analyzing Logs**:
    - Use the `cat` command to view the `auth.log`:
        
        ```bash
        cat auth.log
        ```
        
    - Initially, there will be minimal activity but expect to see failed authentication attempts after some time.
      
- **Filtering Failed Attempts**:
    - Use `grep` to filter entries containing "failed":
        
        ```bash
        grep -i failed auth.log
        ```
        
    - Further filter for attempts specifically for the 'root' user:
        
        ```bash
        grep -i failed auth.log | grep -i root
        ```
        
- **Extracting IP Addresses**:
    - Utilize the `cut` command to isolate IP addresses from failed login attempts:
        
        ```bash
        grep -i failed auth.log | grep -i root | cut -d' ' -f9
        ```
        
---

## 9. Install Elastic Agent on the Server

### Accessing the Elastic Web GUI

- Navigate to the Elastic web GUI.
- Click on the hamburger icon in the top left corner.
- Scroll down and select **Fleet Management**.

### Creating a New Agent Policy

- Click on **Agent Policy** to create a new policy named such as `ideafieldpro-Linux-policy`.
- Select the **system-3** policy type (note: your version may vary).
- This policy will specify which logs the SSH server will push to the Elasticsearch instance.
  ![brave_ncsS6Kktqp](https://github.com/user-attachments/assets/de4aaeaf-9894-4d79-8e95-6cf6bcd337ad)


### Verifying Log Locations

- The default path for logs is `/var/log/secure`.
- If using Ubuntu, check `/var/log/auth.log` for authentication logs, as it differs from Red Hat/CentOS systems.

### Adding the Agent

- Go back to **View Agent Policies** and click **Add Agent**.
- Choose the `ideafieldpro-Linux-policy` policy created earlier.
- Select **Enroll in Fleet**, specifying Linux as the operating system.

### Installing the Elastic Agent

- Copy and paste the provided command into a PowerShell ssh session to install the Elastic Agent.
- If you encounter an error regarding an X.509 certificate, add the `-insecure` flag to bypass it.

### Confirming Installation

- Verify that the Elastic Agent has been successfully installed and that data is flowing into the Elasticsearch instance.
  ![brave_QFcVq3DlAK](https://github.com/user-attachments/assets/9b1a8da5-41ec-4591-917f-985d48723f49)

- Check by going to **Discover** and filtering by agent name.
  ![brave_WBd9MsW3OP](https://github.com/user-attachments/assets/296d8927-7535-460d-8c9d-7c3934630049)

### Analyzing Logs

- Look for authentication failures by searching with relevant keywords.
  ![brave_J5TJHqYx6j](https://github.com/user-attachments/assets/8f70cdf2-f28b-494b-aeca-a600994494a9)

---

## 10. Creating SSH Brute Froce Alert Dashboards in Kibana

### Querying Logs

- Start by accessing the Elastic Search instance web GUI to query logs.
- Use the `Discover` feature to filter relevant data based on your SSH server.
- Look for **failed authentications**, which indicate attempted unauthorized access.

### Identifying Important Fields

- Key fields to focus on:
    - **Failed attempts**: Count the number of failed logins.
    - **Usernames**: Identify the usernames being targeted.
    - **Source IPs**: Track the IP addresses attempting access.

### Creating Alerts

- Once you've filtered for failed attempts, save your query as `SSH Failed Activity`.
- Navigate to the alerts tab and create a new alert:
    - Set thresholds (e.g., 5 failed attempts within 5 minutes).
    - Adjust the timing (e.g., check every minute).
      ![explorer_Rpy1VY7TMm](https://github.com/user-attachments/assets/16d7f570-8eec-4b48-ade0-8c27d10e1eda)


### Building the Dashboard

- Head to the **Analytics** tab to create a visual representation of your data.
- Use a map layer to pinpoint where attacks are originating from, leveraging geolocation based on source IPs.
- Ensure that your queries correctly reflect the data you're interested in visualizing.
  ![brave_wpNb57fXqs](https://github.com/user-attachments/assets/63a1bca3-9057-479a-abf1-65c47c91274c)

### Successful Authentication Queries

- Duplicate the previous dashboard and adjust it to show successful authentications.
- Modify the query to focus on accepted attempts rather than failed ones.
  ![brave_2eHilzsPch](https://github.com/user-attachments/assets/af4d8dcd-0859-4e18-8838-91947f7377a0)

---

## 11. Reviewing Windows Authentication Logs & Creating Alerts in Kibana

### Review Authentication Logs

- **Accessing Logs**: Navigate to the Elastic web GUI and select the "Discover" option.
- **Filtering Events**: Filter events specifically for an RDP server and look for failed authentication attempts.
- **Identifying Event ID**: The focus is on Event ID `4625`, which indicates failed authentication attempts. Searching for the event ID.

### Analyzing Failed Authentication Attempts

- **Expanding Event Details**: The first failed event is expanded to gather fields such as source IP address and username.
- **Creating a Search Query**: A search query for failed RDP activity is saved, named "RDP Failed Activity". This query helps in monitoring failed logins.
  ![brave_mKj9YtRzth](https://github.com/user-attachments/assets/5fa04581-9a9f-4eff-b6e8-f914f84b80a2)


### Testing Authentication

- **Testing Logins**: Test the login with a specific username and check the logs for successful and failed attempts.
- Remember log types:
    - **Logon Type 3**: Network-based authentication (e.g., RDP).
    - **Logon Type 10**: Remote interactive logon.

### Creating Alerts

- **Set Up Alerts**: Create an alert to detect brute force attacks.
- **Search Threshold Rule**: A search threshold rule is created based on Event ID `4625`, configured to check every minute for multiple failed login attempts.
- **Rule Details**: The rule captures user details and source IP addresses.
  ![brave_nonfMnxbOu](https://github.com/user-attachments/assets/daee37a8-a8af-412b-ae22-e06cbe2d4fe0)

### Enhancing Alert Information

- **Creating Detection Rules**: The host explains the process of creating more informative detection rules that provide detailed information compared to standard alerts.
- **Custom Queries**: Custom queries are introduced to include usernames, allowing analysts to better understand the context of failed authentication attempts.


---


## 12. Creating Dashboards for Windows RDP Activty in Kibana

### Creating the Dashboard

### Step 1: Query Setup

- Navigate to the Elastic web GUI and select the "Maps" feature.
- Use the saved query to analyze authentication attempts related to RDP:
    - **Event Code**: `4625` for failed attempts.
- Make sure to set the time filter so results are displayed.

### Step 2: Data Layer Addition

- Add a layer for geographical context using country data.
- Identify where a significant number of failed authentication events originate from.
  ![brave_jg4Sd3lm7L](https://github.com/user-attachments/assets/e2de841b-a249-47db-9af4-5becdabe043d)

### Step 3: Save and Organize

- Save the dashboard titled "RDP Failed Authentication".
- Duplicate the dashboard to create one for successful RDP authentications using **Event Code**: `4624`.

### Step 4: Successful Authentication Queries

- Focus on logon types, specifically logon type `10` (RDP) and `7`.
- Update the query and save as "RDP Successful Activity".
  ![brave_HEzUP6lWIH](https://github.com/user-attachments/assets/c6f659e0-f117-47e7-a016-01626cc10ad9)

## Visualization Enhancements

- Create visual representations of RDP and SSH activities.
- Add tables showing usernames, source IPs, and country names for both failed and successful authentications.
- Configure charts to display the top ten values for user activity without grouping remaining values.
  ![brave_1fO5vjOIXk](https://github.com/user-attachments/assets/8fe82d97-a9c6-434f-8314-82503d608164)

## Final Adjustments

- Ensure all queries reflect accurate data by editing and updating titles and configurations.
- Save all changes to prevent data loss.

---

## 13. Creating an Attack Diagram

### **Setting Up the Attack Diagram**

- Use **draw.io** to create the attack diagram.
- Main components included:
    - **Mythic C2 Server** (Command and Control server)
    - **Windows Server** (target server)
    - **Attacker's Laptop** (using Kali Linux)

### **Phases of Attack**

The attack is broken down into six distinct phases:

- **Phase One: Initial Access**
    - Perform an **RDP brute force attack** against the Windows Server to gain access.

- **Phase Two: Discovery**
    - After successful access, run discovery commands:
        - `ipconfig`
        - `net user`
        - `net group`

- **Phase Three: Execution**
    - Download and execute the **Mythic agent** on the Windows Server using PowerShell:
        - Utilize `IEX` (Invoke Expression) to download the agent.

- **Phase Four: Defense Evasion**
    - Disable Windows Defender on the Windows Server to avoid detection before execution.

- **Phase Five: Command and Control (C2)**
    - Establish a command and control session with the Mythic C2 server, enabling remote control over the target.

- **Phase Six: Exfiltration**
    - Create a fake password file named `passwords.txt` on the Windows Server and download it through the established C2 session.

### **Final Notes on the Attack Diagram**

- This diagram serves as a conceptual map for understanding the attack pathway and steps involved in successfully compromising a target machine.
  ![Attack Diagrampng](https://github.com/user-attachments/assets/c5106a08-13ee-4afc-88cf-492f492fe0a6)

---

## 14. Mythic Server Setup

### Setting Up Mythic C2

- **Cloud Provider Setup**
    - I continued using Vultr as the cloud provider.
    - Steps include logging in, clicking "Deploy," and selecting options such as:
        - Cloud Compute with shared CPU.
        - Operating system: Ubuntu with 4 GB RAM.
        - No need for auto backups or IPv6.
          
- **Installing Kali Linux**
    - Download Kali Linux from the official website to your personal computer.
    - Select the virtual machine option suitable for the hypervisor being used (e.g., VirtualBox).
    - Extract the downloaded file and ensure that file name extensions are visible to find the file.
      ![VirtualBox_vCGCfWPOWv](https://github.com/user-attachments/assets/bf174210-dfd5-4e9e-90cc-5f5987baaeb4)
      
- **Deploying Mythic C2**
    - Access the Vulture console and log into the server using SSH.
    - Update and upgrade the system repositories:
        
        ```bash
        apt-get update
        apt-get upgrade
        
        ```
        
    - Install required prerequisites, including Docker Compose.
    
- **Cloning and Installing Mythic**
    - Clone the Mythic repository from GitHub:
        
        ```bash
        git clone https://github.com/its-a-feature/SL-Mythic
        ```
        
    - Navigate to the Mythic directory and run the installation script:
        
        ```bash
        cd Mythic
        ./install_core_docker_U
        ```
        
- **Configuring Docker**
    - If Docker is not running, restart it:
        ```bash
        systemctl restart docker
        ```
      ![WindowsTerminal_aA69ad96wR](https://github.com/user-attachments/assets/f8f2bd69-abf0-429b-9279-c4190ff6e595)

        
    - Start the Mythic CLI:
        ```bash
        ./mythic_cli start
        ```
      ![WindowsTerminal_qOKtxaQ6Kp](https://github.com/user-attachments/assets/3775cdbe-bab2-40cf-ac04-90a11eb43b30)

        
### Security Configurations

- Set up firewall rules through the cloud provider to restrict communication to only necessary targets.
- Create a firewall group in Mythic for added security.
  ![brave_YvoL2YIYT6](https://github.com/user-attachments/assets/10d38459-68ea-4771-9c9d-0a224d8b501b)

### Accessing Mythic Web GUI

- Access the Mythic web interface using the public IP address on port 7443;
    - If an HTTP error appears, add HTTPS.
- Default login credentials can be found in the environment variable file.

### Overview of Mythic Features

- **Dashboard**: Displays callbacks and agent status.
- **Payload Management**: Options to generate, import, and manage payloads.
- **Artifact Tracking**: Keeps track of keylogs, screenshots, and other artifacts.
- **MITRE Attack Mapping**: Provides a way to analyze tasks against MITRE framework categories.

---

## 15. Mythic Agent Setup

### Setting Up the Windows Server

- Create a fake file named `passwords.txt` on the Windows server and set a common password (`Winter2024!`).
- Adjust local group policies to change password requirements, allowing simpler passwords for testing.

### Performing Brute Force Attack

- Log into the Kali Linux machine and prepare for the Brute Force attack using tools like `crowbar`.
- Use an existing wordlist (`rockyou.txt`) to attempt to crack the administrator's password on the Windows server.
  ![VirtualBoxVM_IuueO4BQrQ](https://github.com/user-attachments/assets/38cc7c5b-fb9c-4d9e-8074-7c767edc0b66)

### Executing Commands on the Windows Server

- Once logged in via RDP (Remote Desktop Protocol) using xfreerdp and execute discovery commands:
    - `ipconfig`
    - `net user`
    - `net localgroup`
- Disable Windows Defender as part of the defense evasion phase.
  ![VirtualBoxVM_6MMWKBmw4O](https://github.com/user-attachments/assets/9a6f8398-23bd-43e7-815d-4b2766e83b0e)

### Building and Deploying Mythic Agent

- Access Mythic’s web GUI to install the necessary agents (e.g., Apollo).
  ![brave_y0VpUUF8yH](https://github.com/user-attachments/assets/298a151f-cf4b-4422-acbe-6512dc502b47)
  ![WindowsTerminal_aLq2edLQeh](https://github.com/user-attachments/assets/bde7908f-8e1c-40ef-9848-fb217c8d7dd1)
  ![brave_DjtOaDzNy6](https://github.com/user-attachments/assets/0ef41632-d3da-439b-8c15-14ad8a747ae7)
  ![WindowsTerminal_Qnet5yALkn](https://github.com/user-attachments/assets/8dc52151-e275-4aa5-af93-33d2a240c8b9)

- Generate a payload for the Windows machine through Mythic web GUI, specifying the callback host and port.
  ![brave_o8ImnauBdx](https://github.com/user-attachments/assets/e5bcd21d-fae4-410f-a498-23ed425be0ae)

- Download the agent and rename it appropriately for execution on the target.
  ![WindowsTerminal_MQj6OZtylK](https://github.com/user-attachments/assets/0421d45e-dc3e-4661-81d4-e5efaa6cba95)


### Establishing Connection and Exfiltration

- Use Python's HTTP server module to serve the agent file.
- Allow necessary ports in the firewall settings to facilitate communication between the agent and Mythic C2.
  ![WindowsTerminal_FptqwDGIIP](https://github.com/user-attachments/assets/77102f40-6fcf-4839-b166-0a0d303b8d0c)

- Execute the agent to establish a connection with Mythic C2, confirming successful execution through task manager.
    ![VirtualBoxVM_rPhU1wec8H](https://github.com/user-attachments/assets/534a81c5-4890-429e-95d7-64642ad37f95)

### Downloading Password File

- Utilize the established C2 session to issue commands that download the previously created `passwords.txt` file from the Windows server.
  ![brave_JIMhBjIuIt](https://github.com/user-attachments/assets/9234a5c5-f7af-4da7-96e3-22efa44c56e6)

- Verify that the password retrieved matches what was set earlier.
  ![brave_vuMtX9mhdk](https://github.com/user-attachments/assets/95757512-cfcb-4823-acd1-9209348f5137)

---

## 16. Creating Alerts and Dashboards for Mythic C2 Activity in Kibana

- **Accessing Elastic Web GUI**:
    - Navigate to the "Discover" section by clicking the hamburger icon.
    - Set the time frame to capture all relevant events.
- **Identifying Events**:
    - The focus is on identifying events related to `scvhost.exe` and `mythic C2` activity.
      ![brave_aHdGV1WAEj](https://github.com/user-attachments/assets/136315e7-0c9b-4201-8d2a-6c15be666f48)

    - Use event code 1 to look for file creation events and expand to investigate.
      ![brave_DHTrl9y6jr](https://github.com/user-attachments/assets/9a7da2df-962e-47fb-b5f2-7d11e6e019ff)

- **Using Open Source Intelligence**:
    - Specific attention is given to the original file name `Apollo.exe`, which indicates potential malicious activity.
- **Creating Detection Rules**:
    - A basic alert is created to detect any process creation involving `Apollo.exe`.
    - The alert is set to trigger when the process is created, regardless of its success.
      ![brave_SwfiEYoT2d](https://github.com/user-attachments/assets/cce666a4-b95d-4da7-a089-20f1ffbfb45e)

- **Setting Required Fields**:
    - Essential fields such as timestamp, username, command line, and parent command line are included for detailed analysis.

### Dashboard Creation

1. **Building Dashboards**:
    - A dashboard is created to show suspicious activity, including external network connections and process creation events.
    - Queries are constructed for event IDs related to these activities.
2. **Visualization Setup**:
    - Create visualizations for both process creation (event ID 1) and network connections (event ID 3).
    - Multiple panels are added to provide a comprehensive view of ongoing activities.
3. **Finalizing Dashboards**:
    - The dashboard is titled and includes multiple alerts and visualizations.
    - Emphasis is placed on monitoring specific indicators of compromise, including disabled security tools like Microsoft Defender.
      ![brave_CsE54UYHsy](https://github.com/user-attachments/assets/f157d67f-11c4-472c-8958-591f32b3e8b8)

---

## 17. osTicket Setup

### Step 1: Deploying a Server

- **Platform**: I use Vultr to deploy a new Windows server.
- **Configuration**:
    - **Server Type**: Cloud compute with shared CPU.
    - **Location**: Osaka (same as before).
    - **Operating System**: Windows Standard 2022.
    - **Specifications**: 55 GB storage, 1 CPU, and 2 GB memory.
- **Firewall Setup**: A firewall is configured to restrict access to the web server that will host OS Ticket.

### Step 2: Installing XAMPP

- **Download XAMPP**: Download XAMPP (version 8.2.2) from the Apache Friends website.
- **Installation**:
    - Default installation settings are used, and properties are edited to configure Apache and MySQL settings.
- **Firewall Rules**: Inbound rules are created to allow connections on ports 80 and 443.

### Step 3: Configuring PHPMyAdmin

- **Accessing PHPMyAdmin**: Initial connection errors are resolved by adjusting configuration files to allow access through the public IP address.
- **User Accounts**: User credentials for root and PMA accounts are set up.
  ![mstsc_6GnrIpSZYQ](https://github.com/user-attachments/assets/5de54368-d761-4bde-b5f9-8e59a91dbb4b)

### **Installing OS Ticket**

### Step 4: Downloading OS Ticket

- **Download Version**: Download OS Ticket (version 1.18.1) from the official site.
- **File Extraction**: Extracts the files to the `htdocs` directory in XAMPP.

### Step 5: Running the Installer

- **Installation Steps**:
    - Initial configuration prompts require setting up help desk name, username, and database settings.
    - A new database is created within PHPMyAdmin for OS Ticket.

### Step 6: Finalizing Installation

- After addressing some errors regarding email settings, the installation is successfully completed.
  ![mstsc_p04vjGHjct](https://github.com/user-attachments/assets/18cb48ce-8bc2-407d-aee7-1d536b32a559)

---

## 18. osTicket + ELK Integration

### Accessing OS Ticket

- Log into the OS Ticket control panel.
- Navigate to the Admin panel and select `Manage`, then `API`.
- Click `Add New API Key`, entering the private IP address of the OS Ticket server if it's in the same Virtual Private Cloud (VPC), or the public IP if not.
  ![brave_BFYW9HzygC](https://github.com/user-attachments/assets/79f65ca0-0da6-40df-bdf3-15ce6daa77f1)

### Setting Up Elastic Stack

- Open the Elastic interface and go to `Management`.
- Select `Stack Management`, then `Alerts and Insights`.
- Click on `Connectors` and choose to create a new connector.
- Start a free 30-day trial to enable API connections if you're using a free license.
  ![brave_TKgexj3P3s](https://github.com/user-attachments/assets/4bdca4dc-dcae-4100-817f-48819a003b18)

### Creating the Connector

- Use a webhook connector to send alerts from Elastic to OS Ticket.
- Set up the webhook with the OS Ticket's IP address and API key.
  ![brave_xh4t34tYDY](https://github.com/user-attachments/assets/579aaabb-0160-4f5c-b735-dbee10daaa72)

- Configure the body for the webhook request using an XML payload example from OS Ticket’s GitHub page.
  ![brave_q97N7g9waL](https://github.com/user-attachments/assets/3a971277-876b-40c2-bafa-5f0992d60e0d)

  ![brave_iVZzJBERuy](https://github.com/user-attachments/assets/72770257-1066-44f6-823c-c99c26b432a4)

### Troubleshooting Connection Issues

- If encountering a timeout error during testing, check network connections:
    - SSH into the ELK server to verify IP addresses.
    - Make sure that the OS Ticket server is reachable.

### Finalizing Integration

- Adjust the network settings on your OS Ticket server if necessary to ensure it has a private IP.
- Rerun the test for the connector after making any adjustments.
  ![brave_IcOWFX5oDx](https://github.com/user-attachments/assets/c111816c-a044-4caf-82ac-993c2cbcaf14)

---

## 19. Investigate SSH Brute Force Attack

### Steps to Investigate Brute Force Alerts

- **Identifying the Source IP**:
    - The first step is to note the source IP address from the alert, which was reported as `218.92.0.133`.
      ![brave_CcFfVyzi4N](https://github.com/user-attachments/assets/fa00110a-aa2d-43bc-9d2c-ad14ec25b597)

    - Check this IP against known databases to determine its reputation for brute force activity.
      
- **Using External Resources**:
    - **AbuseIPDB**: The IP is found to be reported indicating malicious behavior.
    - **GreyNoise**: A search reveals that the IP is known to use SSH brute-forcing.
      ![brave_HfeyjvUU7b](https://github.com/user-attachments/assets/8cf54698-ee38-4dad-a05f-17b413b26aff)

- **Identifying Affected Users**:
    - Use Kibana to query events related to the identified IP over the last 30 days.
    - One distinct user is affected: root.
      ![brave_Jfs87ubIFM](https://github.com/user-attachments/assets/288bc9b8-7872-4510-a79b-4526c8ea021e)      
      
- **Looking for Successful Logins**:
    - Initial queries for successful logins return no results, suggesting that all login attempts were unsuccessful.
    - Double-check queries and adjust capitalization since it can affect search results.

### Documenting Findings

- Document findings in a ticketing system, adding notes to ensure proper processes are followed.
  ![brave_tY7VdtF99e](https://github.com/user-attachments/assets/8552eacd-b418-4eff-b77a-57da02edc5f1)

- Modifications are made to alert rules to push notifications into a ticketing system (OS Ticket).
  ![brave_4ldqM7Brsq](https://github.com/user-attachments/assets/fe24f114-1001-4bb7-911b-cec000440533)


### Configuring Alerts

- Edit alert settings, including configuring webhook actions and ensuring that alerts contain relevant information such as the source IP and user details.
- It's important to have hyperlinks in notifications for easy access to alert details.

### Closing Tickets

- Finally, it's important to communicate among team members to avoid duplicated efforts.

---

## 20. Investigate RDP Brute Force Attack

### Investigating RDP Brute Force Attacks

- **Accessing Alerts:**
    - Navigate to the alert section of Elastic.
    - Filter alerts to focus specifically on RDP Brute Force alerts from the past 30 days.
      
- **Details of the Alert:**
    - An example alert is examined, revealing the source IP address (189.180.183.69) and the use of the username "Administrator".
      ![brave_d6MO26IqWX](https://github.com/user-attachments/assets/8a55a78f-8718-4e1c-9563-edb1da22c49d)

    - Create a ticket in OS Ticket for the alert.
      
- **Using AbuseIPDB:**
    - Check the flagged IP address on AbuseIPDB, which shows it has been reported for suspicious activity.
      ![brave_3BAJW4kRZg](https://github.com/user-attachments/assets/a1aab87d-5053-4f5f-9602-4a7168058846)
      
- **Gray Noise Analysis:**
    - Analyze the IP using Gray Noise, which identifies scanning activity but cannot determine intent.
      ![brave_J9PxLqscNe](https://github.com/user-attachments/assets/731b5dad-db11-407e-871f-2d65166d2774)

### Addressing Key Questions

- **Is the IP Known for Brute Force Activity?**
    - Yes, confirmed through AbuseIPDB reports.
- **Are There Other Users Affected by This IP?**
    - The analysis shows that only the "Administrator" and account is affected, with no successful logins recorded.
- **Successful Login Attempts:**
    - Look for event code 4624, indicating successful authentications, and found no successful logins from the flagged IP address.
      ![brave_AEX9M8jVVc](https://github.com/user-attachments/assets/e79e8f73-4871-4fde-8e38-df3958a80232)

- **Investigating Another IP:**
    - (see what you find)

---

## 21. Investigate Mythic Agent

### Getting Started with Mythic C2

- **Initial Investigation**: My Mythic C2 agent was called `svchost-ideafieldpro.exe` (the name may vary based on what you configure).
- **Finding Events**: Analysts should use the Discover feature by setting the time frame to 30 days and searching for `svchost-ideafieldpro.exe` to gather relevant events.

### Tips on Identifying C2 Activity

- **Network Telemetry**: C2 sessions often involve significant back-and-forth traffic, indicating potential data transfer.
- **Top Talkers**: Monitoring the top 10 address pairs for high traffic can help identify C2 communications.
- **Heartbeat Monitoring**: A tool called [Rita](https://www.blackhillsinfosec.com/projects/rita/) from Black Hills Security is recommended for detecting potential C2 traffic.

### Process Creation Analysis

- **Sysmon Event ID 3**: Look at inbound network connections to the host initiated by certain processes, particularly focusing on `rundll32.exe`, which is commonly exploited by malware.
  ![brave_19XAkZY2dh](https://github.com/user-attachments/assets/33190175-1ad2-40f0-b795-1e87e84ce875)

- **Suspicious Activity**: Identifying unusual process executions, like those from `Microsoft Edge` or executables in unexpected directories, is crucial.

### Building a Timeline

- **Event Correlation**: Build a timeline of events related to suspicious network connections and process creations.
  ![Notepad_Oevcoeiu3f](https://github.com/user-attachments/assets/cfdd0874-effc-4e25-9e36-e70781b1d82c)

- **Using Process GUIDs**: By following the process GUID, analysts can trace back the actions of PowerShell sessions and other potentially malicious activities.
  ![brave_KHrq04pehB](https://github.com/user-attachments/assets/719920f4-9765-4771-b8ae-a3ca311a7ee0)
  

### Detection Rules Configuration

- **Mythic C2 Apollo Rules**: Edit detection rules for the Mythic payload to ensure alerts are generated for any suspicious activities.
  ![brave_JNdcGatapa](https://github.com/user-attachments/assets/5c7e79d7-56b5-43b7-8440-dede7593caf3)

---

## 22. Elastic Defend Setup

### Key Steps in the Installation Process

- **Downloading and Installing Elastic Defend**:
    - Download and install Elastic Defend on the endpoint to start protecting against malicious activity.
    - Note: Free subscriptions do not allow for remote host isolation.
      ![brave_4fhDyKAAzi](https://github.com/user-attachments/assets/859ba1e5-e6e2-4dbd-bf4a-89a20befe1b5)

      
- **Integration Setup**:
    - Once installed, users should navigate to the top-left corner (the hamburger icon) and scroll to "Integrations."
    - Click on Elastic Defend to add the integration, providing a name and description for the setup.
      
- **Configuration Options**:
    - There are four configuration types:
        - Data Collection
        - Next-Gen Antivirus
        - Essential EDR
        - Complete EDR
    - The presenter selects the "Complete EDR" option for full telemetry and protection.
    - Configurations can be set for traditional endpoints or cloud workloads. I used traditional endpoints.
      ![brave_QUIX7ITUt5](https://github.com/user-attachments/assets/80127cc5-d687-4884-8ec1-74def98c22a4)

      
- **Endpoint Management**:
    - The Windows Server is selected for integration, and changes are saved for deployment.
    - Once deployed, we can view endpoints under the "Security" section.
      ![brave_Te3auHI4rc](https://github.com/user-attachments/assets/76390332-0e0a-42a0-b879-f191b3bfa284)

### Demonstrating EDR Capabilities

- Execute a test by terminating a potentially harmful process (`ideafieldpro-analyst.exe`) to showcase Elastic Defend's alert mechanisms.
  ![brave_9OZBhnq762](https://github.com/user-attachments/assets/c04142c4-cb63-4498-97a3-2fbc3adfd55f)

- An alert is generated indicating that the file contains a virus, demonstrating effective malware prevention.
  ![mstsc_iJChfIeYo9](https://github.com/user-attachments/assets/ab50bcf9-4c27-463b-8ab3-0bd4ad3eefd3)

## Investigating Alerts

- Access telemetry data via Kibana:
    - Search for malware alerts in the "Discover" tab.
      ![brave_WhjaqVXmdB](https://github.com/user-attachments/assets/47cef086-fdd0-4c55-8df9-41c3e689c8d0)

## Incident Response Actions

- Edit rule settings in Elastic Defend:
    - Users can set responses to isolate the host if malicious activity is detected.
      ![brave_WdupH0CjY4](https://github.com/user-attachments/assets/15fdd968-98e0-4f1c-95e7-5b72c4f3c3f1)

    - A command prompt demonstration shows an infinite ping command, illustrating that network activity is limited when a host is isolated.
      ![mstsc_XMFneoa5DB](https://github.com/user-attachments/assets/8ed74483-3bb4-4451-af07-65547ad38c6c)
      
      ![brave_qdeqi0wq64](https://github.com/user-attachments/assets/a3d2ce79-e435-4c69-a703-831b888d5803)


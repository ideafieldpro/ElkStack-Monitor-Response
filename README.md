# ELK Stack, Security Monitoring, and Incident Response Project

A comprehensive hands-on training project focused on developing practical Security Operations Center (SOC) analyst skills through real-world scenarios and industry-standard tools.

## Project Overview

This project demonstrates my practical experience with essential SOC analyst tools and methodologies, including:

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

# Steps

## 1. Using Draw.io for Diagram Creation

- **Getting Started**:
    - Visit [draw.io](https://draw.io/) to create visual diagrams easily.
    - Rename the default diagram from "Untitled Diagram" to "30-Day Defer Diagram".

### Building the Infrastructure

1. **Creating Servers**:
    - Search for "server" icons and create six servers using the Vulture cloud provider.
    - Types of servers included:
        - Elastic and Kibana servers
        - Windows server (RDP enabled)
        - Ubuntu server (SSH enabled)
        - Fleet server
        - OS Ticket server
        - Command and Control (C2) server
2. **Diagram Structure**:
    - Use rounded rectangles to represent cloud providers and label them appropriately (e.g., Vulture).
    - Color coding is used for visual clarity (e.g., red for the C2 server).
3. **Linking Servers**:
    - Connect servers using arrows to show communication paths.
    - Use directional arrows to indicate data flow between servers.
4. **Private Network Setup**:
    - Specify a private network range (e.g., 172.31.0.0/24) for virtual machines within the VPC.
5. **Adding Internet Gateway**:
    - Include an internet gateway and connect it to the VPC and external internet.
6. **SOC Analyst Laptop**:
    - Introduce a "SOC Analyst Laptop" and an "Attacker Laptop" representing different roles in the environment.
    - Connect these laptops to the internet and relevant servers.

## Finalizing the Diagram

- Save your work in Draw.io to keep a record of the diagram.
  ![Test Environment](https://github.com/user-attachments/assets/df783eda-f2e8-42bf-94c8-c0706d77045e)

---

## 2. Elastic Setup

### 1. **Creating a Virtual Private Cloud (VPC)**

- **Platform:** Vultr.com
- **Sign Up:** Users can sign up and utilize a $300 credit if they are following these steps.
- **VPC Setup:**
    - Navigate to the "Products" section.
    - Click on "Network" and select "VPC 2.0".
    - Create a new VPC ensuring that the location matches the virtual machines to be created (e.g., Toronto).
    - Configure the IP range (e.g., `172.31.0.0/24`) and name it "ideafieldpro analyst".

### 2. **Deploying a Virtual Machine**

- **Deployment:**
    - Click "Deploy" and select a new server.
    - Use Ubuntu with specified resources (e.g., 4 virtual CPUs, 16 GB RAM).
    - Disable auto backups and IPv6.
      ![brave_P2TmUPxxgv](https://github.com/user-attachments/assets/d512a003-699d-4a80-a457-5fdaf76dc30e)
    - Ensure that the virtual machine is in the correct VPC.
      ![brave_Evy4ZGcMot](https://github.com/user-attachments/assets/7a5b1498-0138-4e17-85f6-8e75d2191342)

### 3. **SSH Access to the Virtual Machine**

- Use PowerShell to SSH into the VM using the provided username and public IP address.
  ![WindowsTerminal_NA8i3xTdp5](https://github.com/user-attachments/assets/cd70bf79-252f-428c-b60c-a8cc53a9f532)
  
- Update system repositories with:
    ```bash
    apt-get update
    apt-get upgrade
    
    ```
    
### 4. **Installing Elasticsearch**

- **Download Installation:**
    - Find the appropriate Elasticsearch package and download it using `wget`.
- **Installation Command:**
    
    ```bash
    dpkg -i elasticsearch*.deb
    
    ```
    
- **Security Configuration:**
    - Save the security auto-configuration information containing the built-in superuser's password.
    - **This step is very important!**

### 5. **Configuring Elasticsearch**

- Edit the configuration file located at `/etc/elasticsearch/elasticsearch.yml`:
    - Change `network.host` to allow access from the SOC analyst laptop.
- Ensure to set HTTP ports correctly for access.

### 6. **Starting Elasticsearch Service**

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

## 4. Kibana Setup

### Installation Steps

1. **Download Kibana**:
    - Go to [elastic.co](https://www.elastic.co/downloads).
    - Select the appropriate version for your system (e.g., Debian x86_64).
    - Copy the download link and use an SSH session to download Kibana with the command:
        
        ```bash
        wget <KIBANA_DOWNLOAD_LINK>
        
        ```
        
2. **Install Kibana**:
    - After downloading, use the following command to install Kibana:
        
        ```bash
        dpkg -i <KIBANA_PACKAGE>
        
        ```
      ![WindowsTerminal_O61V8GFKKm](https://github.com/user-attachments/assets/e64089d3-63c0-4414-92d9-0f7fc4f3962d)

        
3. **Configuration Changes**:
    - Open the configuration file located at `/etc/kibana/kibana.yml` using:
        
        ```bash
        nano /etc/kibana/kibana.yml
        
        ```
        
    - Make necessary changes for `server.port` and `server.host`:
        - Remove the `#` for `server.host` and set it to your public IP address.
    - Save and exit the editor.
      ![WindowsTerminal_ko01MKj5CX](https://github.com/user-attachments/assets/731d352c-7578-4395-8e31-beab58d38e09)

4. **Start Kibana Service**:
    - Reload the system daemon and start Kibana using:
        
        ```bash
        systemctl daemon-reload
        systemctl enable kibana
        systemctl start kibana
        
        ```
        
5. **Check Kibana Status**:
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

## Firewall Configuration

1. **Adjust Firewall Rules**:
    - Ensure that the firewall allows access to port 5601 (Kibana's default port).
    - Use the following command to allow incoming connections:
        
        ```bash
        ufw allow 5601
        
        ```
        ![WindowsTerminal_NGjMrhO3Xh](https://github.com/user-attachments/assets/31f3bbd1-89c1-4979-93b8-8a5d0c787f87)
        
        
2. **Vultr Firewall Settings**:
    - In your Vultr instance, configure firewall rules to allow TCP traffic on ports 1-65535 for your public IP address.
      ![brave_gPZx8QGMhc](https://github.com/user-attachments/assets/8717be63-7ef9-4932-a513-1282982d3c66)


### Verification and Key Management

- Access Kibana through a web browser using your public IP and port 5601.
- Use the enrollment token to configure Elasticsearch.

## Adding Encryption Keys

- Generate and add encryption keys in Kibana for saved objects and security settings.
  ![WindowsTerminal_SiLNCDmJTk](https://github.com/user-attachments/assets/8f8b7e58-c188-4913-924e-d3445fbf79d4)
  
  ![WindowsTerminal_arqwJ3bX9w](https://github.com/user-attachments/assets/d4889a20-61cb-4276-9888-eca32a50a708)

- Restart Kibana after adding these keys:
    
    ```bash
    systemctl restart kibana
    
    ```

---

## 5. Windows Server 2022 Installation

### Steps to Deploy Windows Server

1. **Accessing the Cloud Provider**:
    - Navigate to the Vultr platform.
    - Log in to your account.
2. **Deploying a New Server**:
    - Select "Deploy" and then "Deploy New Server."
    - Choose "Cloud Compute" with shared CPU, as a high-performance server isn't necessary for this task.
    - Set the server location to "Toronto" (the same region as before) and select the latest Windows Server 2022 image.
    - Opt for the $24/month plan, which has 1 vCPU and 2 GB of memory to save money/credits.
3. **Network Configuration**:
    - It is important to keep the Windows Server isolated from the broader network to prevent unauthorized access.
    - Instead of using a Virtual Private Cloud (VPC), the server will be set up without it to allow public access.
4. **Server Naming Convention**:
    - Follow a specific naming convention for the server.
    - For instance, if your username is ideafieldpro, name your server `socanalyst-win2022-ideafieldpro`.
5. **Deployment Process**:
    - After naming the server, click "Deploy".
    - Wait for the server status to change to "Running".
    - Access the console to log in by sending a Control-Alt-Delete command and entering the password copied from the dashboard.
6. **RDP Connection**:
    - Copy the public IP address and open Remote Desktop.
    - Paste the IP and connect successfully to the Windows Server.

---

## 7. Elastic Agent and Fleet Server Setup 

### Setup Process

1. **Creating the Fleet Server**:
    - A new server is deployed in "Toronto" (the same location as before) using Ubuntu 22.04 with 4 GB of RAM.
    - The server is set up without auto-backups and IPv6.
    - The public IP address for the Fleet server is noted.
      ![brave_pxf58YQwKC](https://github.com/user-attachments/assets/4269792a-3425-4075-81c9-b0780603288b)

2. **Web GUI Access**:
    - Access the Elastic web GUI at `http://<public_IP>:5601`.
    - Navigate to Fleet management and select "Add Fleet Server."
    - Opt for the "Quick Start" setup.
      ![brave_lEXaSjB85z](https://github.com/user-attachments/assets/ee473e92-6b1b-4dc6-a4ff-b732d25fe0aa)

3. **Fleet Server Policy Creation**:
    - Enter the public IP of the virtual machine and ensure it uses `https://` protocol.
      ![brave_NV6EWPGanM](https://github.com/user-attachments/assets/fd05f439-40e9-4bf4-973d-af62c96dfe14)

    - Generate the Fleet server policy and copy the provided token for installation.
      ![brave_8LPjvE04if](https://github.com/user-attachments/assets/0edefe7e-48e8-4bd5-b9fd-2dfe8568af83)

4. **SSH into Fleet Server**:
    - Use PowerShell to SSH into the Fleet server using the root account.
    - Update repository lists and install the Elastic Agent by pasting the policy.
      
5. **Firewall Configuration**:
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

## 8. Sysmon Setup

### Step-by-Step Process

1. Preparation

- The server's public IP address and password is used for remote desktop connection.

2. Connecting to the Server

- Use Remote Desktop Protocol (RDP) to connect to the Windows Server.
- Enter the administrator credentials to access the server.

3. Downloading Sysmon

- Open a web browser and search for Sysmon.
- Download Sysmon version 15.15 from Microsoft's website.
- It's advised to scroll down the page to understand various event IDs for later investigations.

4. Extracting Files

- After downloading, extract the Sysmon files from the zip folder.

5. Downloading Configuration File

- Search for Olaf’s Sysmon Configuration file on GitHub.
- Save the configuration file `sysmonconfig.xml` in the Sysmon directory.

6. Using PowerShell

- Open PowerShell with administrative privileges.
- Change the directory to where Sysmon is located.
- Confirm you are in the correct directory by typing `dir`.

7. Installing Sysmon

- Use the command line to install Sysmon:
    
    ```bash
    sysmon64.exe -accepteula -i sysmonconfig.xml
    
    ```
    
- This command installs Sysmon as a service and begins capturing logs.

8. Verifying Installation

- Open Windows Event Viewer to confirm that Sysmon is running.
- Navigate through the Event Viewer to check for Sysmon events under "Microsoft" > "Windows" > "Sysmon" > "Operational".
  ![mstsc_Npsf48wRgC](https://github.com/user-attachments/assets/c2a753bb-e8c9-4b16-8e0b-90c6b39f6757)


---

## 9. Elasticsearch Ingest Data 

### Steps to Ingest Logs

1. Logging into Elasticsearch

- Start by logging into your Elasticsearch instance.
- Select the blue "Add Integrations" button on the homepage.

2. Installing Sysmon Integration

- Search for "Windows Event" and choose the "Custom Windows Event Log" package.
- This package allows the ingestion of events from the Windows Event log channel.

### Field Mapping

- The video discusses the field mappings provided in this package, which includes details like `wind log.computer name`.

3. Configuring Sysmon Logs

- Open Event Viewer on your Windows Server and navigate to `Applications and Services Logs > Microsoft > Windows > Sysmon`.
- Right-click on "Operational" to view its properties and copy the full channel name for integration.

4. Adding Sysmon Integration

- In Elasticsearch, add the integration with a custom name (e.g., `DFIR-win-Sysmon`) and paste the copied channel name.
- Save and deploy changes to complete the Sysmon integration.

### Installing Microsoft Defender Integration

1. Setting Up Defender Logs

- Expand the "Windows Defender" logs in Event Viewer and choose "Operational."
- The video suggests filtering event IDs to include only those relevant for monitoring (e.g., `1116`, `1117`, and `50001`).

### Important Event IDs

- Event ID `1116`: Indicates detection of potentially unwanted software.
- Event ID `1117`: Shows actions taken to protect the system from detected malware.
- Event ID `50001`: Indicates when real-time protection is disabled.

2. Adding Microsoft Defender Integration

- Similar to Sysmon, add a new integration for Microsoft Defender with a custom name (e.g., `DFIR-win-Defender`).
- Specify the relevant channel names and event IDs to include or exclude as needed.

### Testing & Troubleshooting

1. Verifying Ingested Logs

- Use the Discover feature in Elasticsearch to check if any Sysmon or Defender logs are showing up.
- If no data appears, troubleshooting steps include checking agent status and ensuring firewall rules allow connections to port 9200.

2. Firewall Configuration

- Ensure that your firewall permits incoming connections on port `9200` for Elasticsearch.

### 3. Restarting Services

- Restart the Elastic Agent service if logs do not appear after configuration.

## Conclusion

- After troubleshooting, the video confirms that Sysmon and Microsoft Defender logs are successfully ingested into the Elasticsearch instance.
- Viewers are encouraged to explore these logs further and check the documentation for deeper insights.

## Next Steps

- The next video will cover common attacks seen in various environments and tools used to conduct these attacks.
- 11 - What is a Brute Force Attack?

# Summary of "Day 11: Brute Force Attacks" - 30-Day Defend for SOC Analyst Challenge

## Introduction

- This video is part of a 30-day challenge aimed at helping aspiring SOC analysts gain practical experience.
- If you haven't started from Day 1, it is recommended to pause and do so.

## What is a Brute Force Attack?

- A Brute Force attack involves trying every possible password combination to gain unauthorized access to an account.
- The analogy used is attempting to unlock luggage with a keypad by testing every combination, starting from `0000`.

## Common Sources of Brute Force Attacks

- Many online services, such as remote desktops, are exposed to the internet, allowing attackers to attempt logins using leaked credentials from data breaches or through social engineering.

## Types of Brute Force Attacks

1. **Simple Brute Force Attack**
    - Attempts every combination systematically (e.g., `0000`, `0001`, etc.).
    - Usually automated.
2. **Dictionary Attack**
    - Uses a list of common words and phrases instead of all numerical combinations.
    - Targets passwords that are often human-generated and predictable.
3. **Credential Stuffing**
    - Involves using leaked credential dumps to try various username-password combinations to access accounts.

## Protection Against Brute Force Attacks

### 1. Use Long Passwords or Passphrases

- Passwords should ideally be at least 15 characters long and include uppercase letters, numbers, and special characters.
- Consider using password managers to generate and store complex passwords securely.

### 2. Enable Multi-Factor Authentication (MFA)

- MFA adds an extra layer of security, requiring an additional form of verification (like a text or authenticator app) after the initial password input.

### 3. Stay Vigilant

- Be cautious with emails or prompts asking for login information. Always verify the source.
- Monitor accounts for unauthorized access and change passwords if a data breach occurs.

## Common Tools Used for Brute Force Attacks

1. **Hydra**
2. **Hashcat**
3. **John the Ripper**

> Note: Use these tools responsibly and only on machines you own or have permission to test.
> 

## Conclusion

- The video emphasizes understanding brute force attacks, the different types, how to protect oneself, and familiarizing with commonly used tools.
- The next video will focus on setting up an SSH server in the cloud to observe brute force attacks in real time.
- 12 - Ubuntu Server 24.02 Installation

# Summary of Day 12: 30-Day MyDfir SOC Analyst Challenge

## Overview

The focus of Day 12 is on setting up an SSH server in the cloud and reviewing authentication logs in real-time.

## Key Steps

### Setting Up the SSH Server

1. **Vultr Setup**:
    - Visit [Vultr.com](https://vultr.com/) and sign in.
    - Click on "Deploy" in the top right corner and select "Deploy New Server."
    - Choose a shared CPU plan; the host selects Ubuntu version 24.0.
    - Opt for a basic configuration: 1 CPU and 1 GB memory, without auto backups or IPv6.
    - Name the server appropriately (e.g., `dfir-linux`), which is crucial for following the challenge.
2. **Deployment**:
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

1. **Location of Logs**:
    - Authentication logs are stored in `/var/log`.
    - The specific log file of interest is `auth.log`.
2. **Analyzing Logs**:
    - Use the `cat` command to view the `auth.log`:
        
        ```bash
        cat auth.log
        ```
        
    - Initially, there will be minimal activity but expect to see failed authentication attempts after some time.
3. **Filtering Failed Attempts**:
    - Use `grep` to filter entries containing "failed":
        
        ```bash
        grep -i failed auth.log
        ```
        
    - Further filter for attempts specifically for the 'root' user:
        
        ```bash
        grep -i failed auth.log | grep -i root
        ```
        
4. **Extracting IP Addresses**:
    - Utilize the `cut` command to isolate IP addresses from failed login attempts:
        
        ```bash
        grep -i failed auth.log | grep -i root | cut -d' ' -f9
        ```
        

### Conclusion

- The video concludes with a recap of successfully setting up the SSH server and observing real-time login attempts, some of which are indicative of brute force attacks.
- The next video will cover installing an Elastic Agent on the SSH server to forward logs to an Elasticsearch instance for further analysis.
- 13 - How to Install Elastic Agent on Ubuntu

# Summary of Day 13: 30-Day SOC Analyst Challenge

## Introduction

Day 13 of the 30-day SOC Analyst Challenge focuses on installing an Elastic Agent onto an SSH server that was set up on Day 12. This step is essential for enabling log querying on an Elasticsearch instance.

## Key Steps in the Process

### 1. Accessing the Elastic Web GUI

- Navigate to the Elastic web GUI.
- Click on the hamburger icon in the top left corner.
- Scroll down and select **Fleet Management**.

### 2. Creating a New Agent Policy

- Click on **Agent Policy** to create a new policy named `mydf-Linux-D-policy`.
- Select the **system-3** policy type (note: your version may vary).
- This policy will specify which logs the SSH server will push to the Elasticsearch instance.

### 3. Verifying Log Locations

- The default path for logs is `/var/log/secure`.
- If using Ubuntu, check `/var/log/auth.log` for authentication logs, as it differs from Red Hat/CentOS systems.

### 4. Adding the Agent

- Go back to **View Agent Policies** and click **Add Agent**.
- Choose the `df-Linux-DP` policy created earlier.
- Select **Enroll in Fleet**, specifying Linux as the operating system.

### 5. Installing the Elastic Agent

- Copy and paste the provided command into your PowerShell session to install the Elastic Agent.
- If you encounter an error regarding an X.509 certificate, add the `-insecure` flag to bypass it.

### 6. Confirming Installation

- Verify that the Elastic Agent has been successfully installed and that data is flowing into the Elasticsearch instance.
- Check by going to **Discover** and filtering by agent name.

## Analyzing Logs

- Look for authentication failures by searching with relevant keywords.
- The video demonstrates how to expand log events and adjust settings for easier viewing.

## Conclusion

By successfully installing the Elastic Agent and beginning to analyze logs, participants enhance their practical skills for SOC analysis. Day 13 wraps up with a reminder of upcoming topics, including creating alerts for brute-force activity and building a dashboard.

- 14 - How to Create Alerts and Dashboards in Kibana

# Summary of Day 14 - 30-Day MyDfir SOC Analyst Challenge

In this session, we focus on creating an **SSH Brute Force Alert Dashboard** to visualize attacks.

## Objectives

1. **Understand Brute Force Attacks**: Recognize what a Brute Force attack looks like in logs.
2. **Query Logs**: Learn how to query logs for failed authentication attempts.
3. **Create Alerts**: Set up alerts for detecting Brute Force activity.
4. **Visualize Data**: Create a dashboard for better visualization of the attack data.

## Step-by-Step Breakdown

### 1. Querying Logs

- Start by accessing the Elastic Search instance to query logs.
- Use the `Discover` feature to filter relevant data based on your SSH server.
- Look for **failed authentications**, which indicate attempted unauthorized access.

### 2. Identifying Important Fields

- Key fields to focus on:
    - **Failed attempts**: Count the number of failed logins.
    - **Usernames**: Identify the usernames being targeted.
    - **Source IPs**: Track the IP addresses attempting access.

### 3. Creating Alerts

- Once you've filtered for failed attempts, save your query as `SSH Failed Activity`.
- Navigate to the alerts tab and create a new alert:
    - Set thresholds (e.g., 5 failed attempts within 5 minutes).
    - Adjust the timing (e.g., check every minute).

### 4. Building the Dashboard

- Head to the **Analytics** tab to create a visual representation of your data.
- Use a map layer to pinpoint where attacks are originating from, leveraging geolocation based on source IPs.
- Ensure that your queries correctly reflect the data you're interested in visualizing.

### 5. Successful Authentication Queries

- Duplicate the previous dashboard and adjust it to show successful authentications.
- Modify the query to focus on accepted attempts rather than failed ones.

## Conclusion

Congratulations! You've successfully:

- Created an alert for SSH Brute Force activity.
- Designed a dashboard to visualize both failed and successful authentication attempts.

### Next Steps

In the next video, you'll learn about common services that many organizations use and commonly abused.

- 15 - Remote Desktop Protocol Intro

# Summary of RDP Abuse and Protection Strategies

## Introduction

The video discusses the abuse of the Remote Desktop Protocol (RDP), highlighting its prevalence in ransomware breaches and offering practical advice for aspiring security operations center (SOC) analysts.

## What is RDP?

- **Definition**: RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft that allows authorized users to connect remotely to another machine.
- **Functionality**: It operates over TCP and uses the default port 3389, enabling remote access for troubleshooting and management.

## RDP Abuse Statistics

- **Prevalence**: In 2023, it was noted that 90% of ransomware breaches involved RDP abuse.
- **Common Attack Vector**: Exposed RDP services can be targeted by attackers to gain unauthorized access through methods like brute force attacks.

## How Attackers Abuse RDP

1. **Initial Access**: Attackers exploit exposed RDP services on production or development servers.
2. **Brute Force Attacks**: They may use brute force techniques to authenticate using stolen or guessed credentials.
3. **Lateral Movement**: Once inside, attackers can perform actions such as credential dumping and lateral movement to compromise additional systems.

## Finding Exposed RDP Services

- The video introduces tools like **Shodan**:
    - **Creating an Account**: Users are encouraged to sign up for Shodan.
    - **Searching for Exposed RDP**: Users can search for the default port 3389 to find assets with RDP exposed.
- Another tool mentioned is **Census**:
    - Users can filter searches specifically for RDP services and analyze public IP addresses.

## Recommendations for Protecting Against RDP Abuse

1. **Disable RDP When Not Needed**: Ensure RDP is disabled on development servers once their use is complete.
2. **Use Multi-Factor Authentication (MFA)**: Add an additional layer of security to accounts.
3. **Restrict Access**: Implement firewall rules to limit access to RDP servers within a specific IP range, ideally placing them behind a VPN.
4. **Strengthen Passwords**: Use strong passwords with at least 15 characters, including upper and lowercase letters, numbers, and special characters.
5. **Disable Default Accounts**: Prevent credential stuffing attacks by disabling default local accounts.

## Conclusion

The video emphasizes the importance of understanding RDP, recognizing how it can be abused, and implementing protective measures. Future content promises to cover RDP logs and alert setups for brute force attacks.

- 16 - How to Create Alerts and Dashboards in Kibana

# Summary of Day 16: 30-Day SOC Analyst Challenge

## Overview

Day 16's focus is on reviewing authentication logs from a Windows server and creating Brute Force attack alerts.

## Key Steps Covered

### 1. Review Authentication Logs

- **Accessing Logs**: The host navigates to the Elastic web GUI and selects the "Discover" option.
- **Filtering Events**: He filters events specifically for an RDP server, identifying approximately 32,000 failed authentication attempts.
- **Identifying Event ID**: The focus is on Event ID `4625`, which indicates failed authentication attempts. The host explains how to find this information by searching for the event ID.

### 2. Analyzing Failed Authentication Attempts

- **Expanding Event Details**: The first failed event is expanded to gather fields such as source IP address and username.
- **Creating a Search Query**: A search query for failed RDP activity is saved, named "RDP Failed Activity". This query helps in monitoring failed logins.

### 3. Testing Authentication

- **Testing Logins**: The host tests the login with a specific username and checks the logs for successful and failed attempts. He emphasizes the importance of understanding log types:
    - **Logon Type 3**: Network-based authentication (e.g., RDP).
    - **Logon Type 10**: Remote interactive logon.

### 4. Creating Alerts

- **Set Up Alerts**: The video dives into creating alerts for detecting brute force attacks.
- **Search Threshold Rule**: A search threshold rule is created based on Event ID `4625`, configured to check every minute for multiple failed login attempts.
- **Rule Details**: The rule captures user details and source IP addresses.

### 5. Enhancing Alert Information

- **Creating Detection Rules**: The host explains the process of creating more informative detection rules that provide detailed information compared to standard alerts.
- **Custom Queries**: Custom queries are introduced to include usernames, allowing analysts to better understand the context of failed authentication attempts.

### 6. Final Thoughts

- The host encourages viewers to further explore alert options and improve their configurations to enhance security monitoring.
- Emphasizes the importance of using strong passwords, implementing MFA, and limiting access to services exposed to the internet.
- Preview of the next video includes creating a dashboard to visualize authentication attempts.

## Conclusion

The video provides valuable insights into using Elastic security tools for monitoring authentication attempts and setting up alerts for potential security issues. Viewers are encouraged to experiment with different configurations and remain vigilant about securing their systems.

---

This summary should help you grasp the main points discussed in Day 16 of the SOC Analyst Challenge. Are there any specific areas you’d like to explore further?

Cheers, Craig

- 17 - How to Create Alerts and Dashboards in Kibana

# Summary of Day 17: 30-Day SOC Analyst Challenge

## Objective

- The goal is to create a dashboard that focuses on Remote Desktop Protocol (RDP) activity generated by a Windows server.
- This exercise builds upon previous lessons, specifically from Day Five.

## Creating the Dashboard

### Step 1: Query Setup

- Navigate to the Elastic web GUI and select the "Maps" feature.
- Use the saved query to analyze authentication attempts related to RDP:
    - **Event Code**: `4625` for failed attempts.
- Set the time filter to the last 7 days.

### Step 2: Data Layer Addition

- Add a layer for geographical context using country data.
- Identify a significant number of failed authentication events originating from Russia.

### Step 3: Save and Organize

- Save the dashboard titled "RDP Failed Authentication".
- Duplicate the dashboard to create one for successful RDP authentications using **Event Code**: `4624`.

### Step 4: Successful Authentication Queries

- Focus on logon types, specifically logon type `10` (RDP) and `7`.
- Update the query and save as "RDP Successful Activity".

## Visualization Enhancements

- Create visual representations of RDP and SSH activities.
- Add tables showing usernames, source IPs, and country names for both failed and successful authentications.
- Configure charts to display the top ten values for user activity without grouping remaining values.

## Final Adjustments

- Ensure all queries reflect accurate data by editing and updating titles and configurations.
- Save all changes to prevent data loss.

## Conclusion

- The video wraps up with encouragement to build additional alerts and dashboards for practice.
- The host teases the next video focusing on command and control tactics using the Mythic framework.
- 18 - Command and Control Introduction

# Summary of Command and Control in Cybersecurity

## Overview

In this video, the host discusses the concept of Command and Control (C2) within the context of cybersecurity, particularly as part of a 30-day challenge aimed at aspiring Security Operations Center (SOC) analysts. The objective is to provide practical experience in understanding how malicious executables operate and the tools used for establishing C2 sessions.

## Key Points

### Malicious Executable Behavior

- **Execution of Commands**: Upon running a malicious binary, it often executes a series of discovery commands (e.g., `ipconfig`, `nslookup`, `net user`) to gather information about the compromised system.
- **Persistence Mechanisms**: Many malicious binaries create services or scheduled tasks to ensure they survive system reboots.
- **Establishing C2 Sessions**: A primary action of most malicious binaries is to establish a command and control session, allowing attackers to remotely control the victim's system.

### Importance of C2

- **Definition**: Command and Control (C2) refers to techniques that adversaries use to communicate with compromised systems.
- **Objectives**: By establishing a C2 channel, attackers can execute various actions, including stealing sensitive information or moving laterally within a network.

### Tools and Frameworks for C2

The video highlights several common C2 frameworks used by attackers:

1. **Metasploit**
    - A popular framework often used in penetration testing.
    - Provides various exploits and auxiliary modules to probe target machines.
2. **Cobalt Strike**
    - A commercial product used for adversary emulation.
    - Commonly detected in compromised environments, making it important for SOC analysts to recognize.
3. **Sliver**
    - An open-source adversary emulation framework created by Bishop Fox.
    - Supports multiple methods for establishing C2 connections (e.g., HTTP, DNS).
4. **Mythic**
    - The framework that will be utilized in the 30-day challenge.
    - Built using Go and Docker, it has a web-based user interface and supports tracking payloads and callbacks effectively.

### Next Steps

- The upcoming video will focus on crafting an attack against a Windows server and setting up the Mythic server to deploy an agent for establishing a successful C2 session.

## Conclusion

The video serves as an introductory lesson on the significance of command and control in cybersecurity, providing insights into how attackers operate and the tools they use.

- 19 - How to Create an Attack Diagram

# Summary: Day 19 of the 30-Day SOC Analyst Challenge

## Overview

The focus of this day is creating an attack diagram that outlines the steps to compromise a target machine.

## Key Steps in the Attack Diagram Creation

### 1. **Setting Up the Attack Diagram**

- The presenter uses **draw.io** to create the attack diagram.
- Main components included:
    - **Mythic C2 Server** (Command and Control server)
    - **Windows Server** (target server)
    - **Attacker's Laptop** (using Kali Linux)

### 2. **Phases of Attack**

The attack is broken down into six distinct phases:

### **Phase One: Initial Access**

- Perform an **RDP brute force attack** against the Windows Server to gain access.

### **Phase Two: Discovery**

- After successful access, run discovery commands:
    - `ipconfig`
    - `net user`
    - `net group`

### **Phase Three: Execution**

- Download and execute the **Mythic agent** on the Windows Server using PowerShell:
    - Utilize `IEX` (Invoke Expression) to download the agent.

### **Phase Four: Defense Evasion**

- Disable Windows Defender on the Windows Server to avoid detection before execution.

### **Phase Five: Command and Control (C2)**

- Establish a command and control session with the Mythic C2 server, enabling remote control over the target.

### **Phase Six: Exfiltration**

- Create a fake password file named `passwords.txt` on the Windows Server and download it through the established C2 session.

### 3. **Final Notes on the Attack Diagram**

- The presenter emphasizes that this diagram serves as a conceptual map for understanding the attack pathway and steps involved in successfully compromising a target machine.
- Encourages viewers to create their own attack diagrams, especially focusing on SSH servers for additional practice.
- 20 - Mythic Server Setup Tutorial

# Summary of Day 20 of the 30-Day SOC Analyst Challenge

## Setting Up Mythic C2

1. **Cloud Provider Setup**
    - The presenter chooses Vulture as the cloud provider.
    - Steps include logging in, clicking "Deploy," and selecting options such as:
        - Cloud Compute with shared CPU.
        - Operating system: Ubuntu with 4 GB RAM.
        - No need for auto backups or IPv6.
2. **Installing Kali Linux**
    - Download Kali Linux from the official website.
    - Select the virtual machine option suitable for the hypervisor being used (e.g., VMware).
    - Extract the downloaded file and ensure that file name extensions are visible to find the `.vmx` file.
3. **Deploying Mythic C2**
    - Access the Vulture console and log into the server using SSH.
    - Update and upgrade the system repositories:
        
        ```bash
        apt-get update
        apt-get upgrade
        
        ```
        
    - Install required prerequisites, including Docker Compose.
4. **Cloning and Installing Mythic**
    - Clone the Mythic repository from GitHub:
        
        ```bash
        git clone https://github.com/its-a-feature/SL-Mythic
        ```
        
    - Navigate to the Mythic directory and run the installation script:
        
        ```bash
        cd Mythic
        ./install_core_docker_U
        ```
        
5. **Configuring Docker**
    - If Docker is not running, restart it:
        
        ```bash
        systemctl restart docker
        ```
        
    - Start the Mythic CLI:
        
        ```bash
        ./mythic_cli start
        ```
        

## Security Configurations

- Set up firewall rules to restrict communication to only necessary targets.
- Create a firewall group in Mythic for added security.

## Accessing Mythic Web GUI

- Access the Mythic web interface using the public IP address on port 7443; if an HTTP error appears, add HTTPS.
- Default login credentials can be found in the environment variable file.

## Overview of Mythic Features

- **Dashboard**: Displays callbacks and agent status.
- **Payload Management**: Options to generate, import, and manage payloads.
- **Artifact Tracking**: Keeps track of keylogs, screenshots, and other artifacts.
- **MITRE Attack Mapping**: Provides a way to analyze tasks against MITRE framework categories.

## Next Steps

- Upcoming videos will focus on creating a Mythic agent and attacking a Windows server machine. Emphasis on practicing within a controlled environment where permission is granted.
- 21 - Mythic Agent Setup Tutorial

# Summary of the 30-Day Sock Analyst Challenge - Day 21

## Introduction

- The challenge involves performing a Brute Force attack, generating a Mythic agent, and establishing a successful C2 (Command and Control) session with a Windows server.

## Objectives for Today

1. Perform a Brute Force attack from a Kali Linux machine onto a Windows server.
2. Execute discovery commands and implement defense evasion techniques.
3. Use Mythic C2 to generate a payload and create a Mythic agent on the Windows server.
4. Establish a C2 connection and download a password text file from the Windows server.

## Steps to Achieve the Objectives

### 1. Setting Up the Windows Server

- Create a fake file named `passwords.txt` on the Windows server and set a common password (`Winter2024!`).
- Adjust local group policies to change password requirements, allowing simpler passwords for testing.

### 2. Performing Brute Force Attack

- Log into the Kali Linux machine and prepare for the Brute Force attack using tools like `crowbar`.
- Use an existing wordlist (`rockyou.txt`) to attempt to crack the administrator's password on the Windows server.
    
    CIDR (Classless Inter-Domain Routing) notation is used to specify IP address ranges and subnet masks. Here are the different CIDR notations and their common uses:
    
    ### CIDR Notations and Their Common Uses
    
    | CIDR Notation | Number of IP Addresses | Common Uses |
    | --- | --- | --- |
    | /0 | 4,294,967,296 | Represents all possible IPv4 addresses; used in default routing. |
    | /1 | 2,147,483,648 | Used for very large networks; rarely seen in practice. |
    | /8 | 16,777,216 | Often used by large organizations or ISPs; provides a significant number of addresses (e.g., 10.0.0.0/8). |
    | /16 | 65,536 | Commonly used for medium-sized networks; often seen in corporate settings (e.g., 192.168.1.0/16). |
    | /20 | 4,096 | Suitable for smaller networks or subnets within larger organizations (e.g., 172.16.0.0/20). |
    | /24 | 256 | Widely used for local area networks (LANs); typical subnet size for many home and small business networks (e.g., 192.168.1.0/24). |
    | /25 | 128 | Used for networks where a smaller number of devices are required (e.g., branch offices). |
    | /26 | 64 | Suitable for very small networks or specific applications (e.g., point-to-point connections). |
    | /27 | 32 | Often used for small subnets in larger networks or specialized applications. |
    | /28 | 16 | Typically used for very small networks, such as a few devices or hosts (e.g., small IoT deployments). |
    | /29 | 8 | Common in point-to-point links or small subnets where only a few devices are needed. |
    | /30 | 4 | Usually employed for point-to-point connections between two routers (e.g., WAN links). |
    | /32 | 1 | Represents a single host; often used in firewall rules or specific routing configurations. |
    
    ### Summary
    
    CIDR notation provides flexibility in IP address allocation and is essential for efficient routing and network management. The choice of CIDR notation depends on the size of the network and the specific requirements of the deployment.
    

### 3. Executing Commands on the Windows Server

- Once logged in via RDP (Remote Desktop Protocol), execute discovery commands:
    - `ipconfig`
    - `net user`
    - `net localgroup`
- Disable Windows Defender as part of the defense evasion phase.

### 4. Building and Deploying Mythic Agent

- Access Mythic’s web GUI to install the necessary agents (e.g., Apollo).
- Generate a payload for the Windows machine, specifying the callback host and port.
- Download the agent and rename it appropriately for execution on the target.

### 5. Establishing Connection and Exfiltration

- Use Python's HTTP server module to serve the agent file.
- Allow necessary ports in the firewall settings to facilitate communication between the agent and Mythic C2.
- Execute the agent to establish a connection with Mythic C2, confirming successful execution through task manager.

### 6. Downloading Password File

- Utilize the established C2 session to issue commands that download the previously created `passwords.txt` file from the Windows server.
- Verify that the password retrieved matches what was set earlier.

## Conclusion

- The session demonstrates the power of the Mythic framework for conducting penetration testing in an educational context.
- Viewers are encouraged to further explore Mythic's capabilities and participate in future videos for continuous learning.

## Final Note

The video emphasizes ethical considerations and encourages responsible use of demonstrated techniques in cybersecurity practice.

- 22 - How to Create Alerts and Dashboards in Kibana

# Summary of Day 22 of the 30-Day SOC Analyst Challenge

## Creating Alerts for Mythic C2 Activity

1. **Accessing Elastic Web GUI**:
    - Navigate to the "Discover" section by clicking the hamburger icon.
    - Set the time frame to 30 days to capture all relevant events.
2. **Identifying Events**:
    - The focus is on identifying events related to `servicehost.exe` and `mythic C2` activity.
    - Use event code 11 to look for file creation events and expand to investigate.
3. **Using Open Source Intelligence**:
    - The video demonstrates how to gather additional context using hash values from identified processes.
    - Specific attention is given to the original file name, which indicates potential malicious activity.
4. **Creating Detection Rules**:
    - A basic alert is created to detect any process creation involving `apollo.exe`.
    - The alert is set to trigger when the process is created, regardless of its success.
5. **Setting Required Fields**:
    - Essential fields such as timestamp, username, command line, and parent command line are included for detailed analysis.

## Dashboard Creation

1. **Building Dashboards**:
    - A dashboard is created to show suspicious activity, including external network connections and process creation events.
    - Queries are constructed for event IDs related to these activities.
2. **Visualization Setup**:
    - The video guides viewers through creating visualizations for both process creation (event ID 1) and network connections (event ID 3).
    - Multiple panels are added to provide a comprehensive view of ongoing activities.
3. **Finalizing Dashboards**:
    - The dashboard is titled "DFIR Dashboard: Suspicious Activity" and includes multiple alerts and visualizations.
    - Emphasis is placed on monitoring specific indicators of compromise, including disabled security tools like Microsoft Defender.

## Conclusion

- The challenge aims to help participants build confidence in creating alerts and dashboards.
- Viewers are encouraged to continue exploring and customizing their dashboards.
- The next video will cover ticketing systems for managing alerts effectively.
- 23 - What is a Ticketing System

# Summary of Day 23: Ticketing System Introduction

## Overview

In this video, the host discusses the importance of tracking alerts generated by security tools and introduces a ticketing system to help aspiring SOC analysts manage these alerts effectively. 

## Key Points

### Importance of Tracking Alerts

- **Security Alerts**: Keeping track of triggered alerts is crucial for identifying potential misconfigurations or attacks.
- **Ticketing System**: A ticketing system can help organize and manage these alerts, allowing analysts to track tasks and maintain accountability.

### Introduction to Ticketing Systems

- **Purpose**: A ticketing system creates "tickets" to manage tasks such as alerts, customer complaints, or troubleshooting requests.
- **Audit Trail**: This system provides an audit trail, satisfying the requirements of authentication, authorization, and accounting (AAA).

### Recommended Ticketing System: OS Ticket

- **OS Ticket**: The host introduces OS Ticket, an open-source ticketing system that can be self-hosted or managed for a fee.
- **Features**:
    - Customizable fields
    - Ticket filters for routing
    - Assignment and transfer of tickets
    - SLA (Service Level Agreement) settings
    - Email integration (in the self-hosted version)

### Practical Application

- **Integration**: Integrating OS Ticket into a tech stack mimics a small SOC startup environment, providing a realistic experience for participants in the challenge.
- **Free Version**: The free self-hosted version of OS Ticket is sufficient for the purpose of this challenge.
- 24 - osTicket Setup Tutorial

# Summary of Day 24

## Setting Up OS Ticket

### Step 1: Deploying a Server

- **Platform**: The presenter uses Vulture to deploy a new server.
- **Configuration**:
    - **Server Type**: Cloud compute with shared CPU.
    - **Location**: Toronto.
    - **Operating System**: Windows Standard 2022.
    - **Specifications**: 55 GB storage, 1 CPU, and 2 GB memory.
- **Firewall Setup**: A firewall is configured to restrict access to the web server that will host OS Ticket.

### Step 2: Installing XAMPP

- **Download XAMPP**: The presenter downloads XAMPP (version 8.2.2) from the Apache Friends website.
- **Installation**:
    - Default installation settings are used, and properties are edited to configure Apache and MySQL settings.
- **Firewall Rules**: Inbound rules are created to allow connections on ports 80 and 443.

### Step 3: Configuring PHPMyAdmin

- **Accessing PHPMyAdmin**: Initial connection errors are resolved by adjusting configuration files to allow access through the public IP address.
- **User Accounts**: User credentials for root and PMA accounts are set up.

## Installing OS Ticket

### Step 4: Downloading OS Ticket

- **Download Version**: The presenter downloads OS Ticket (version 1.18.1) from the official site.
- **File Extraction**: Extracts the files to the `HTdocs` directory in XAMPP.

### Step 5: Running the Installer

- **Installation Steps**:
    - Initial configuration prompts require setting up help desk name, username, and database settings.
    - A new database is created within PHPMyAdmin for OS Ticket.

### Step 6: Finalizing Installation

- After addressing some errors regarding email settings, the installation is successfully completed.
- **File Permissions**: The presenter discusses how to change file permissions using Windows PowerShell.

## Conclusion

- **Accessing OS Ticket**: Instructions are given on how to access the OS Ticket URL and log in as an admin.
- **Next Steps**: Viewers are encouraged to watch the next video, which will cover integrating OS Ticket into a tech stack for managing alerts.
- 25 - osTicket + ELK Integration

# Summary of Day 25

## Objective

- The main goal for Day 25 is to integrate OS Ticket with Elastic Stack and confirm the integration by sending a test alert.

## Steps for Integration

### Accessing OS Ticket

1. Log into the OS Ticket control panel.
2. Navigate to the Admin panel and select `Manage`, then `API`.
3. Click `Add New API Key`, entering the private IP address of the OS Ticket server if it's in the same Virtual Private Cloud (VPC), or the public IP if not.

### Setting Up Elastic Stack

1. Open the Elastic interface and go to `Management`.
2. Select `Stack Management`, then `Alerts and Insights`.
3. Click on `Connectors` and choose to create a new connector.
4. Start a free 30-day trial to enable API connections if you're using a free license.

### Creating the Connector

1. Use a webhook connector to send alerts from Elastic to OS Ticket.
2. Set up the webhook with the OS Ticket's IP address and API key.
3. Configure the body for the webhook request using an XML payload example from OS Ticket’s GitHub page.

## Troubleshooting Connection Issues

- If encountering a timeout error during testing, check network connections:
    - SSH into the ELK server to verify IP addresses.
    - Make sure that the OS Ticket server is reachable.

### Finalizing Integration

1. Adjust the network settings on your OS Ticket server if necessary to ensure it has a private IP.
2. Rerun the test for the connector after making any adjustments.

## Conclusion

- After successful integration, alerts generated in Elastic can now automatically create tickets in OS Ticket.
- This integration enhances tracking and auditing capabilities for SOC analysts.

## Recap of Previous Steps

- The challenge included spinning up an Elastic Search instance, setting up two servers (Windows and Linux), installing agents, creating alerts for security activities, and now integrating ticketing systems.
- 26 - Investigate SSH Brute Force Attack

# Summary of Day 26

## Key Points

### Investigating SSH Alerts

- The host accesses the alerts section and finds a total of 195 alerts, with the first one dated August 14th.
- The investigation begins by using **Timelines**, a feature that helps visualize alerts and events related to a specific user. This tool is suggested for deeper analysis and is encouraged to be explored further.

### Steps to Investigate Brute Force Alerts

1. **Identifying the Source IP**:
    - The first step is to note the source IP address from the alert, which is reported as `194.50.201.6`.
    - The host checks this IP against known databases to determine its reputation for brute force activity.
2. **Using External Resources**:
    - **AbuseIPDB**: The IP is found to be reported 1,816 times with a confidence level of 100% indicating malicious behavior.
    - **GreyNoise**: A search reveals that the IP is known to use tools such as zmap for SSH brute-forcing.
3. **Identifying Affected Users**:
    - The host uses Kibana to query events related to the identified IP over the last 30 days.
    - Four distinct users are affected: root, Oracle, guest, and test accounts.
4. **Looking for Successful Logins**:
    - Initial queries for successful logins return no results, suggesting that all login attempts were unsuccessful.
    - The host emphasizes the importance of double-checking queries and adjusting capitalization since it can affect search results.

### Documenting Findings

- The host discusses how to document findings in a ticketing system, emphasizing the need to add notes and ensure proper processes are followed.
- Modifications are made to alert rules to push notifications into a ticketing system (OS Ticket).

### Configuring Alerts

- The video covers editing alert settings, including configuring webhook actions and ensuring that alerts contain relevant information such as the source IP and user details.
- The importance of having hyperlinks in notifications for easy access to alert details is noted.

### Closing Tickets

- Finally, the process of assigning and closing tickets is demonstrated, highlighting the importance of communication among team members to avoid duplicated efforts.

## Conclusion

The video wraps up with encouragement to continue practicing investigation skills and building confidence in identifying suspicious activities. The next video will focus on RDP alerts.

- 27 - Investigate RDP Brute Force Attack

# Summary of Day 27: Investigating RDP Brute Force Alerts

## Introduction

- The focus of Day 27 is on investigating RDP (Remote Desktop Protocol) Brute Force alerts.

## Investigating RDP Brute Force Attacks

1. **Accessing Alerts:**
    - The presenter demonstrates how to navigate to the alert section of their security tool.
    - They filter alerts to focus specifically on RDP Brute Force alerts from the past 30 days.
2. **Details of the Alert:**
    - An example alert is examined, revealing the source IP address (81.1.163.20) and the use of the username "administrator."
    - The presenter mentions creating a ticket in OS Ticket for the alert.
3. **Using AbuseIPDB:**
    - The presenter checks the flagged IP address on AbuseIPDB, which shows it has been reported multiple times for suspicious activity.
    - The IP is associated with RDP Brute Force attempts and categorized as originating from Russia.
4. **Gray Noise Analysis:**
    - They also analyze the IP using Gray Noise, which identifies scanning activity but cannot determine intent.
    - The analysis reveals that this IP is classified as a "RDP crawler," indicating potential malicious activity.

## Addressing Key Questions

1. **Is the IP Known for Brute Force Activity?**
    - Yes, confirmed through AbuseIPDB reports.
2. **Are There Other Users Affected by This IP?**
    - The analysis shows that only the "administrator" account is affected, with no successful logins recorded.
3. **Successful Login Attempts:**
    - The presenter looks for event code 4624, indicating successful authentications, and finds no successful logins from the flagged IP address.
4. **Investigating Another IP:**
    - They investigate another IP involved in a previous RDP Brute Force attempt and find similar results regarding its malicious activity.

## Conclusion and Next Steps

- The presenter emphasizes the importance of thorough investigation, including checking for successful logins and understanding potential compromises.
- They encourage viewers to explore processes like persistence mechanisms and lateral movements in their investigations.
- Future videos will continue to build on these investigative techniques, including discussions around Mythic C2 agent activities.
- 28 - Investigate Mythic Agent

# Summary of Day 28

## Overview

In this video, the host continues the SOC Analyst Challenge focusing on investigating a common Command and Control (C2) framework called Mythic.

## Key Points

### Getting Started with Mythic C2

- **Initial Investigation**: The host mentions that the Mythic C2 agent is called `servicehost DStepenrocks.exe` (the name may vary based on user).
- **Finding Events**: Analysts should use the Discover feature by setting the time frame to 30 days and searching for `servicehost DStepenrocks.exe` to gather relevant events.

### Identifying C2 Activity

- **Network Telemetry**: The host explains that C2 sessions often involve significant back-and-forth traffic, indicating potential data transfer.
- **Top Talkers**: Monitoring the top 10 address pairs for high traffic can help identify C2 communications.
- **Heartbeat Monitoring**: A tool called Rita from Black Hills Security is recommended for detecting potential C2 traffic.

### Process Creation Analysis

- **Sysmon Event ID 3**: The host looks at network connections initiated by certain processes, particularly focusing on `rundll32.exe`, which is commonly exploited by malware.
- **Suspicious Activity**: Identifying unusual process executions, like those from `Microsoft Edge` or executables in unexpected directories, is crucial.

### Building a Timeline

- **Event Correlation**: The host demonstrates how to build a timeline of events related to suspicious network connections and process creations.
- **Using Process GUIDs**: By following the process GUID, analysts can trace back the actions of PowerShell sessions and other potentially malicious activities.

### Detection Rules Configuration

- **Mythic C2 Apollo Rules**: The host shows how to edit detection rules in Mythic to ensure alerts are generated for any suspicious activities.

### Real-time Investigation

- **Testing Alerts**: The host interacts with the Mythic server and demonstrates how to generate alerts by executing commands.
- **Monitoring Telemetry**: Both endpoint telemetry and network-related data are emphasized for a comprehensive investigation.

### Conclusion and Encouragement

- The host encourages viewers to practice and explore telemetry related to C2 agents like Mythic, emphasizing the importance of hands-on experience.
- Future videos will cover installing Elastic EDR (Elastic Defend) and troubleshooting techniques.

## Final Thoughts

This video provides valuable insights into practical investigation methods for SOC analysts, focusing on identifying C2 frameworks and analyzing suspicious activities.

- 29 - Elastic Defend Setup Tutorial

# Summary of Day 29

## Introduction

The focus is on installing and configuring Elastic's EDR (Endpoint Detection and Response) tool, known as Elastic Defend.

## Key Steps in the Installation Process

1. **Downloading and Installing Elastic Defend**:
    - The presenter guides viewers to download and install Elastic Defend on their endpoints to start protecting against malicious activity.
    - Note: Free subscriptions do not allow for remote host isolation.
2. **Integration Setup**:
    - Once installed, users should navigate to the top-left corner (the hamburger icon) and scroll to "Integrations."
    - Click on Elastic Defend to add the integration, providing a name and description for the setup.
3. **Configuration Options**:
    - There are four configuration types:
        - Data Collection
        - Next-Gen Antivirus
        - Essential EDR
        - Complete EDR
    - The presenter selects the "Complete EDR" option for full telemetry and protection.
    - Configurations can be set for traditional endpoints or cloud workloads.
4. **Endpoint Management**:
    - The Windows Server is selected for integration, and changes are saved for deployment.
    - Once deployed, users can view endpoints under the "Security" section.

## Demonstrating EDR Capabilities

- The presenter executes a test by terminating a potentially harmful process (`defer D30.exe`) to showcase Elastic Defend's alert mechanisms.
- An alert is generated indicating that the file contains a virus, demonstrating effective malware prevention.

## Investigating Alerts

- Viewers are shown how to access telemetry data via Kibana:
    - Search for malware alerts in the "Discover" tab.
    - The video outlines how to sort alerts by timestamp and examine details of any detected threats, including file paths and hash values.

## Incident Response Actions

- The presenter discusses editing rule settings in Elastic Defend:
    - Users can set responses to isolate the host if malicious activity is detected.
    - A command prompt demonstration shows an infinite ping command, illustrating that network activity is limited when a host is isolated.

## Conclusion

- Participants are encouraged to continue their learning in a Minick environment to gain further practical experience.

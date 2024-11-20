# Kali Local install

To set up a secure pentesting lab that allows our local Kali Linux environment to interact with cloud-hosted vulnerable servers. Let's do the following:

---

### 1. Setting Up Kali to Communicate with AWS EC2 Instances

To enable communication between our local Kali Linux machine on VirtualBox and the vulnerable servers (Ubuntu 16.04 and Windows Server 2003) on AWS EC2, we’ll need to follow these steps:

**A. Networking Configuration**
- **Set up a Public IP for the EC2 Instances**: Ensure each EC2 instance has a public IP or Elastic IP assigned, which will make it accessible from outside AWS (including from your local Kali box).
- **Configure Security Groups**: AWS Security Groups act as virtual firewalls. Allow incoming traffic from your IP (or a range if necessary) on specific ports, such as:
  - **SSH (port 22)**: For SSH access to Ubuntu.
  - **RDP (port 3389)**: For Remote Desktop access to Windows Server 2003.
  - Any other necessary ports (e.g., HTTP, SMB, etc.) based on the vulnerabilities you plan to exploit.

**B. Kali Network Configuration**
- Ensure the **VirtualBox network adapter** for Kali is configured for **NAT Network** or **Bridged Adapter**:
  - **NAT Network**: This allows VirtualBox VMs to share the host’s IP address and access the internet, which can communicate with AWS instances as long as routing and security rules permit.
  - **Bridged Adapter**: This allows the VM to obtain an IP directly from your router, similar to other devices on the network, allowing more seamless communication with external networks.
- **Public IP Requirement**: Since you’re connecting from a local machine, the AWS firewall rules must allow traffic from your external IP address (e.g., the router or firewall’s public IP if you’re on a home network).

**C. Test Connectivity**
Once setup is complete:
1. **SSH to Ubuntu**: `ssh -i /path/to/your-key.pem ubuntu@<EC2-ubuntu-ip>`
2. **RDP to Windows**: Use `xfreerdp` from Kali if you want to connect: `xfreerdp /u:Administrator /v:<EC2-windows-ip>`

#### Troubleshooting
If we have any issues, we should check firewall rules, and confirm IP configurations and routing.

---


### Security Precautions

Ensure your testing is strictly confined to these environments. Isolating your lab network and limiting firewall access is essential for security. Also, remember that some vulnerabilities can cause service crashes, so test them carefully and always make use of snapshots or backups on AWS for easy recovery.
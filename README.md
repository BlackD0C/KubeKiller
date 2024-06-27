# KubeKiller Tool Beta 0.8

Welcome to the repository of KubeKiller, an open-source tool designed for advanced Kubernetes and container penetration testing. This tool is currently in its beta phase and we welcome contributions and feedback from the community to enhance its capabilities.

## Overview

KubeKiller is aimed at security professionals and penetration testers who need a specialized tool to assess the security of Kubernetes clusters and containerized environments. It provides a comprehensive set of features to simulate attacks, identify vulnerabilities, and evaluate the resilience of Kubernetes infrastructures.

## Features

- **Cluster Scanning:** Automatically scan Kubernetes clusters to identify misconfigurations and security loopholes.
- **Simulated Attacks:** Perform simulated attacks on Pods, Services, and Nodes to assess their response to security breaches.
- **Network Exploitation:** Test network policies and firewall rules within Kubernetes clusters.
- **Access Controls Testing:** Evaluate the effectiveness of role-based access controls (RBAC) and service accounts.

## Installation

To install KubeKiller, you need to have Python 3.6 or higher. Follow these steps:

```bash
git clone https://github.com/BlackD0C/kubekiller.git
cd kubekiller
python KubeKillerBeta-0.8.py

# FiveM XDP Filter for TCP/UDP Protection (Optimized)

This project is an **XDP (eXpress Data Path)** program designed to protect FiveM game servers against a wide range of network attacks. It provides comprehensive **TCP/UDP filtering**, **rate limiting**, **connection tracking**, **SYN flood protection** (with SYN cookies), **blocklist/allowlist** support, **deep packet inspection**, **anomaly detection**, **ML-based threat detection**, and **TCP bypass protection**—all while running at the kernel level for high performance.

## Features

1. **TCP/UDP Filtering**  
   - Filters and inspects UDP/TCP packets that target the configured FiveM server IP/port. Other packets pass through without overhead.

2. **Rate Limiting**  
   - Per-CPU rate limit to cap the packet rate and throttle volumetric DDoS attacks.

3. **Connection Tracking**  
   - Maintains state for both UDP and TCP flows using an LRU hash map, enabling stateful inspection (e.g., blocking out-of-sequence TCP packets).

4. **Dynamic Blocklist/Allowlist**  
   - Instantly drop traffic from blacklisted IPs and short-circuit allowlisted IPs for minimal CPU overhead.

5. **SYN Flood Mitigation**  
   - Protects against SYN floods with SYN cookies, verifying TCP sequence numbers before allowing connections.

6. **Deep Packet Inspection (DPI)**  
   - Matches payload patterns against known malicious signatures in a BPF map, dropping those packets immediately.

7. **Anomaly Detection**  
   - Uses an anomaly score map to identify suspicious behavior and drop out-of-profile traffic.

8. **Machine Learning-Based Threat Detection**  
   - Integrates with an external ML model for adaptive threat detection by looking up flagged flows in a BPF map.

9. **TCP Bypass Protection**  
   - Drops suspicious TCP packets that attempt to bypass the normal 3-way handshake, preventing stealth scanning and other bypass methods.

10. **High Performance**  
    - Runs via XDP at the driver layer, ensuring minimal latency and efficient CPU usage.

---

## How It Works

1. **Initial Parsing**  
   - At the **XDP hook**, the program parses Ethernet and IP headers to validate packet length and determine if the traffic is IPv4.

2. **Blocklist/Allowlist**  
   - Immediately drops packets from blocklisted IPs or passes packets from allowlisted IPs—saving CPU time for known decisions.

3. **Destination Check**  
   - Only applies deeper inspection if the packet targets the configured FiveM IP and port (other traffic is passed).

4. **Protocol-Specific Checks**  
   - **UDP**: Prevents amplification attacks from known amplifier ports, checks DPI signatures, and consults anomaly/ML maps.  
   - **TCP**: Validates SYNs via SYN cookie, ensures the flow is in correct state, performs DPI, and checks anomaly/ML maps.

5. **Rate Limiting**  
   - Maintains a per-CPU timestamp of the last packet sent to the server. Drops if packets arrive too quickly per second.

6. **Connection Tracking**  
   - Uses an LRU map keyed by a “5-tuple” flow key to track recently seen flows. Ensures TCP packets follow legitimate handshake sequences.

---

## Installation Guide

### 1. Prerequisites

- **Kernel with XDP Support**  
  A kernel version **4.18+** is recommended with `iproute2` that supports XDP.

- **BPF Compiler (clang, llvm)**  
  Install `clang` and `llvm` to compile the BPF program.

- **iproute2**  
  Required to attach/detach the XDP program.

  ```bash
  sudo apt-get update
  sudo apt-get install clang llvm libelf-dev iproute2
```

4. **libbpf**:
   - You will also need the libbpf library to handle BPF map interactions.
   ```bash
   sudo apt-get install libbpf-dev
   ```

5. **Python**:
   - Install Python and necessary libraries for training the machine learning model.
   ```bash
   sudo apt-get install python3 python3-pip
   pip3 install scikit-learn numpy pandas
   ```

### Building and Loading the XDP Filter

1. Clone the Repository:
   ```bash
   git clone https://github.com/McLovinIt101/FiveM-XDP-Filter-for-TCP-UDP-Protection.git
   cd FiveM-XDP-Filter-for-TCP-UDP-Protection
   ```

2. Compile the XDP Program:
   - You can compile the XDP filter using clang and llvm. Ensure you target the BPF architecture.
   ```bash
   clang -O2 -target bpf -c fivem_xdp.c -o fivem_xdp.o
   ```

3. Load the XDP Program:
   - Use the ip utility to attach the XDP program to a network interface (replace eth0 with the appropriate network interface on your machine).
   ```bash
   sudo ip link set dev eth0 xdp obj fivem_xdp.o sec xdp_program
   ```
   - This will load the XDP program and start filtering packets on the specified interface.

4. Verifying XDP Program Status:
   - You can verify that the XDP program is successfully attached using:
   ```bash
   ip -details link show dev eth0
   ```
   - Look for the xdp section in the output to confirm that the program is running.

### Managing the Blocklist and Allowlist

The blocklist and allowlist are managed through BPF maps that can be accessed from user space. You can dynamically add or remove IP addresses from these lists using tools like bpftool.

1. Adding IP to Blocklist:
   ```bash
   bpftool map update id <map_id> key <ip_address_in_hex> value 1
   ```

2. Adding IP to Allowlist:
   ```bash
   bpftool map update id <map_id> key <ip_address_in_hex> value 1
   ```

3. Deleting IP from Blocklist/Allowlist:
   ```bash
   bpftool map delete id <map_id> key <ip_address_in_hex>
   ```

   - To find the map ID, run:
   ```bash
   bpftool map show
   ```

### Unloading the XDP Program

To unload the XDP program from the interface, run:
```bash
sudo ip link set dev eth0 xdp off
```
This will remove the XDP program from the specified interface.

## Configuration

- **FIVEM_SERVER_IP**: The IP address of your FiveM server (default is 127.0.0.1 for local testing).
- **FIVEM_SERVER_PORT**: The UDP and TCP port number your FiveM server uses (default is 30120).
- **MAX_PACKET_RATE**: The maximum number of packets per second allowed from each connection (default is 13000).
- **BLOCKED_IP_LIST_MAX**: The maximum number of entries in the blocklist/allowlist (default is 128).

You can modify these parameters directly in the fivem_xdp.c file and recompile the program.

## Training and Using the Machine Learning Model

### Training the Model

1. **Collect Data**:
   - Collect normal and attack traffic data. Save the data in CSV format with appropriate labels.

2. **Train the Model**:
   - Use the following Python script to train a machine learning model using scikit-learn:

   ```python
   import pandas as pd
   from sklearn.model_selection import train_test_split
   from sklearn.ensemble import RandomForestClassifier
   from sklearn.metrics import accuracy_score
   import joblib

   # Load data
   data = pd.read_csv('traffic_data.csv')
   X = data.drop('label', axis=1)
   y = data['label']

   # Split data into training and testing sets
   X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

   # Train the model
   model = RandomForestClassifier(n_estimators=100, random_state=42)
   model.fit(X_train, y_train)

   # Evaluate the model
   y_pred = model.predict(X_test)
   print(f'Accuracy: {accuracy_score(y_test, y_pred)}')

   # Save the model
   joblib.dump(model, 'ml_model.joblib')
   ```

3. **Deploy the Model**:
   - Convert the trained model to a format that can be used in the XDP program. This may involve exporting the model to a C header file or using a custom format.

### Using the Model in the XDP Program

1. **Load the Model**:
   - Load the trained model into the XDP program. This may involve reading the model from a file or embedding it directly in the code.

      #### Embedding the Model Directly in the Code
   - Convert the trained model into a C array or a similar format that can be included in the XDP program.
   - For example, if the model is a decision tree, you can convert it into a series of if-else statements or a lookup table.

   ```c
   // Example of embedding a simple decision tree model
   int predict_threat(__u64 flow_key) {
       // Example decision tree logic
       if (flow_key < 1000) {
           return 0;  // Not a threat
       } else if (flow_key < 2000) {
           return 1;  // Threat
       } else {
           return 0;  // Not a threat
       }
   }
   ```

2. **Feature Extraction**:
   - Extract features from incoming packets and use the model to predict whether the packet is a threat.

3. **Threat Detection**:
   - Use the model's predictions to drop packets flagged as threats.

## Debugging

You can use the bpf_trace_printk() function in the XDP program to print debug messages to the kernel log. This is useful for debugging packet flows and understanding how your filter is performing.

To view the kernel log:
```bash
sudo dmesg | tail
```

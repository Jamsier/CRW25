# CRW-25

1. clone the repo
    ```bash
    git clone https://github.com/Jamsier/CRW25.git
    cd CRW25
    ```
2. Pull the images
    ```bash
    cd oai-env
    docker compose pull

    cd oai-env/rfsim-cu-du-split
    docker compose pull
    ```
3. Run the OAI-CN
    ```bash
    cd oai-env
    ./run-cn.sh
    ```
4. RUN the OAI-CU and CU's agents
      ```bash
      cd rfsim-cu-du-split
      ./run-cu-with-agents.sh
      ```
5. RUN the OAI-DU and OAI-NR-UEs
    ```bash
    ./run-du-ues.sh
    ```


### Description
1. `cu-agent/output.json`: Record the currently connected UE
2. `near-rt-ric/malicious_ip.json`: Record suspicious IP addresses predicted by the model
# CRW-25

### How to run
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
- In `./cu-agent`
    1. `ue_list.json`: Records the currently connected UE dict. (Change at any time)
    2. `ip_blacklist.json`: Records the latest prediction results from xApp, which is a list of suspicious IP addresses. (Change at any time)
    3. `imsi_blacklist.json`: Records a set of suspicious IMSI lists, which are derived from `ue_list.json` and `ip_blacklist.json`. (Append only)
- In `./near-rt-ric`
    1. `malicious_ip.json`: Records suspicious IP addresses predicted by the model. (Change at each inferences)

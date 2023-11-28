# Port Scanner

Port Scanner (Shodan-BinaryEdge) with ELK Logging (Currently ElasticSearch and Kibana methods, Filebeat method in dev)

## Prerequisites

Before you begin, ensure you have met the following requirements:
- [SMAP](https://github.com/s0md3v/Smap) - SMAP (shodan and nmap scanner).

## Installation

To install and set up this project, follow these steps:

1. Step 1: Clone the repository.
    ```sh
    git clone https://github.com/Trustable-Lab/Port-scanner.git
    ```
   
2. Step 2: Navigate to the project directory.
    ```sh
    cd Port-scanner/
    ```
   
3. Step 3: Install dependencies.
    ```sh
    pip3 install -r requirements.txt
    ```
   
## Usage

How to use this project:

```sh
./run.sh -f hosts_list.txt -r 1-MAX_PORT
```

Access Kibana at http://yourserver:5601/ and login with creds.
Newly and updated logs should be availble under ``Management > Stack Mangement > Index Mangement``.



### Cronjob

Now to scheduel the script to run every 7 day we need to make this happen manually using ``crontab``


```sh
crontab -e
(HERE YOU WILL BE PROMPTED WHAT EDITOR YOU WANT TO USE, YOU USE ANY EDITOR.)
0 0 */7 * * /path/to/your/project/directory/run.sh -f hosts_list.txt -r 1-MAX_PORT
```


## Common Issues

If ``magic.py`` throws a jsonDecodeError try downgrading to a previous version of json python module.



import asyncio
import asyncssh
from aiohttp import web
import json
import os
import time


NODE_LIST = ['ip1', 'ip2']
PASSWORD = "password"  
USERNAME = 'root'
KNOWN_HOSTS = None  
BBAUTO_PATH = "/bbauto/"
ATTACKS_FILE = 'attacks.json'
SSH_TIMEOUT = 10



def load_attacks():
    if os.path.exists(ATTACKS_FILE):
        with open(ATTACKS_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_attacks(attacks):
    with open(ATTACKS_FILE, 'w') as f:
        json.dump(attacks, f)

ATTACKS = load_attacks()




bandwidth_data = {
    'timestamps': [],
    'upload': [],
    'download': []
}

async def get_or_create_connection(ip_address, username, password, connections):
    """Get or create an SSH connection to a given IP address."""
    if ip_address not in connections:
        connections[ip_address] = await asyncssh.connect(ip_address, username=username, password=password, known_hosts=KNOWN_HOSTS)
        print(connections)
    return connections[ip_address]

async def check_and_create_directories(connection):
    """Check and create necessary directories on the remote server."""
    commands = [
        f"mkdir -p {BBAUTO_PATH}",
        f"mkdir -p {BBAUTO_PATH}scilla",
        f"mkdir -p {BBAUTO_PATH}nuclei",
        f"mkdir -p {BBAUTO_PATH}subfinder",
        f"mkdir -p {BBAUTO_PATH}assetfinder",
        f"mkdir -p {BBAUTO_PATH}gau"
    ]
    
    for cmd in commands:
        await connection.run(cmd, check=True)
    print("Sistem Hazir Devam Edebilirsin.")

async def initialize_servers():
    """Initialize all servers in the node list."""
    connections = {}
    for node in NODE_LIST:
        conn = await get_or_create_connection(node, USERNAME, PASSWORD, connections)
        await check_and_create_directories(conn)

async def get_cpu_ram_and_bandwidth_usage(connection):
    """Get CPU, RAM, and bandwidth usage for a given SSH connection."""
    cpu_cmd = "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'"
    ram_cmd = "free | grep Mem | awk '{print $3/$2 * 100.0}'"
    int_cmd = "ifstat -i eth0 1 1 | tail -n 1 | awk '{print $1/1000,$2/1000}'"

    async with connection as conn:
        cpu_usage = float((await conn.run(cpu_cmd, check=True)).stdout.strip())
        ram_usage = float((await conn.run(ram_cmd, check=True)).stdout.strip())
        int_result = await conn.run(int_cmd, check=True)
        bandwidth_usage = int_result.stdout.strip().split()

        if len(bandwidth_usage) >= 2:
            
            download, upload = map(float, bandwidth_usage)
            print("download: "+str(download)+"     Upload: "+ str(upload))
        else:
            download, upload = 0.0, 0.0

        if download < 0.01:
            download = 0.0
        if upload < 0.01:
            upload = 0.0

    return cpu_usage, ram_usage, download, upload

async def server_data(request):
    """Handles requests for server data."""
    connections = {}
    server_list = [{"ip_address": node, "username": USERNAME, "password": PASSWORD} for node in NODE_LIST]
    tasks = [get_server_data(server, connections) for server in server_list]
    results = await asyncio.gather(*tasks)

   
    timestamp = time.time()
    total_upload = sum(result['upload'] for result in results)
    total_download = sum(result['download'] for result in results)
    bandwidth_data['timestamps'].append(timestamp)
    bandwidth_data['upload'].append(total_upload)
    bandwidth_data['download'].append(total_download)

    return web.Response(text=json.dumps(results), content_type='application/json')

async def get_server_data(server, connections):
    """Get data for a specific server."""
    connection = await get_or_create_connection(server["ip_address"], server["username"], server["password"], connections)
    cpu_usage, ram_usage, download, upload = await get_cpu_ram_and_bandwidth_usage(connection)
    return {
        'ip_address': server["ip_address"],
        'cpu_usage': cpu_usage,
        'ram_usage': ram_usage,
        'download': download,
        'upload': upload
    }

async def perform_attack(request):
    data = await request.json()
    attack_id = data.get('attack_id')
    domain = data.get('domain')
    if not attack_id or not domain:
        return web.Response(text="Attack ID and domain must be provided", status=400)
    if attack_id not in ATTACKS:
        return web.Response(text="Invalid attack ID", status=400)

    command = ATTACKS[attack_id]['command'].format(domain=domain)
    tasks = [start_operation(node, command) for node in NODE_LIST]
    await asyncio.gather(*tasks)

    return web.Response(text=f"{ATTACKS[attack_id]['name']} attack started for domain: {domain}")

async def start_operation(node, command):
    """Start a specific operation on a node."""
    async with asyncssh.connect(node, username=USERNAME, password=PASSWORD, known_hosts=KNOWN_HOSTS) as conn:
        await conn.run(command, check=True)

async def get_operation_results(request):
    """Returns the results of operations performed on a specific domain."""
    domain = request.match_info['domain']
    tasks = [fetch_results(node, domain) for node in NODE_LIST]
    results = await asyncio.gather(*tasks)
    combined_results = [result for sublist in results for result in sublist]  
    return web.Response(text=json.dumps(combined_results), content_type='application/json')

async def fetch_results(node, domain):
    """Fetches the operation results from a node."""
    try:
        async with asyncssh.connect(node, username=USERNAME, password=PASSWORD, known_hosts=KNOWN_HOSTS) as conn:
            command = f'cat /bbauto/*/{domain}'
            result = await conn.run(command, check=False) 
            if result.exit_status == 0:
                return [{'node': node, 'content': result.stdout}]
            else:
                return [{'node': node, 'error': 'No results found or error occurred'}]
    except (asyncssh.Error, OSError) as e:
        return [{'node': node, 'error': f'SSH connection error: {e}'}]

async def fetch_domains(node):
    """Fetches the list of domains from a node."""
    try:
        async with asyncssh.connect(node, username=USERNAME, password=PASSWORD, known_hosts=KNOWN_HOSTS) as conn:
            result = await conn.run('ls /bbauto/*/*|cut -d "/" -f 4', check=True)
            domains = result.stdout.splitlines()
        return domains
    except (asyncssh.Error, OSError) as e:
        print(f"SSH connection error: {e}")
        return []

async def list_scanned_domains(request):
    """Lists all scanned domains across all nodes."""
    tasks = [fetch_domains(node) for node in NODE_LIST]
    results = await asyncio.gather(*tasks)
    all_domains = {domain for sublist in results for domain in sublist}
    return web.Response(text=json.dumps(list(all_domains)), content_type='application/json')

async def list_attacks(request):
    """Lists all available attacks."""
    return web.Response(text=json.dumps([{ 'id': key, 'name': value['name']} for key, value in ATTACKS.items()]), content_type='application/json')

async def index(request):
    """Serve the main HTML page."""
    return web.FileResponse('index.html')

def setup_routes(app):
    """Setup routes for the web application."""
    app.router.add_get('/data', server_data)
    app.router.add_get('/operations/result/{domain}', get_operation_results)
    app.router.add_get('/operations/resultslist', list_scanned_domains)
    app.router.add_get('/attacks', list_attacks)
    app.router.add_post('/attack', perform_attack)
    app.router.add_get('/', index)

def main():
    """Main function to start the web application."""
    app = web.Application()
    setup_routes(app)
    asyncio.run(initialize_servers())
    web.run_app(app, port=8080)

if __name__ == '__main__':
    main()

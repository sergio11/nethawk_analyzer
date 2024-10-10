from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

class SMBScanner:
    def __init__(self, timeout=1):
        """Initialize the SMB scanner with a timeout."""
        self.timeout = timeout

    def discover_public_shares(self, ip):
        """Discover and list public SMB shares on a host."""
        user_name = ""
        password = ""
        local_machine_name = "laptop"
        server_machine_name = ip

        share_details = {}
        try:
            conn = SMBConnection(user_name, password, local_machine_name, server_machine_name, use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(ip, 445, timeout=self.timeout):
                for share in conn.listShares(timeout=10):
                    if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                        try:
                            files = conn.listPath(share.name, '/')
                            share_details[share.name] = [file.filename for file in files if file.filename not in ['.', '..']]
                        except Exception as e:
                            print(f"Could not access {share.name} on {ip}: {e}")
                conn.close()
        except Exception as e:
            print(f"Could not retrieve shares from {ip}: {e}")
        return share_details

    def scan_smb_shares(self, active_hosts):
        """Scan SMB shares on a list of active hosts."""
        smb_shares = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.discover_public_shares, ip): ip for ip in tqdm(active_hosts, desc="Discovering SMB Shares")}
            for future in futures:
                shares = future.result()
                if shares:
                    smb_shares[future.result()] = shares
        return smb_shares

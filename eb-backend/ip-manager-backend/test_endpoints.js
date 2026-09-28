(async () => {
  const login = await fetch('http://127.0.0.1/api/ip-manager/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({username: 'admin', password: 'SYSAD@2025@A'})
  }).then(r => r.json());
  
  const routes = ['real-ip-subnets', 'internal-ip-subnets', 'vlans-v2', 'wan-v2', 'tunnels-v2', 'vpns', 'dsp-v2', 'credentials-v2'];
  
  console.log("\n--- RUNNING TESTS ---");
  for (const r of routes) {
    const res = await fetch(`http://127.0.0.1/api/ip-manager/${r}`, {
      headers: { 'Authorization': 'Bearer ' + login.token }
    }).then(x => x.json());
    
    console.log(r.padEnd(25), res.ok ? '✅ OK' : '❌ FAIL - ' + JSON.stringify(res));
  }
  console.log("---------------------\n");
})();

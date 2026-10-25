// scripts/test-warning-params.js
import { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';

const p = spawn('C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', [
  '--remote-debugging-port=9222',
  `--user-data-dir=${path.join(os.tmpdir(), 'edge_warning_test')}`,
  '--load-extension=C:\\Dev\\LinkProtection\\browser-extension',
  'about:blank'
]);

setTimeout(async () => {
  const targets = await (await fetch('http://127.0.0.1:9222/json')).json();
  const extTarget = targets.find(t => t.url && t.url.endsWith('/background.js'));
  const extId = extTarget ? extTarget.url.match(/chrome-extension:\/\/([a-z0-9]+)\//)[1] : '';
  console.log('Discovered Ext ID:', extId);
  
  const testUrl = `chrome-extension://${extId}/pages/warning.html?url=${encodeURIComponent('https://paypal.example/login')}&level=HIGH&score=80&explanation=TestExpl&titles=${encodeURIComponent(JSON.stringify(['Phishing Link']))}`;
  console.log('Opening test warning URL:', testUrl);

  const tabRes = await fetch(`http://127.0.0.1:9222/json/new?${encodeURIComponent(testUrl)}`, { method: 'PUT' });
  const tab = await tabRes.json();

  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.method === 'Runtime.consoleAPICalled') {
      console.log('[Console]', data.params.type, data.params.args);
    } else if (data.method === 'Runtime.exceptionThrown') {
      console.error('[Exception]', data.params.exceptionDetails);
    } else if (data.id === 1) {
      console.log('Full data.result:', JSON.stringify(data.result, null, 2));
      p.kill('SIGTERM');
    }
  };
  ws.onopen = async () => {
    ws.send(JSON.stringify({ id: 99, method: 'Runtime.enable' }));
    await new Promise(r => setTimeout(r, 1500));
    ws.send(JSON.stringify({
      id: 1,
      method: 'Runtime.evaluate',
      params: {
        expression: `(() => {
          return {
            container: !!document.getElementById('container'),
            badge: !!document.getElementById('risk-badge'),
            titleText: !!document.getElementById('title-text'),
            targetUrlEl: !!document.getElementById('target-url'),
            explanationText: !!document.getElementById('explanation-text'),
            indicatorsContainer: !!document.getElementById('indicators-container'),
            indicatorsList: !!document.getElementById('indicators-list'),
            recommendationText: !!document.getElementById('recommendation-text'),
            backBtn: !!document.getElementById('back-btn'),
            continueBtn: !!document.getElementById('continue-btn')
          };
        })()`,
        returnByValue: true
      }
    }));
  };
}, 2000);

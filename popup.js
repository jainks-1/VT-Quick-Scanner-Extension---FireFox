// On popup load, handle initialization and pending right-click scans
document.addEventListener('DOMContentLoaded', async () => {
  const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

  // 1. Load saved API key if it exists
  browserAPI.storage.local.get(['vtApiKey'], (result) => {
    if (result.vtApiKey) {
      document.getElementById('apiKeyInput').value = result.vtApiKey;
    }
  });

  // 2. Check if the user arrived here via a right-click menu action
  browserAPI.storage.local.get(['pendingScanUrl'], (result) => {
    if (result.pendingScanUrl) {
      const inputField = document.getElementById('urlInput');
      inputField.value = result.pendingScanUrl;
      browserAPI.storage.local.remove(['pendingScanUrl']);
      document.getElementById('checkBtn').click();
    }
  });
});

// Save the API key to local browser storage
document.getElementById('saveKeyBtn').addEventListener('click', () => {
  const browserAPI = typeof browser !== 'undefined' ? browser : chrome;
  const keyInput = document.getElementById('apiKeyInput').value.trim();
  browserAPI.storage.local.set({ vtApiKey: keyInput }, () => {
    alert('API Key saved successfully!');
  });
});

// Main search function
document.getElementById('checkBtn').addEventListener('click', async () => {
  const browserAPI = typeof browser !== 'undefined' ? browser : chrome;
  const urlInput = document.getElementById('urlInput').value.trim();
  const resultDiv = document.getElementById('result');
  
  if (!urlInput) {
    alert('Please enter a query (URL, Hash, Domain, or IP) first.');
    return;
  }

  const storage = await browserAPI.storage.local.get(['vtApiKey']);
  const activeApiKey = storage.vtApiKey;

  if (!activeApiKey) {
    alert('Error: Please enter and save your VirusTotal API Key at the bottom first!');
    return;
  }

  resultDiv.style.display = 'block';
  resultDiv.className = 'loading';
  resultDiv.innerText = 'Searching VirusTotal intelligence...';

  try {
    // Universal v3 generic search endpoint
    const encodedQuery = encodeURIComponent(urlInput);
    const response = await fetch(`https://www.virustotal.com/api/v3/search?query=${encodedQuery}`, {
      method: 'GET',
      headers: {
        'x-apikey': activeApiKey,
        'accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status}. Check your API key limits.`);
    }

    const data = await response.json();

    // The search endpoint returns an array of objects inside "data"
    if (!data.data || data.data.length === 0) {
      resultDiv.className = 'unsafe';
      resultDiv.innerText = 'No records found for this query on VirusTotal.';
      return;
    }

    // Extract the primary matching object item found
    const matchItem = data.data[0];
    const itemType = matchItem.type; // 'file', 'url', 'domain', or 'ip_address'
    const stats = matchItem.attributes.last_analysis_stats;
    const itemId = matchItem.id;

    displayResults(stats, resultDiv, itemType, itemId);

  } catch (error) {
    resultDiv.className = 'unsafe';
    resultDiv.innerText = `Error: ${error.message}`;
  }
});

function displayResults(stats, element, type, id) {
  const browserAPI = typeof browser !== 'undefined' ? browser : chrome;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  
  if (malicious > 0 || suspicious > 0) {
    element.className = 'unsafe';
    element.innerHTML = `⚠️ <b>Threat Detected! (${type.replace('_', ' ')})</b><br> Flagged by ${malicious} malicious and ${suspicious} suspicious security engines.`;
  } else {
    element.className = 'safe';
    element.innerHTML = `✅ <b>Looks Clean! (${type.replace('_', ' ')})</b><br> Checked across security engines and no threats were detected.`;
  }

  // Construct the correct GUI report URL depending on the asset type discovered
  let guiTypePath = 'search';
  if (type === 'file') guiTypePath = 'file';
  if (type === 'url') guiTypePath = 'url';
  if (type === 'domain') guiTypePath = 'domain';
  if (type === 'ip_address') guiTypePath = 'ip-address';

  const reportUrl = `https://www.virustotal.com/gui/${guiTypePath}/${id}`;
  
  const reportBtn = document.createElement('button');
  reportBtn.innerText = 'View Full Report';
  reportBtn.className = 'report-button';
  
  reportBtn.onclick = () => {
    browserAPI.tabs.create({ url: reportUrl });
  };

  element.appendChild(document.createElement('br'));
  element.appendChild(reportBtn);
}
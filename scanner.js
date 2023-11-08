const fs = require('fs');
const axios = require('axios');
const chokidar = require('chokidar');

const logFilePath = '/var/log/suricata/eve.json'; // Replace with your Suricata eve.json file path
const discordWebhookUrl = ''; // Replace with your Discord webhook URL
const virusTotalApiKey = ''; // Replace with your VirusTotal API Key

let scannedIPs = {};

// Load scannedIPs data from a JSON file if it exists
if (fs.existsSync('scannedIPs.json')) {
  scannedIPs = JSON.parse(fs.readFileSync('scannedIPs.json', 'utf8'));
}

// Function to save scannedIPs to a JSON file
function saveScannedIPs() {
  fs.writeFileSync('scannedIPs.json', JSON.stringify(scannedIPs), 'utf8');
}

// Function to check IP against VirusTotal
async function checkIp(ip, srcType) {
  const url = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;

  try {
    const response = await axios.get(url, {
      headers: { 'x-apikey': virusTotalApiKey },
    });

    const info = response.data;

    let malicious = false;
    for (const key in info.data.attributes.last_analysis_stats) {
      if (key !== 'harmless' && key !== 'undetected') {
        if (info.data.attributes.last_analysis_stats[key] > 0) {
          malicious = true;
          break;
        }
      }
    }

    if (malicious) {
      await sendDiscordAlert(ip, srcType);
    }
  } catch (error) {
    console.log(error);
  }
}

// Function to send a Discord alert
async function sendDiscordAlert(ip, srcType) {
  const message = `Warning! A potentially malicious IP (${ip}) has triggered an ${srcType}.`;

  return new Promise((resolve, reject) => {
    setTimeout(() => {
      axios.post(discordWebhookUrl, {
        content: message
      })
        .then(response => {
          console.log('Message sent successfully:', response.data);
          resolve();
        })
        .catch(error => {
          console.error('Error sending message:', error);
          reject(error);
        });
    }, 5000); // 5000 milliseconds = 5 seconds
  });
}

// Watch the Suricata log file for changes
chokidar.watch(logFilePath).on('change', () => {
  fs.readFile(logFilePath, 'utf8', async (err, data) => {
    if (err) {
      console.error(err);
      return;
    }

    const logs = data.split('\n');

    for (const log of logs) {
      try {
        const parsedLog = JSON.parse(log);

        if (parsedLog.event_type === 'anomaly' || parsedLog.event_type === 'alert') {
          const srcIp = parsedLog.src_ip;
          const srcType = parsedLog.event_type;

          if (!scannedIPs[srcIp]) {
            scannedIPs[srcIp] = true;
            checkIp(srcIp, srcType);
          }
        }
      } catch (error) {
        // Ignore errors from parsing non-JSON lines
      }
    }

    // Save the scannedIPs data to the JSON file after processing
    saveScannedIPs();
  });
});

// Handle exit events (e.g., Ctrl+C) to save scannedIPs data before exiting
process.on('exit', () => {
  saveScannedIPs();
});
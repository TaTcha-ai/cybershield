// server.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const GOOGLE_API_KEY = 'AIzaSyDbJxlugpagyRtnqvU2556Hj1vFZg3w1DU';
const VT_API_KEY = 'b85f844665e4e73ae3b7a2140e46b2ebbf6188e1d7458561514e09bf07788f20';

app.post('/check-url', async (req, res) => {
    const url = req.body.url;

    if (!url) return res.status(400).json({ error: "Missing URL" });

    try {
        const safeBrowsingBody = {
            client: {
                clientId: "cybershield",
                clientVersion: "1.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        // Google Safe Browsing
        const safeRes = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(safeBrowsingBody)
        });

        const safeData = await safeRes.json();

        // VirusTotal - Submit
        const vtSubmit = await fetch(`https://www.virustotal.com/api/v3/urls`, {
            method: 'POST',
            headers: {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const vtSubmitData = await vtSubmit.json();
        const analysisId = vtSubmitData.data.id;

        // Wait 4 seconds
        await new Promise(resolve => setTimeout(resolve, 4000));

        // VirusTotal - Report
        const vtReportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': VT_API_KEY }
        });

        const vtReportData = await vtReportRes.json();
        const stats = vtReportData.data.attributes.stats;

        res.json({
            safeBrowsing: safeData,
            virusTotalStats: stats
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

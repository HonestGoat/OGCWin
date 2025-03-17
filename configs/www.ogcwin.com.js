addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const userAgent = request.headers.get("User-Agent") || "";

    // Block requests with no User-Agent (suspicious bots)
    if (!userAgent) {
        return new Response("Access Denied: Missing User-Agent", { status: 403 });
    }

    // Allow only known browsers
    const isBrowser = /Mozilla|Chrome|Safari|Edge|Firefox|Opera|Brave|Vivaldi|Chromium|SamsungBrowser|YaBrowser|UCBrowser|QQBrowser/i.test(userAgent);
    
    // Block all other unknown requests (e.g., scripts, bots, curl, etc.)
    if (!isBrowser) {
        return new Response("Blocked: Unauthorized Request", { status: 403 });
    }

    // Generate the HTML response
    return new Response(generateHTML(), {
        headers: { "Content-Type": "text/html; charset=UTF-8" },
    });
}

function generateHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OGCWin – The Ultimate Windows Utility</title>
    <style>
        /* Dark mode styling */
        body {
            font-family: Arial, sans-serif;
            background-color: #121212;
            color: #ffffff;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }

        h1, h2, h3 {
            color: #ffcc00; /* Highlighted headers */
        }

        a {
            color: #1e90ff;
        }

        pre {
            background-color: #333;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 14px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .copy-box {
            background-color: #222;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border: 1px solid #444;
        }

        .copy-box input {
            background: transparent;
            border: none;
            color: #fff;
            width: 100%;
            outline: none;
            font-size: 14px;
        }

        .copy-box button {
            background: #ffcc00;
            border: none;
            padding: 5px 10px;
            cursor: pointer;
            font-size: 14px;
            border-radius: 3px;
        }
    </style>
</head>
<body>

    <h1>🛠️ OGCWin – The Ultimate Windows Utility for Windows Users and Gamers 🎮</h1>

    <p>OGCWin is still being actively developed. Right now, the launcher is fully functional, and the Windows 10 & 11 new installation wizards are being optimized. More features and improvements are on the way! 🚀</p>

    <p>OGC Windows Utility is an all-in-one tool designed to help Windows users debloat, optimize, troubleshoot, repair, and enhance their system with ease. Built from decades of experience as a technician, this utility brings together my best scripts into an intuitive and user-friendly package.</p>

    <p>Originally developed for the <strong>Oceanic Gaming Community Discord</strong>, OGCWin is now available for everyone who wants to improve their Windows experience effortlessly.</p>

    <h2>🔥 Features</h2>
    <ul>
        <li>✅ <strong>Debloat Windows</strong> – Remove unnecessary bloatware for a leaner, faster system.</li>
        <li>✅ <strong>Privacy Enhancements</strong> – Disable Windows telemetry, tracking, and data collection.</li>
        <li>✅ <strong>Gaming Optimizations</strong> – Tune Windows settings for improved gaming performance.</li>
        <li>✅ <strong>Automated Software Installation</strong> – Install essential apps, game launchers, and utilities with one click.</li>
        <li>✅ <strong>System Troubleshooting & Repair</strong> – Diagnose and fix common Windows issues automatically.</li>
        <li>✅ <strong>New PC Setup Wizard</strong> – A step-by-step guide to optimizing a new PC or fresh Windows installation.</li>
        <li>✅ <strong>Easy to Use</strong> – No tech knowledge required—just run the tool and follow the prompts.</li>
    </ul>

    <h2>🚀 Installation & First-Time Setup</h2>
    <p>To install and run OGCWin for the first time, right-click on the Start button and open <strong>PowerShell (Admin)</strong> in Windows 10 or <strong>Terminal (Admin)</strong> in Windows 11 and run the following command:</p>

    <!-- Copyable Command Box -->
    <div class="copy-box">
        <input type="text" id="copyCommand" value="irm https://get.ogcwin.com | iex" readonly>
        <button onclick="copyToClipboard()">Copy</button>
    </div>

    <script>
        function copyToClipboard() {
            var copyText = document.getElementById("copyCommand");
            copyText.select();
            copyText.setSelectionRange(0, 99999); // For mobile devices
            document.execCommand("copy");
            alert("Command copied to clipboard!");
        }
    </script>

    <p>🔹 <strong>What Happens Next?</strong> OGCWin will automatically download and set up everything needed. A shortcut will be created on your Desktop, allowing you to launch the utility anytime with a double-click. After the first run, simply use the shortcut to start OGCWin. No need to re-enter the command.</p>

    <h3>🎯 How It Works</h3>
    <ol>
        <li>Launch OGCWin using the desktop shortcut or PowerShell command.</li>
        <li>Choose between Wizard Mode or Utility Mode based on your needs.</li>
        <li>Follow the on-screen prompts to apply tweaks, install apps, or fix system issues.</li>
    </ol>

    <h3>📥 Supported Windows Versions</h3>
    <ul>
        <li>✅ Windows 10 Home & Pro</li>
        <li>✅ Windows 11 Home & Pro</li>
    </ul>

    <h3>🔗 Join the Community!</h3>
    <p>Need help, have suggestions, or just want to chat with other gamers? Join the <a href="https://discord.com/channels/934947083566329896/939073656406032414" target="_blank">Oceanic Gaming Community Discord</a>!</p>

    <p>💡 Want to contribute or report an issue? Open a GitHub issue or join the Discord to discuss!</p>

    <h3>⭐ Support the Project</h3>
    <p>If you find OGCWin useful, consider starring ⭐ this repository and sharing it with others!</p>

    <p>Happy gaming! 🎮🔥</p>

</body>
</html>`;
}

addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const userAgent = request.headers.get("User-Agent") || "";

    // Check if the request is from a browser
    const isBrowser = /Mozilla|Chrome|Safari|Edge|Firefox|Opera|Brave|Vivaldi|Chromium|SamsungBrowser|YaBrowser|UCBrowser|QQBrowser|MSIE|Trident|Coast|Falkon|Epiphany|Midori|Konqueror|Seamonkey|Waterfox|PaleMoon|Iceweasel|IceCat|Basilisk/i.test(userAgent);

    // Check if the request is from PowerShell or another CLI tool
    const isCLI = /WindowsPowerShell|curl|wget|Invoke-WebRequest|Invoke-RestMethod|PostmanRuntime/i.test(userAgent);

    if (isBrowser && !isCLI) {
        // Serve the installer webpage for browsers
        return new Response(
            `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>OGC Windows Utility - Installer</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        background-color: #f9f9f9;
                        margin: 0;
                        padding: 20px;
                        color: #333;
                    }
                    .container {
                        max-width: 600px;
                        margin: 50px auto;
                        background: #fff;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #0078D4;
                        font-size: 26px;
                    }
                    p {
                        font-size: 18px;
                    }
                    .code-container {
                        display: flex;
                        align-items: center;
                        background: #f4f4f4;
                        padding: 10px;
                        border-radius: 5px;
                        font-size: 16px;
                        font-family: monospace;
                        justify-content: space-between;
                        overflow-x: auto;
                        white-space: nowrap;
                    }
                    .code {
                        flex: 1;
                        margin: 0;
                        padding: 5px;
                        user-select: all;
                    }
                    .copy-btn {
                        background: #0078D4;
                        color: white;
                        border: none;
                        padding: 8px 12px;
                        cursor: pointer;
                        border-radius: 5px;
                        margin-left: 10px;
                        transition: background 0.3s;
                    }
                    .copy-btn:hover {
                        background: #005ea6;
                    }
                    .footer {
                        margin-top: 20px;
                        font-size: 14px;
                        color: #666;
                    }

                    /* 🌙 Dark Mode Support */
                    @media (prefers-color-scheme: dark) {
                        body {
                            background-color: #121212;
                            color: #e0e0e0;
                        }
                        .container {
                            background: #1e1e1e;
                            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
                        }
                        .code-container {
                            background: #333;
                            color: #e0e0e0;
                        }
                        .copy-btn {
                            background: #1e88e5;
                        }
                        .copy-btn:hover {
                            background: #1565c0;
                        }
                        .footer {
                            color: #bbb;
                        }
                    }
                </style>
                <script>
                    function copyToClipboard() {
                        var copyText = document.getElementById("install-command").innerText;
                        navigator.clipboard.writeText(copyText).then(function() {
                            alert("Command copied to clipboard!");
                        }).catch(function(err) {
                            console.error("Failed to copy: ", err);
                        });
                    }
                </script>
            </head>
            <body>
                <div class="container">
                    <h1>OGC Windows Utility</h1>
                    <p>To install OGCWin, right-click on the Start button and open <strong>PowerShell (Admin)</strong> for Windows 10 or <strong>Terminal (Admin)</strong> for Windows 11.
                    Click <b>Yes</b> when prompted, then enter the following command and press the <strong>Enter</strong> key:</p>
                    <div class="code-container">
                        <span id="install-command" class="code">irm https://get.ogcwin.com | iex</span>
                        <button class="copy-btn" onclick="copyToClipboard()">Copy</button>
                    </div>
                    <p>This will automatically download and launch the OGC Windows Utility.</p>
                    <p class="footer">Need help? Visit our <a href="https://discord.com/channels/934947083566329896/939073656406032414">Discord</a> for support.</p>
                </div>
            </body>
            </html>`, 
            {
                headers: { "Content-Type": "text/html" }
            }
        );
    } else {
        // This ensures PowerShell gets the correct script response
        const script = `Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HonestGoat/OGCWin/main/scripts/launch.ps1' -OutFile "$env:TEMP\\launch.ps1"
& "$env:TEMP\\launch.ps1"`;

        return new Response(script, {
            headers: { 
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        });
    }
}

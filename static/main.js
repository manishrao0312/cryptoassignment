const API_URL = "http://127.0.0.1:5000"; // Flask backend

async function encryptMessage() {
    const message = document.getElementById("messageInput").value;
    if (!message) return alert("Please type a message!");

    const response = await fetch(`${API_URL}/encrypt`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ message })
    });

    if (!response.ok) {
        alert("Encryption failed!");
        return;
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);

    document.getElementById("qrContainer").innerHTML = `<img src="${url}" alt="Encrypted QR">`;
}

async function decryptMessage() {
    const payloadText = document.getElementById("payloadInput").value;
    if (!payloadText) return alert("Paste the payload JSON!");

    let payload;
    try {
        payload = JSON.parse(payloadText);
    } catch (e) {
        return alert("Invalid JSON!");
    }

    const response = await fetch(`${API_URL}/decrypt`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ payload })
    });

    const data = await response.json();
    if (data.error) {
        document.getElementById("decryptedContainer").innerText = `Error: ${data.error}`;
    } else {
        document.getElementById("decryptedContainer").innerText = `Decrypted: ${data.message}`;
    }
}

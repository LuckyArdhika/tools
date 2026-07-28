import React, { useState, useEffect } from 'react';
import { Shield, Lock, Unlock, Save, Copy, RefreshCw, Trash2, CheckCircle, Hash, AlertTriangle } from 'lucide-react';

const App = () => {
  const [key, setKey] = useState('');
  const [algorithm, setAlgorithm] = useState('AES-GCM');
  const [encoding, setEncoding] = useState('hex'); 
  const [rawText, setRawText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [status, setStatus] = useState({ message: '', type: '' });
  const [isKeySaved, setIsKeySaved] = useState(false);

  // Memuat kunci dari localStorage saat aplikasi dijalankan
  useEffect(() => {
    const savedKey = localStorage.getItem('default_aes_key');
    if (savedKey) {
      setKey(savedKey);
      setIsKeySaved(true);
    }
  }, []);

  const showStatus = (msg, type = 'info') => {
    setStatus({ message: msg, type });
    setTimeout(() => setStatus({ message: '', type: '' }), 5000);
  };

  const saveKeyToLocal = () => {
    if (!key) {
      showStatus('Key cannot be empty!', 'error');
      return;
    }
    localStorage.setItem('default_aes_key', key);
    setIsKeySaved(true);
    showStatus('Key saved to local storage', 'success');
  };

  const clearSavedKey = () => {
    localStorage.removeItem('default_aes_key');
    setIsKeySaved(false);
    showStatus('Key removed from local storage', 'info');
  };

  const bufferToHex = (buffer) => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const hexToBuffer = (hex) => {
    const cleanHex = hex.trim().replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length % 2 !== 0) throw new Error('Invalid hex length');
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }
    return bytes.buffer;
  };

  const bufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const base64ToBuffer = (base64) => {
    const binaryString = window.atob(base64.trim());
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const getCryptoKey = async (passphrase) => {
    const encoder = new TextEncoder();
    let keyData = encoder.encode(passphrase);
    
    // Node.js crypto dengan aes-256 memerlukan kunci 32-byte.
    // Jika input bukan 32 byte, gunakan SHA-256 hash untuk mendapatkan panjang yang tetap.
    if (keyData.length !== 32) {
      const hash = await window.crypto.subtle.digest('SHA-256', keyData);
      keyData = new Uint8Array(hash);
    }

    return window.crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  };

  const handleEncrypt = async () => {
    try {
      if (!key || !rawText) {
        showStatus('Key and Raw Text are required', 'error');
        return;
      }

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const cryptoKey = await getCryptoKey(key);
      const encoder = new TextEncoder();
      
      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        cryptoKey,
        encoder.encode(rawText)
      );

      // Web Crypto API mengembalikan [Ciphertext][AuthTag (16 byte)]
      const fullBuffer = new Uint8Array(encryptedBuffer);
      const tag = fullBuffer.slice(-16);
      const data = fullBuffer.slice(0, -16);

      let result;
      if (encoding === 'hex') {
        result = `${bufferToHex(iv)}:${bufferToHex(tag)}:${bufferToHex(data)}`;
      } else {
        result = `${bufferToBase64(iv)}:${bufferToBase64(tag)}:${bufferToBase64(data)}`;
      }
      
      setEncryptedText(result);
      showStatus('Encryption successful!', 'success');
    } catch (err) {
      console.error(err);
      showStatus('Encryption failed: ' + err.message, 'error');
    }
  };

  const handleDecrypt = async () => {
    try {
      if (!key || !encryptedText) {
        showStatus('Key and Encrypted Text are required', 'error');
        return;
      }

      const trimmedInput = encryptedText.trim();
      const parts = trimmedInput.split(':').map(p => p.trim());
      
      if (parts.length !== 3) {
        showStatus('Format error: Expected iv:tag:data', 'error');
        return;
      }

      // Validasi panjang karakter HEX sebelum konversi (UX lebih baik)
      if (encoding === 'hex') {
        if (parts[0].length !== 24) {
          showStatus(`IV HEX must be 24 chars (12 bytes). Found: ${parts[0].length}`, 'error');
          return;
        }
        if (parts[1].length !== 32) {
          showStatus(`Tag HEX must be 32 chars (16 bytes). Found: ${parts[1].length}`, 'error');
          return;
        }
      }

      let iv, tag, data;
      try {
        if (encoding === 'hex') {
          iv = new Uint8Array(hexToBuffer(parts[0]));
          tag = new Uint8Array(hexToBuffer(parts[1]));
          data = new Uint8Array(hexToBuffer(parts[2]));
        } else {
          iv = new Uint8Array(base64ToBuffer(parts[0]));
          tag = new Uint8Array(base64ToBuffer(parts[1]));
          data = new Uint8Array(base64ToBuffer(parts[2]));
        }
      } catch (e) {
        showStatus('Decoding error: Invalid ' + encoding.toUpperCase() + ' data format.', 'error');
        return;
      }

      // Validasi ulang panjang byte hasil konversi
      if (iv.length !== 12) {
        showStatus('Internal Error: IV length must be 12 bytes.', 'error');
        return;
      }
      if (tag.length !== 16) {
        showStatus('Internal Error: Tag length must be 16 bytes.', 'error');
        return;
      }

      // Web Crypto API mengharapkan [Ciphertext][AuthTag] sebagai satu buffer untuk dekripsi
      const combined = new Uint8Array(data.length + tag.length);
      combined.set(data);
      combined.set(tag, data.length);

      const cryptoKey = await getCryptoKey(key);
      
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { 
          name: 'AES-GCM', 
          iv: iv, 
          tagLength: 128 
        },
        cryptoKey,
        combined
      );

      const decoder = new TextDecoder();
      setRawText(decoder.decode(decryptedBuffer));
      showStatus('Decryption successful!', 'success');
    } catch (err) {
      console.error(err);
      const errorMsg = err.name === 'OperationError' 
        ? 'Decryption failed. Authentication failed (wrong key, wrong encoding, or data mismatch).' 
        : 'Error: ' + err.message;
      showStatus(errorMsg, 'error');
    }
  };

  const copyToClipboard = (text) => {
    if (!text) return;
    const tempInput = document.createElement("textarea");
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand("copy");
    document.body.removeChild(tempInput);
    showStatus('Copied to clipboard!', 'info');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans p-4 md:p-8">
      <div className="max-w-4xl mx-auto">
        
        <header className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="bg-indigo-600 p-3 rounded-2xl text-white shadow-lg shadow-indigo-200">
              <Shield size={32} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">AES Crypto Tool</h1>
              <p className="text-slate-500 text-sm">Server-Compatible Encryption Utility</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 bg-white p-2 rounded-xl border border-slate-200 shadow-sm">
            <div className="flex items-center gap-2 border-r border-slate-200 pr-3 mr-1">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">Mode:</span>
              <span className="text-xs font-bold text-indigo-600 px-1">AES-256-GCM</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">Encoding:</span>
              <select 
                value={encoding}
                onChange={(e) => setEncoding(e.target.value)}
                className="bg-transparent outline-none text-xs font-bold text-indigo-600 cursor-pointer"
              >
                <option value="hex">HEX (iv:tag:data)</option>
                <option value="base64">Base64 (iv:tag:data)</option>
              </select>
            </div>
          </div>
        </header>

        {status.message && (
          <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl animate-in slide-in-from-right duration-300 ${
            status.type === 'success' ? 'bg-emerald-500 text-white' : 
            status.type === 'error' ? 'bg-rose-500 text-white' : 'bg-slate-800 text-white'
          }`}>
            {status.type === 'error' ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
            <span className="font-medium text-sm">{status.message}</span>
          </div>
        )}

        <section className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm mb-6">
          <div className="flex items-center justify-between mb-4">
            <label className="text-sm font-bold text-slate-700 flex items-center gap-2">
              <Lock size={16} className="text-indigo-500" />
              Secret Key
            </label>
            {isKeySaved && (
              <span className="text-[10px] bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">
                Stored Key Active
              </span>
            )}
          </div>
          <div className="flex flex-col md:flex-row gap-3">
            <input 
              type="password"
              placeholder="Enter your secret key (32 bytes recommended)..."
              className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-all font-mono"
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            <div className="flex gap-2">
              <button 
                onClick={saveKeyToLocal}
                className="flex-1 md:flex-none flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-3 rounded-xl font-semibold transition-colors shadow-md shadow-indigo-100"
              >
                <Save size={18} />
                <span>Save Key</span>
              </button>
              <button 
                onClick={clearSavedKey}
                className="p-3 text-slate-400 hover:text-rose-500 hover:bg-rose-50 rounded-xl transition-all"
                title="Wipe key from local storage"
              >
                <Trash2 size={20} />
              </button>
            </div>
          </div>
        </section>

        <div className="grid md:grid-cols-2 gap-6 items-start">
          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-bold text-slate-700">Plaintext Input</h2>
              <button onClick={() => copyToClipboard(rawText)} className="p-2 text-slate-400 hover:text-indigo-600 transition-colors">
                <Copy size={18} />
              </button>
            </div>
            <textarea 
              className="w-full h-48 bg-slate-50 border border-slate-200 rounded-2xl p-4 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-all resize-none text-slate-600 font-mono text-sm mb-4"
              placeholder="Enter text to encrypt..."
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
            <button 
              onClick={handleEncrypt}
              className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-2xl font-bold flex items-center justify-center gap-2 transition-all transform active:scale-[0.98] shadow-lg shadow-indigo-100"
            >
              <Lock size={20} />
              Encrypt (iv:tag:data)
            </button>
          </div>

          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-bold text-slate-700 flex items-center gap-2">
                Ciphertext Output
                <span className="text-[10px] bg-slate-100 text-slate-500 px-2 py-0.5 rounded-md uppercase">
                  {encoding}
                </span>
              </h2>
              <button onClick={() => copyToClipboard(encryptedText)} className="p-2 text-slate-400 hover:text-indigo-600 transition-colors">
                <Copy size={18} />
              </button>
            </div>
            <textarea 
              className="w-full h-48 bg-slate-800 border border-slate-700 rounded-2xl p-4 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-all resize-none text-indigo-300 font-mono text-xs mb-4"
              placeholder={`Paste your iv:tag:data string here...`}
              value={encryptedText}
              onChange={(e) => setEncryptedText(e.target.value)}
            />
            <button 
              onClick={handleDecrypt}
              className="w-full py-4 border-2 border-indigo-600 text-indigo-600 hover:bg-indigo-50 rounded-2xl font-bold flex items-center justify-center gap-2 transition-all transform active:scale-[0.98]"
            >
              <Unlock size={20} />
              Decrypt Ciphertext
            </button>
          </div>
        </div>

        <footer className="mt-12 text-center text-slate-400 text-sm">
          <p>Matching Node.js crypto logic. All encryption happens locally.</p>
          <div className="mt-2 flex flex-wrap items-center justify-center gap-4 text-[10px] font-bold uppercase tracking-widest">
            <span className="flex items-center gap-1 opacity-60"><RefreshCw size={12}/> AES-256-GCM</span>
            <span className="flex items-center gap-1 opacity-60"><Shield size={12}/> Compatibility: Node.js</span>
          </div>
        </footer>

      </div>
    </div>
  );
};

export default App;

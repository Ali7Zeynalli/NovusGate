import React, { useState, useEffect } from 'react';
import { Download, QrCode as QrIcon, X, Copy, Check, Monitor, Smartphone, Terminal, Box } from 'lucide-react';
import { Button, Modal } from './ui';
import { getAuthHeaders, api } from '../api/client';

interface ServerConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  nodeId: string;
  nodeName: string;
}

const InstallTab: React.FC<{
  icon: React.ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
}> = ({ icon, label, active, onClick }) => (
  <button
    onClick={onClick}
    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      active
        ? 'border-primary-600 text-primary-600 dark:text-primary-400'
        : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
    }`}
  >
    {icon}
    {label}
  </button>
);

export const ServerConfigModal: React.FC<ServerConfigModalProps> = ({
  isOpen,
  onClose,
  nodeId,
  nodeName,
}) => {
  const [activeTab, setActiveTab] = useState<'general' | 'windows' | 'mac' | 'linux' | 'docker'>('general');
  const [config, setConfig] = useState<string>('');
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && nodeId) {
      loadConfig();
      setActiveTab('general');
    }
  }, [isOpen, nodeId]);

  const loadConfig = async () => {
    setLoading(true);
    setError('');
    try {
      // Fetch Config Text
      const text = await api.getNodeConfig(nodeId);
      setConfig(text);

      // Fetch QR Code as base64 data URL (avoids blob URL security warning)
      const blob = await api.getNodeQrCode(nodeId);
      const reader = new FileReader();
      reader.onloadend = () => {
        setQrCodeUrl(reader.result as string);
      };
      reader.readAsDataURL(blob);

    } catch (err: any) {
      setError(err.message || 'Error loading configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    const element = document.createElement('a');
    // Use data URL instead of blob URL to avoid security warning
    const base64 = btoa(unescape(encodeURIComponent(config)));
    element.href = `data:text/plain;base64,${base64}`;
    element.download = `${nodeName.replace(/\s+/g, '-').toLowerCase()}.conf`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        setCopied(true);
      } else {
        // Fallback for non-secure contexts
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        textArea.style.top = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
          document.execCommand('copy');
          setCopied(true);
        } catch (err) {
          console.error('Fallback: Oops, unable to copy', err);
        }
        document.body.removeChild(textArea);
      }
    } catch (err) {
      console.error('Failed to copy!', err);
    }
    setTimeout(() => setCopied(false), 2000);
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'general':
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  WireGuard Config
                </label>
                <button
                  onClick={() => copyToClipboard(config)}
                  className="text-xs flex items-center gap-1 text-primary-600 hover:text-primary-700"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <textarea
                className="w-full h-64 p-3 text-xs font-mono bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg resize-none focus:ring-2 focus:ring-primary-500 outline-none"
                readOnly
                value={config}
              />
              <Button onClick={handleDownload} className="w-full flex items-center justify-center gap-2">
                <Download className="w-4 h-4" /> Download .conf
              </Button>
            </div>
            <div className="flex flex-col items-center justify-center space-y-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">Mobile Scan</h3>
              {qrCodeUrl ? (
                <div className="bg-white p-3 rounded-lg shadow-sm">
                  <img 
                    src={qrCodeUrl} 
                    alt="WireGuard QR Code" 
                    className="w-48 h-48"
                  />
                </div>
              ) : (
                <div className="w-48 h-48 bg-gray-100 dark:bg-gray-700 flex items-center justify-center text-gray-400 rounded-lg">
                  <QrIcon className="w-10 h-10 opacity-50" />
                </div>
              )}
              <p className="text-xs text-center text-gray-500 dark:text-gray-400">
                WireGuard tətbiqini açın və skan edin
              </p>
            </div>
          </div>
        );

      case 'windows':
        return (
          <div className="space-y-4">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">1. Install WireGuard</h4>
              <p className="text-sm text-blue-800 dark:text-blue-200 mb-3">
                Download and install the official WireGuard client for Windows.
              </p>
              <a 
                href="https://download.wireguard.com/windows-client/wireguard-installer.exe" 
                target="_blank" 
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium transition-colors"
              >
                <Download className="w-4 h-4" /> Download Installer
              </a>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900 dark:text-white">2. Import Config</h4>
              <ol className="list-decimal list-inside text-sm text-gray-600 dark:text-gray-300 space-y-1">
                <li>Open WireGuard application.</li>
                <li>Click on <strong>Import tunnel(s) from file</strong>.</li>
                <li>Select the downloaded <code>.conf</code> file.</li>
                <li>Click <strong>Activate</strong> to connect.</li>
              </ol>
            </div>
          </div>
        );

      case 'mac':
        return (
          <div className="space-y-4">
             <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <h4 className="font-semibold text-gray-900 dark:text-white mb-2">1. Install WireGuard</h4>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
                Download WireGuard from the Mac App Store.
              </p>
              <a 
                href="https://apps.apple.com/us/app/wireguard/id1451685025?mt=12" 
                target="_blank" 
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 hover:bg-black text-white rounded-md text-sm font-medium transition-colors"
              >
                <Download className="w-4 h-4" /> Mac App Store
              </a>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900 dark:text-white">2. Import Config</h4>
              <ol className="list-decimal list-inside text-sm text-gray-600 dark:text-gray-300 space-y-1">
                <li>Open WireGuard from your Applications.</li>
                <li>Click <strong>Import tunnel(s) from file</strong> in the menu bar.</li>
                <li>Select the downloaded <code>.conf</code> file.</li>
                <li>Click <strong>Activate</strong> to connect.</li>
              </ol>
            </div>
          </div>
        );

      case 'linux':
        const installCommand = `curl -sSfLk ${window.location.origin}/api/v1/nodes/${nodeId}/install.sh | sudo bash`;
        return (
          <div className="space-y-4">
            <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex justify-between items-center mb-2">
                <h4 className="text-sm font-semibold text-gray-400">Easy One-Line Install</h4>
                <button
                  onClick={() => copyToClipboard(installCommand)}
                  className="text-xs flex items-center gap-1 text-primary-400 hover:text-primary-300"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <code className="text-xs text-green-400 break-all">
                {installCommand}
              </code>
              <p className="text-xs text-yellow-500 mt-2">
                ⚠️ Run this from a machine that already has VPN access to the server
              </p>
            </div>

            <div className="space-y-4">
               <div className="p-4 bg-gray-900 text-gray-300 rounded-lg font-mono text-sm overflow-x-auto">
                 <p className="text-gray-500 mb-2"># Manual Install (Ubuntu/Debian)</p>
                 <p className="mb-4 text-green-400">sudo apt update && sudo apt install -y wireguard</p>
  
                 <p className="text-gray-500 mb-2"># Save Config</p>
                 <p className="mb-4 text-green-400">sudo nano /etc/wireguard/wg0.conf</p>
                 <p className="text-gray-500 italic mb-4 text-xs">(Paste the config content here)</p>
  
                 <p className="text-gray-500 mb-2"># Start VPN</p>
                 <p className="text-green-400">sudo wg-quick up wg0</p>
              </div>
            </div>
          </div>
        );

      case 'docker':
        return (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              You can run a WireGuard client easily using Docker. Replace <code>/path/to/wg0.conf</code> with your config path.
            </p>
            <div className="p-4 bg-gray-900 text-gray-300 rounded-lg font-mono text-sm overflow-x-auto relative group">
              <button 
                onClick={() => copyToClipboard(`docker run -d \\
  --name=wireguard-client \\
  --cap-add=NET_ADMIN \\
  --cap-add=SYS_MODULE \\
  -v /path/to/wg0.conf:/config/wg0.conf \\
  linuxserver/wireguard`)}
                className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <Copy className="w-4 h-4" />
              </button>
              <pre>
{`docker run -d \\
  --name=wireguard-client \\
  --cap-add=NET_ADMIN \\
  --cap-add=SYS_MODULE \\
  -v /path/to/wg0.conf:/config/wg0.conf \\
  linuxserver/wireguard`}
              </pre>
            </div>
          </div>
        );
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Connect: ${nodeName}`}>
      <div className="space-y-6">
        {loading ? (
          <div className="flex justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : error ? (
          <div className="text-red-500 p-4 bg-red-50 rounded-lg">{error}</div>
        ) : (
          <>
            {/* Tabs */}
            <div className="flex overflow-x-auto border-b border-gray-200 dark:border-gray-700">
              <InstallTab 
                active={activeTab === 'general'} 
                label="Config & QR" 
                icon={<QrIcon className="w-4 h-4" />}
                onClick={() => setActiveTab('general')} 
              />
              <InstallTab 
                active={activeTab === 'windows'} 
                label="Windows" 
                icon={<Monitor className="w-4 h-4" />}
                onClick={() => setActiveTab('windows')} 
              />
              <InstallTab 
                active={activeTab === 'mac'} 
                label="macOS" 
                icon={<Monitor className="w-4 h-4" />}
                onClick={() => setActiveTab('mac')} 
              />
              <InstallTab 
                active={activeTab === 'linux'} 
                label="Linux" 
                icon={<Terminal className="w-4 h-4" />}
                onClick={() => setActiveTab('linux')} 
              />
              <InstallTab 
                active={activeTab === 'docker'} 
                label="Docker" 
                icon={<Box className="w-4 h-4" />}
                onClick={() => setActiveTab('docker')} 
              />
            </div>

            {/* Tab Content */}
            <div className="mt-4">
              {renderContent()}
            </div>
          </>
        )}

        <div className="flex justify-end pt-4 border-t border-gray-100 dark:border-gray-800">
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
};

#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const GITHUB_REPO = 'PinataCloud/grapevine-cli';
const VERSION = '0.1.0'; // This should match package.json version

function getPlatformInfo() {
  const platform = process.platform;
  const arch = process.arch;
  
  // Map Node.js platform names to your GitHub release names
  const platformMap = {
    'win32': 'windows',
    'darwin': 'darwin',
    'linux': 'linux'
  };
  
  // Map Node.js arch names to your GitHub release names
  const archMap = {
    'x64': 'amd64',
    'arm64': 'arm64'
  };
  
  const mappedPlatform = platformMap[platform];
  const mappedArch = archMap[arch];
  
  if (!mappedPlatform || !mappedArch) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }
  
  return {
    platform: mappedPlatform,
    arch: mappedArch,
    extension: platform === 'win32' ? '.exe' : ''
  };
}

function getDownloadUrl(platform, arch, extension) {
  // Based on your GitHub release assets
  const filename = `grapevine-${platform}-${arch}${extension}`;
  return `https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${filename}`;
}

function downloadFile(url, destination) {
  return new Promise((resolve, reject) => {
    console.log(`Downloading ${url}...`);
    
    const file = fs.createWriteStream(destination);
    
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Handle redirects
        file.close();
        fs.unlinkSync(destination);
        return downloadFile(response.headers.location, destination)
          .then(resolve)
          .catch(reject);
      }
      
      if (response.statusCode !== 200) {
        file.close();
        fs.unlinkSync(destination);
        reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        resolve();
      });
      
      file.on('error', (err) => {
        file.close();
        fs.unlinkSync(destination);
        reject(err);
      });
    }).on('error', (err) => {
      file.close();
      fs.unlinkSync(destination);
      reject(err);
    });
  });
}

async function install() {
  try {
    const { platform, arch, extension } = getPlatformInfo();
    const url = getDownloadUrl(platform, arch, extension);
    
    // Create bin directory if it doesn't exist
    const binDir = path.join(__dirname, 'bin');
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    
    // Download the binary, replacing the placeholder
    const binaryPath = path.join(binDir, `grapevine${extension}`);
    await downloadFile(url, binaryPath);
    
    // Make executable on Unix systems
    if (process.platform !== 'win32') {
      execSync(`chmod +x "${binaryPath}"`);
    }
    
    console.log('✅ Grapevine CLI installed successfully!');
    console.log('Run "grapevine --help" to get started.');
    
  } catch (error) {
    console.error('❌ Installation failed:', error.message);
    console.error('\nTroubleshooting:');
    console.error('1. Check your internet connection');
    console.error('2. Verify the release exists at: https://github.com/PinataCloud/grapevine-cli/releases');
    console.error('3. Try installing from source: https://github.com/PinataCloud/grapevine-cli#from-source');
    process.exit(1);
  }
}

// Only run if this script is executed directly
if (require.main === module) {
  install();
}

module.exports = { install };
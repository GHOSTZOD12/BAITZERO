import fs from 'fs';
import path from 'path';

const srcImg = process.env.LOGO_SOURCE_IMAGE || path.join(process.cwd(), 'Assets', 'StoreLogo.png');
const destPng = 'C:\\Dev\\LinkProtection\\public\\logo.png';
const destTauriIcon = 'C:\\Dev\\LinkProtection\\src-tauri\\icons\\icon.png';

if (fs.existsSync(srcImg)) {
  fs.copyFileSync(srcImg, destPng);
  console.log('Copied official logo to public/logo.png');

  if (fs.existsSync('C:\\Dev\\LinkProtection\\src-tauri\\icons')) {
    fs.copyFileSync(srcImg, destTauriIcon);
    console.log('Copied official logo to src-tauri/icons/icon.png');
  }
} else {
  console.log('Source image not found, skipping logo processing.');
}

const fs = require('fs');
const path = require('path');

// Helper to read file content
function readFileSyncSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return '';
  }
}

// Count <img> tags with src, data-src, or loading="lazy" in HTML
function countImagesInHTML(htmlContent) {
  const imgTagRegex = /<img\s+[^>]*(src|data-src)\s*=\s*['"][^'"]+['"][^>]*>/gi;
  const lazyImgTagRegex = /<img\s+[^>]*loading\s*=\s*['"]lazy['"][^>]*>/gi;
  const matches = htmlContent.match(imgTagRegex) || [];
  const lazyMatches = htmlContent.match(lazyImgTagRegex) || [];
  // Use a Set to avoid double-counting images that match both
  const allMatches = new Set([...matches, ...lazyMatches]);
  return allMatches.size;
}

// Count background-image in CSS, optionally filter by target URL
function countBackgroundImagesInCSS(cssContent, targetUrl) {
  const bgImgRegex = /background-image\s*:\s*url\s*\(\s*['"]?([^'")]+)['"]?\s*\)/gi;
  const matches = [];
  let match;
  while ((match = bgImgRegex.exec(cssContent)) !== null) {
    if (!targetUrl || match[1] === targetUrl) {
      matches.push(match[1]);
    }
  }
  return matches.length;
}

// Main function
function main() {
  const publicDir = path.join(__dirname, 'public');
  const htmlPath = path.join(publicDir, 'index.html');
  const cssPath = path.join(publicDir, 'style.css');

  const htmlContent = readFileSyncSafe(htmlPath);
  const cssContent = readFileSyncSafe(cssPath);

  const imgCount = countImagesInHTML(htmlContent);
  // Specify your target image URL here
  const targetBgUrl = 'https://your-image-url.com/image.jpg';
  const bgImgCount = countBackgroundImagesInCSS(cssContent, targetBgUrl);

  console.log(`Images in <img> tags (src/data-src/loading="lazy"): ${imgCount}`);
  console.log(`Images in CSS background-image with URL '${targetBgUrl}': ${bgImgCount}`);
  console.log(`Total images used: ${imgCount + bgImgCount}`);
}

main();

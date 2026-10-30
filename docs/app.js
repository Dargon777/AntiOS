const REPO = "Dargon777/AntiOS";
const FALLBACK_RELEASES = `https://github.com/${REPO}/releases`;

const translations = document.querySelectorAll("[data-en][data-ru]");
const langButton = document.getElementById("langButton");

function setLanguage(lang) {
  const normalized = lang === "ru" ? "ru" : "en";
  document.documentElement.lang = normalized;
  translations.forEach((node) => {
    node.textContent = node.dataset[normalized];
  });
  langButton.textContent = normalized === "ru" ? "EN" : "RU";
  langButton.setAttribute("aria-label", normalized === "ru" ? "Switch to English" : "Переключить на русский");
  try { localStorage.setItem("antios-language", normalized); } catch (_) {}
}

let preferred = "en";
try {
  preferred = localStorage.getItem("antios-language") || (navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en");
} catch (_) {
  preferred = navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}
setLanguage(preferred);

langButton.addEventListener("click", () => {
  setLanguage(document.documentElement.lang === "ru" ? "en" : "ru");
});

document.getElementById("year").textContent = new Date().getFullYear();

async function hydrateLatestRelease() {
  try {
    const response = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=10`, {
      headers: { "Accept": "application/vnd.github+json" }
    });
    if (!response.ok) throw new Error(`GitHub API: ${response.status}`);

    const releases = await response.json();
    const release = releases.find((item) => !item.draft);
    if (!release) return;

    const installer = release.assets?.find((asset) => asset.name === "AntiOS-Setup.exe");
    const checksum = release.assets?.find((asset) => asset.name === "AntiOS-Setup.exe.sha256");

    document.getElementById("versionText").textContent = release.tag_name;
    document.getElementById("releaseLabel").dataset.en = `Public alpha · ${release.tag_name}`;
    document.getElementById("releaseLabel").dataset.ru = `Публичная alpha · ${release.tag_name}`;
    document.getElementById("releaseLabel").textContent =
      document.documentElement.lang === "ru"
        ? document.getElementById("releaseLabel").dataset.ru
        : document.getElementById("releaseLabel").dataset.en;

    if (installer?.browser_download_url) {
      document.getElementById("downloadButton").href = installer.browser_download_url;
      document.getElementById("downloadButtonBottom").href = installer.browser_download_url;
    }
    if (checksum?.browser_download_url) {
      document.getElementById("checksumLink").href = checksum.browser_download_url;
    }
  } catch (_) {
    document.getElementById("downloadButton").href = FALLBACK_RELEASES;
    document.getElementById("downloadButtonBottom").href = FALLBACK_RELEASES;
    document.getElementById("checksumLink").href = FALLBACK_RELEASES;
  }
}

hydrateLatestRelease();

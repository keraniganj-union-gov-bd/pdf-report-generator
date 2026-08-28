/* Voter Search All BD — District → Upazila dependent dropdowns.
 * Location data is loaded from a public, bilingual Bangladesh administrative
 * dataset and cached locally so repeat visits are fast.
 */
(function () {
  const DATA_URL = "https://iqbalhasandev.github.io/bangladesh-geo-json/bangladesh-geo.json";
  const CACHE_KEY = "v1_bd_geo_voter_locations_v1";
  const CACHE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;
  let tree = [];

  const $ = (id) => document.getElementById(id);
  const cleanDistrict = (name) => String(name || "").replace(/\s+জেলা$/u, "").trim();
  const cleanUpazila = (name) => {
    let n = String(name || "").trim();
    n = n.replace(/\s+উপজেলা$/u, "").trim();
    return n ? `${n} উপজেলা` : n;
  };
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (m) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));

  function normalize(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.map(div => ({
      name: div.bn_name || div.name || "",
      districts: Array.isArray(div.districts) ? div.districts.map(d => ({
        name: cleanDistrict(d.bn_name || d.name || ""),
        upazilas: Array.isArray(d.upazilas) ? d.upazilas.map(u => cleanUpazila(u.bn_name || u.name || "")).filter(Boolean) : []
      })).filter(d => d.name) : []
    })).filter(d => d.districts.length);
  }

  function flattenDistricts() {
    const out = [];
    tree.forEach(div => div.districts.forEach(d => out.push(d)));
    return out.sort((a,b) => a.name.localeCompare(b.name, "bn"));
  }

  function fillDistricts(selected) {
    const district = $("voterDistrict");
    const upazila = $("voterUpazila");
    if (!district || !upazila) return;
    const districts = flattenDistricts();
    district.innerHTML = `<option value="">-- জেলা নির্বাচন করুন --</option>` +
      districts.map(d => `<option value="${esc(d.name)}">${esc(d.name)}</option>`).join("");
    district.value = selected || "";
    fillUpazilas(district.value, "");
  }

  function fillUpazilas(districtName, selected) {
    const district = $("voterDistrict");
    const upazila = $("voterUpazila");
    if (!district || !upazila) return;
    const d = flattenDistricts().find(x => x.name === districtName);
    if (!d) {
      upazila.disabled = true;
      upazila.innerHTML = `<option value="">-- আগে জেলা নির্বাচন করুন --</option>`;
      return;
    }
    upazila.disabled = false;
    upazila.innerHTML = `<option value="">-- উপজেলা নির্বাচন করুন --</option>` +
      d.upazilas.map(u => `<option value="${esc(u)}">${esc(u)}</option>`).join("");
    upazila.value = selected || "";
  }

  async function getData() {
    try {
      const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
      if (cached && cached.savedAt && Date.now() - cached.savedAt < CACHE_MAX_AGE && Array.isArray(cached.data)) {
        return cached.data;
      }
    } catch (_) {}
    const r = await fetch(DATA_URL, { cache: "force-cache" });
    if (!r.ok) throw new Error("Location data unavailable");
    const raw = await r.json();
    try { localStorage.setItem(CACHE_KEY, JSON.stringify({ savedAt: Date.now(), data: raw })); } catch (_) {}
    return raw;
  }

  window.initVoterLocationDropdowns = async function () {
    const district = $("voterDistrict");
    const upazila = $("voterUpazila");
    if (!district || !upazila) return;
    if (district.dataset.locationReady === "1") return;
    district.dataset.locationReady = "loading";
    district.disabled = true;
    upazila.disabled = true;
    try {
      const raw = await getData();
      tree = normalize(raw);
      fillDistricts(district.dataset.selected || "");
      district.addEventListener("change", () => fillUpazilas(district.value, ""));
      district.dataset.locationReady = "1";
    } catch (_) {
      // Keep the controls quiet for customers; do not expose a provider/API error.
      district.innerHTML = `<option value="">-- জেলা নির্বাচন করুন --</option>`;
      upazila.innerHTML = `<option value="">-- উপজেলা নির্বাচন করুন --</option>`;
      district.disabled = false;
      upazila.disabled = true;
      district.dataset.locationReady = "error";
    }
  };
})();

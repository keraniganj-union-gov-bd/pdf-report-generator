/* Voter Search All BD — District → Upazila dependent dropdowns.
 * Location data is loaded from the application's server-side DB Clouds proxy.
 * The DB Clouds API key is never exposed to the browser.
 */
(function () {
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (m) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
  }[m]));

  const $ = (id) => document.getElementById(id);

  window.initVoterLocationDropdowns = async function () {
    const district = $("voterDistrict");
    const upazila = $("voterUpazila");
    if (!district || !upazila) return;
    if (district.dataset.locationReady === "1") return;

    district.dataset.locationReady = "loading";
    district.disabled = true;
    upazila.disabled = true;
    district.innerHTML = `<option value="">-- জেলা লোড হচ্ছে --</option>`;
    upazila.innerHTML = `<option value="">-- আগে জেলা নির্বাচন করুন --</option>`;

    try {
      const r = await fetch("/api/customer/voter-locations/districts", {
        credentials: "same-origin",
        cache: "no-store"
      });
      const x = await r.json();
      if (!r.ok || !Array.isArray(x.districts)) throw new Error("districts");

      const districts = x.districts.filter(Boolean);
      district.innerHTML =
        `<option value="">-- জেলা নির্বাচন করুন --</option>` +
        districts.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
      district.disabled = false;

      district.addEventListener("change", async () => {
        const value = district.value.trim();
        upazila.disabled = true;
        upazila.innerHTML = `<option value="">-- উপজেলা লোড হচ্ছে --</option>`;

        if (!value) {
          upazila.innerHTML = `<option value="">-- আগে জেলা নির্বাচন করুন --</option>`;
          return;
        }

        try {
          const rr = await fetch(
            `/api/customer/voter-locations/upazilas?district=${encodeURIComponent(value)}`,
            { credentials: "same-origin", cache: "no-store" }
          );
          const xx = await rr.json();
          if (!rr.ok || !Array.isArray(xx.upazilas)) throw new Error("upazilas");

          const upazilas = xx.upazilas.filter(Boolean);
          upazila.innerHTML =
            `<option value="">-- উপজেলা নির্বাচন করুন --</option>` +
            upazilas.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
          upazila.disabled = !upazilas.length;
        } catch (_) {
          upazila.innerHTML = `<option value="">-- উপজেলা পাওয়া যায়নি --</option>`;
          upazila.disabled = true;
        }
      });

      district.dataset.locationReady = "1";
    } catch (_) {
      district.innerHTML = `<option value="">-- জেলা পাওয়া যায়নি --</option>`;
      upazila.innerHTML = `<option value="">-- উপজেলা নির্বাচন করুন --</option>`;
      district.disabled = false;
      upazila.disabled = true;
      district.dataset.locationReady = "error";
    }
  };
})();

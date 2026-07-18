(() => {
  const qs = (s) => document.querySelector(s);
  const qsa = (s) => [...document.querySelectorAll(s)];
  const overlay = qs('#loadingOverlay');
  qsa('.loading-form').forEach((form) => form.addEventListener('submit', () => overlay?.classList.add('show')));
  qs('#menuToggle')?.addEventListener('click', () => qs('#sidebar')?.classList.toggle('open'));

  const params = new URLSearchParams(location.search);
  const toastMessage = params.get('toast');
  if (toastMessage) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = toastMessage;
    qs('#toastContainer')?.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
    params.delete('toast');
    history.replaceState({}, '', `${location.pathname}${params.toString() ? `?${params}` : ''}`);
  }

  const common = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8fa5b7', boxWidth: 10 } } },
    scales: {
      x: { ticks: { color: '#71879b' }, grid: { color: 'rgba(41,68,93,.28)' } },
      y: { ticks: { color: '#71879b' }, grid: { color: 'rgba(41,68,93,.28)' }, beginAtZero: true }
    }
  };

  async function renderDashboard() {
    if (!qs('#eventsChart') || typeof Chart === 'undefined') return;
    try {
      const res = await fetch('/api/stats');
      const data = await res.json();
      new Chart(qs('#eventsChart'), { type: 'line', data: { labels: data.charts.events_timeline.labels, datasets: [{ label: 'Events', data: data.charts.events_timeline.values, borderColor: '#32d6d2', backgroundColor: 'rgba(50,214,210,.08)', fill: true, tension: .35, pointRadius: 2 }] }, options: common });
      new Chart(qs('#severityChart'), { type: 'doughnut', data: { labels: data.charts.alert_severity.labels, datasets: [{ data: data.charts.alert_severity.values, backgroundColor: ['#4ea1ff','#ffbd59','#ff916e','#ff6577','#9b7bff'], borderWidth: 0 }] }, options: { responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#8fa5b7',boxWidth:10}}} } });
      new Chart(qs('#sourcesChart'), { type: 'bar', data: { labels: data.charts.event_sources.labels, datasets: [{ label: 'Events', data: data.charts.event_sources.values, backgroundColor: '#4ea1ff', borderRadius: 7 }] }, options: common });
      new Chart(qs('#mitreChart'), { type: 'bar', data: { labels: data.charts.mitre_tactics.labels, datasets: [{ label: 'Rules', data: data.charts.mitre_tactics.values, backgroundColor: '#9b7bff', borderRadius: 7 }] }, options: { ...common, indexAxis: 'y' } });
    } catch (error) { console.error('Chart load failed', error); }
  }
  window.addEventListener('load', renderDashboard);

  const fileInput = qs('.drop-zone input[type=file]');
  fileInput?.addEventListener('change', () => {
    const label = qs('.drop-zone strong');
    if (label && fileInput.files?.[0]) label.textContent = fileInput.files[0].name;
  });
})();

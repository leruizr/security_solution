/* Utilidades compartidas de interfaz. */

export function esc(v) {
  const d = document.createElement('div');
  d.textContent = v == null ? '' : String(v);
  return d.innerHTML;
}

export function el(id) { return document.getElementById(id); }

export function hora(iso) { return String(iso || '').replace('T', ' '); }

export function soloHora(iso) { return String(iso || '').slice(11, 16); }

export function numero(n) {
  return new Intl.NumberFormat('es-CO').format(Number(n) || 0);
}

export function bytes(n) {
  const v = Number(n) || 0;
  if (v >= 1e6) return (v / 1e6).toFixed(1).replace('.0', '') + ' MB';
  if (v >= 1e3) return (v / 1e3).toFixed(1).replace('.0', '') + ' KB';
  return v + ' B';
}

export const CLASE_SEV = {
  'Crítica': 'sev-critica',
  'Alta': 'sev-alta',
  'Media': 'sev-media',
  'Baja': 'sev-baja',
  'Descartada': 'sev-descartada',
};

export function pill(texto, clase) {
  return `<span class="pill ${clase || ''}">${esc(texto)}</span>`;
}

export function tarjeta({ cifra, etiqueta, detalle, tono }) {
  return `<div class="kpi ${tono ? 'kpi-' + tono : ''}">
    <div class="kpi-cifra">${esc(cifra)}</div>
    <div class="kpi-etiqueta">${esc(etiqueta)}</div>
    ${detalle ? `<div class="kpi-detalle">${esc(detalle)}</div>` : ''}
  </div>`;
}

export function abrirModal(titulo, html) {
  el('modal-titulo').textContent = titulo;
  el('modal-cuerpo').innerHTML = html;
  el('modal').showModal();
}

export function tablaClaveValor(obj, etiquetas) {
  const filas = Object.keys(obj).map(k => {
    const nombre = (etiquetas && etiquetas[k]) || k.replace(/_/g, ' ');
    return `<tr><th>${esc(nombre)}</th><td>${esc(obj[k])}</td></tr>`;
  }).join('');
  return `<table class="kv"><tbody>${filas}</tbody></table>`;
}

export function copiar(texto, boton) {
  const fin = (ok) => {
    const original = boton.innerHTML;
    boton.innerHTML = ok ? '✓ Copiado' : '✕ No se pudo';
    boton.disabled = true;
    setTimeout(() => { boton.innerHTML = original; boton.disabled = false; }, 1600);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(texto).then(() => fin(true), () => fin(false));
  } else {
    // file:// y http sin TLS no tienen clipboard API
    const ta = document.createElement('textarea');
    ta.value = texto; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    fin(ok);
  }
}

export function descargar(nombre, texto, tipo) {
  const blob = new Blob([texto], { type: (tipo || 'text/plain') + ';charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = nombre;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

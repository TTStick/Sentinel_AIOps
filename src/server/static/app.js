/* 前端公共库：请求、格式化、提示、图表、模态。状态仅存内存。 */
const API = {
  async req(method, url, body){
    const opt = {method, headers:{}, credentials:'same-origin'};
    if(body !== undefined){ opt.headers['Content-Type']='application/json'; opt.body=JSON.stringify(body); }
    const r = await fetch(url, opt);
    let data=null; try{ data = await r.json(); }catch(e){}
    if(!r.ok){
      const msg = (data && data.detail) ? data.detail : ('请求失败 ('+r.status+')');
      if(r.status===401){ location.href='/login'; }
      throw new Error(msg);
    }
    return data;
  },
  get(u){return this.req('GET',u);},
  post(u,b){return this.req('POST',u,b);},
  put(u,b){return this.req('PUT',u,b);},
  del(u){return this.req('DELETE',u);},
};

/* ---------- 格式化 ---------- */
const F = {
  time(ts){ if(!ts) return '—'; const d=new Date(ts*1000);
    return d.toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}); },
  date(ts){ if(!ts) return '—'; return new Date(ts*1000).toLocaleString('zh-CN'); },
  ago(ts){ if(!ts) return '从未'; const s=Date.now()/1000-ts;
    if(s<60) return Math.floor(s)+' 秒前'; if(s<3600) return Math.floor(s/60)+' 分钟前';
    if(s<86400) return Math.floor(s/3600)+' 小时前'; return Math.floor(s/86400)+' 天前'; },
  dur(sec){ if(sec==null) return '—'; if(sec<3600) return (sec/60).toFixed(0)+' 分钟';
    if(sec<86400) return (sec/3600).toFixed(1)+' 小时'; return (sec/86400).toFixed(1)+' 天'; },
  pct(v){ return (v==null)?'—':(Math.round(v*10)/10)+'%'; },
  num(v){ return (v==null)?'—':v; },
  esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); },
};

const RISK_CLASS = {Normal:'ok',Warning:'warn',Critical:'crit'};
const RISK_LABEL = {Normal:'正常',Warning:'警告',Critical:'严重'};
function riskBadge(level){ const c=RISK_CLASS[level]||'info'; return `<span class="badge ${c}">${RISK_LABEL[level]||level||'—'}</span>`; }
function onlineDot(online){ return `<span class="dot ${online?'ok':'off'}"></span>`; }
function healthColor(h){ if(h==null) return 'var(--ink-3)'; if(h>=75) return 'var(--ok)'; if(h>=45) return 'var(--warn)'; return 'var(--crit)'; }
function cmdRiskClass(r){ return r==='dangerous'?'risk-dangerous':(r==='caution'?'risk-caution':'risk-safe'); }
function cmdRiskLabel(r){ return r==='dangerous'?'高危':(r==='caution'?'注意':'安全'); }

/* ---------- toast ---------- */
function toast(msg, kind='ok'){
  let box=document.getElementById('toasts');
  if(!box){ box=document.createElement('div'); box.id='toasts'; document.body.appendChild(box); }
  const t=document.createElement('div'); t.className='toast '+(kind==='err'?'err':'ok'); t.textContent=msg;
  box.appendChild(t); setTimeout(()=>{ t.style.opacity='0'; t.style.transition='.3s'; setTimeout(()=>t.remove(),300); }, 3200);
}

/* ---------- 健康环 ---------- */
function ring(h){
  const v = h==null?0:Math.round(h);
  return `<div class="ring" style="--p:${v};--c:${healthColor(h)}"><b>${h==null?'—':v}</b></div>`;
}

/* ---------- 迷你折线 (SVG sparkline) ---------- */
function sparkline(points, color){
  color=color||'#b56548';
  const vals = points.map(p=>p.v).filter(v=>v!=null);
  if(vals.length<2) return '<div class="muted tiny">数据不足</div>';
  const min=Math.min(...vals), max=Math.max(...vals), rng=(max-min)||1;
  const W=160,H=34;
  const step=W/(vals.length-1);
  const d=vals.map((v,i)=>`${i===0?'M':'L'}${(i*step).toFixed(1)},${(H-2-((v-min)/rng)*(H-4)).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:34px">
    <path d="${d}" fill="none" stroke="${color}" stroke-width="1.6"/>
    <path d="${d} L${W},${H} L0,${H} Z" fill="${color}" opacity="0.07"/></svg>`;
}

/* ---------- Chart.js 默认主题 ---------- */
function chartDefaults(){
  if(window.Chart){
    Chart.defaults.color='#6e665a';
    Chart.defaults.font.family="'Noto Sans SC','Inter',sans-serif";
    Chart.defaults.font.size=11;
    Chart.defaults.borderColor='rgba(180,160,140,.22)';
    Chart.defaults.plugins.legend.labels.boxWidth=12;
  }
}

/* ---------- 模态 ---------- */
function modal(html, opts){
  opts=opts||{};
  let mask=document.getElementById('app-modal');
  if(!mask){ mask=document.createElement('div'); mask.id='app-modal'; mask.className='modal-mask'; document.body.appendChild(mask); }
  mask.innerHTML = `<div class="modal"><div class="modal-h"><h3>${opts.title||''}</h3><span class="x">&times;</span></div>
    <div class="modal-b">${html}</div>${opts.footer?`<div class="modal-f">${opts.footer}</div>`:''}</div>`;
  mask.classList.add('show');
  const close=()=>mask.classList.remove('show');
  mask.querySelector('.x').onclick=close;
  mask.onclick=(e)=>{ if(e.target===mask) close(); };
  return {el:mask, close};
}

/* ---------- 通用 ---------- */
async function logout(){ try{ await API.post('/api/logout'); }catch(e){} location.href='/login'; }
function setActiveNav(page){ document.querySelectorAll('.nav a[data-page]').forEach(a=>{ a.classList.toggle('active', a.dataset.page===page); }); }

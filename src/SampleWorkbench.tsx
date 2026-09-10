import { useEffect, useState } from 'react';
import { apiGet, apiPost, apiPut, API_BASE } from './api-contract';
import type { Packet } from './App';
import './samples.css';

type Row = { packet: Packet; length: number; fields: { name: string; value: string; offset: number; size: number; kind: string }[] };
type Batch = { id: string; source: string; items: Row[] };
type Template = { id: string; name: string; builtin: boolean; packet?: Packet; layers: Packet['layers'] };

export default function SampleWorkbench({ current, canAdd, hosts, onAdd, onTemplates }: {
  current?: Packet; canAdd: boolean; hosts: { id: string; name: string; address: string }[];
  onAdd: (packet: Packet) => void; onTemplates: () => Promise<void>;
}) {
  const [batches, setBatches] = useState<Batch[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [row, setRow] = useState<Row>();
  const [original, setOriginal] = useState<Row>();
  const [name, setName] = useState('');
  const [templateId, setTemplateId] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [operation, setOperation] = useState('field');
  const [field, setField] = useState('');
  const [value, setValue] = useState('');
  const [offset, setOffset] = useState(0);
  const [count, setCount] = useState(1);
  const [hex, setHex] = useState('ff');
  const [calculation, setCalculation] = useState('preserve');
  const [hostId, setHostId] = useState('');
  const [iface, setIface] = useState('');
  const [bpf, setBpf] = useState('tcp or udp');
  const [seconds, setSeconds] = useState(10);
  const [limit, setLimit] = useState(20);
  const [approved, setApproved] = useState(false);
  const [remove, setRemove] = useState(false);
  async function refresh() {
    const [samples, library] = await Promise.all([apiGet<{ items: Batch[] }>('/samples'), apiGet<{ items: Template[] }>('/templates')]);
    setBatches(samples.items); setTemplates(library.items.filter(t => !t.builtin));
  }
  useEffect(() => { void refresh().catch(e => setError(String(e))); }, []);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { if (row && original && row.packet.rawHex !== original.packet.rawHex) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [row, original]);
  async function work(fn: () => Promise<void>) {
    setBusy(true); setError(''); setMessage('');
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  function select(next: Row, id = '', title = next.packet.name) {
    if (row && original && row.packet.rawHex !== original.packet.rawHex && !window.confirm('当前编辑尚未另存为模板，是否切换报文？')) return;
    setRow(next); setOriginal(next); setName(title); setTemplateId(id); setRemove(false);
    setField(next.fields[0]?.name ?? ''); setValue(next.fields[0]?.value ?? '');
    setMessage('样本已载入；默认保留原始长度和校验和');
  }
  async function loadPacket(packet: Packet, id = '', title?: string) {
    select(await apiPost<Row>('/samples/edit', { packet }), id, title);
  }
  return <section className="sample-workbench">
    <header className="page-title"><div><div className="eyebrow">PACKET SAMPLES / BYTE EXACT</div><h1>报文样本与模板</h1><p>采集真实报文，精确编辑字节，保存为可复用的测试基底。</p></div></header>
    {error && <p className="api-error" role="alert">{error}</p>}
    <p role="status" className="editor-hint">{busy ? '处理中，请等待…' : message}</p>
    <fieldset disabled={busy} className="sample-controls">
      <div className="sample-acquire panel">
        <h2>01 · 获取报文</h2>
        <label>导入 PCAP<input type="file" accept=".pcap,.cap" onChange={e => {
          const file = e.target.files?.[0]; e.target.value = '';
          if (file) void work(async () => {
            if (file.size > 16 * 1024 * 1024) throw new Error('文件超过 16 MiB');
            const data = new FormData(); data.append('file', file);
            const response = await fetch(`${API_BASE}/samples/import`, { method: 'POST', body: data });
            const body = await response.json(); if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : '导入失败');
            await refresh(); setMessage(`已导入 ${body.items.length} 个报文，请从列表选择`);
          });
        }} /></label>
        <small>经典 PCAP · Ethernet · 最大 16 MiB / 1000 包；PCAPNG 请先转换。</small>
        <button className="quiet-button" disabled={!current} onClick={() => void work(() => loadPacket(current!))}>载入当前场景报文</button>
        <details><summary>从远端网口抓包</summary><div className="sample-form">
          <label>抓包主机<select value={hostId} onChange={e => { setHostId(e.target.value); setApproved(false); }}><option value="">选择主机</option>{hosts.map(h => <option key={h.id} value={h.id}>{h.name} · {h.address}</option>)}</select></label>
          <label>抓包网口<input value={iface} placeholder="例如 eth0" onChange={e => { setIface(e.target.value); setApproved(false); }} /></label>
          <label>BPF 过滤<input value={bpf} onChange={e => { setBpf(e.target.value); setApproved(false); }} /></label>
          <label>最长时间（秒）<input type="number" min="1" max="30" value={seconds} onChange={e => setSeconds(Number(e.target.value))} /></label>
          <label>最多报文数<input type="number" min="1" max="100" value={limit} onChange={e => setLimit(Number(e.target.value))} /></label>
          <label className="sample-check"><input type="checkbox" checked={approved} onChange={e => setApproved(e.target.checked)} />已获授权抓取上述网口流量并保存在本机</label>
          <button className="add-button" disabled={!hostId || !iface || !approved} onClick={() => void work(async () => {
            const batch = await apiPost<Batch>('/samples/capture', { hostId, interface: iface, bpf, seconds, count: limit, approved });
            await refresh(); setMessage(batch.items.length ? `抓取 ${batch.items.length} 个报文` : '抓包结束，未匹配到报文'); setApproved(false);
          })}>开始限量抓包</button>
        </div></details>
      </div>
      <div className="sample-grid">
        <aside className="panel sample-library"><h2>02 · 选择样本</h2>
          {!batches.length && <p>导入或抓包后，报文显示在这里。</p>}
          {batches.map(batch => <details key={batch.id} open><summary>{batch.source} · {batch.items.length} 包</summary>{batch.items.map((item, i) => <button className="sample-row" key={item.packet.id} onClick={() => select(item)}><b>#{i + 1} · {item.length} bytes</b><small>{item.fields.filter(f => /srcIp|dstIp|Port/.test(f.name)).map(f => f.value).join(' → ') || '原始字节'}</small></button>)}</details>)}
          <h2>用户模板</h2>{!templates.length && <p>尚无用户模板</p>}
          {templates.map(t => <button className="sample-row" key={t.id} onClick={() => void work(() => loadPacket(t.packet ?? {id:t.id,name:t.name,enabled:true,sendCount:1,intervalMs:0,layers:t.layers,mutations:[]}, t.id, t.name))}>{t.name}</button>)}
        </aside>
        <section className="panel sample-editor"><h2>03 · 编辑与复用</h2>
          {!row ? <p>先选择一条报文。未知协议可直接使用字节编辑。</p> : <>
            <p>{row.length} bytes · {row.packet.rawHex === original?.packet.rawHex ? '与载入字节一致' : '存在字节修改'}</p>
            <div className="sample-form">
              <label>编辑操作<select value={operation} onChange={e => setOperation(e.target.value)}><option value="field">修改协议字段</option><option value="overwrite">覆盖字节</option><option value="insert">插入字节</option><option value="delete">删除字节</option><option value="padding">尾部追加 Padding</option><option value="inspect">仅执行计算策略</option></select></label>
              {operation === 'field' ? <><label>字段<select value={field} onChange={e => { setField(e.target.value); setValue(row.fields.find(f => f.name === e.target.value)?.value ?? ''); }}><option value="">请选择字段</option>{row.fields.map(f => <option key={f.name}>{f.name}</option>)}</select></label><label>字段值<input value={value} onChange={e => setValue(e.target.value)} /></label></> : <>
                {['overwrite', 'insert', 'delete'].includes(operation) && <label>字节偏移（从 0 开始）<input type="number" min="0" value={offset} onChange={e => setOffset(Number(e.target.value))} /></label>}
                {['delete', 'padding'].includes(operation) && <label>字节数<input type="number" min="0" max="65535" value={count} onChange={e => setCount(Number(e.target.value))} /></label>}
                {['overwrite', 'insert', 'padding'].includes(operation) && <label>Hex 字节 / 填充模式<input value={hex} onChange={e => setHex(e.target.value)} placeholder="例如 de ad be ef" /></label>}
              </>}
              <label>计算策略<select value={calculation} onChange={e => setCalculation(e.target.value)}><option value="preserve">保留长度与校验和（可制造异常）</option><option value="checksums">只修正校验和</option><option value="lengths_checksums">按实际字节修正长度与校验和</option></select></label>
            </div>
            <p className="editor-hint">修正长度时会把尾部字节算入 IP 负载。保留策略不会修正任何相关字段。</p>
            <div className="head-actions"><button className="add-button" onClick={() => void work(async () => { const next = await apiPost<Row>('/samples/edit', { packet: row.packet, operation, offset, count, hex, field, value, calculation }); setRow(next); setValue(next.fields.find(f => f.name === field)?.value ?? value); setMessage('字节已更新，请保存为模板或添加到场景'); })}>应用编辑</button><button className="quiet-button" onClick={() => { if (original) setRow(original); }}>恢复载入字节</button></div>
            <pre className="sample-hex" aria-label="样本 Hex">{row.packet.rawHex?.match(/.{1,32}/g)?.map(line => line.match(/.{1,2}/g)?.join(' ')).join('\n')}</pre>
            <label>模板名称<input value={name} maxLength={120} onChange={e => setName(e.target.value)} /></label>
            <div className="head-actions">
              <button className="add-button" disabled={!name.trim()} onClick={() => void work(async () => { const t = await apiPost<Template>('/templates', { name, packet: row.packet }); setTemplateId(t.id); setOriginal(row); await refresh(); await onTemplates(); setMessage('用户模板已保存'); })}>另存为用户模板</button>
              {templateId && <button className="quiet-button" disabled={!name.trim()} onClick={() => void work(async () => { await apiPut(`/templates/${templateId}`, { name, packet: row.packet }); setOriginal(row); await refresh(); await onTemplates(); setMessage('模板已更新，已有场景保持原快照'); })}>更新当前模板</button>}
              <button className="quiet-button" disabled={!canAdd} onClick={() => { onAdd(row.packet); setOriginal(row); setMessage('已添加到当前场景，请保存场景'); }}>添加到当前场景</button>
              {templateId && <button className="quiet-button" onClick={() => setRemove(true)}>删除当前模板</button>}
            </div>
            {remove && <div role="alert"><p>确认删除模板“{name}”？已有场景中的报文不受影响。</p><button onClick={() => void work(async () => { const response = await fetch(`${API_BASE}/templates/${templateId}`, { method: 'DELETE' }); if (!response.ok) throw new Error('删除失败'); setTemplateId(''); setRemove(false); await refresh(); await onTemplates(); setMessage('模板已删除；已有场景保留快照，模板本身没有回收站'); })}>确认删除模板</button><button onClick={() => setRemove(false)}>取消</button></div>}
          </>}
        </section>
      </div>
    </fieldset>
  </section>;
}

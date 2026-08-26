const fs=require('fs');
function reader(p){ const data=fs.readFileSync(p); const other=compute(p); fs.readFileSync(p); return data; }
function sink(p){ const code=fs.readFileSync(p); eval(code); }

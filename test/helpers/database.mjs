export function memoryDatabase({coldTransactions=false}={}){
 const records=new Map();
 const clone=v=>structuredClone(v??null);
 const snapshot=v=>({val:()=>clone(v)});
 const db={ref:path=>({
  async get(){return snapshot(records.get(path));},
  async set(value){records.set(path,clone(value));},
  async remove(){records.delete(path);const parts=path.split('/');const key=parts.pop();const parent=parts.join('/');if(records.has(parent)){const value=clone(records.get(parent));delete value[key];records.set(parent,value);}},
  async transaction(update){if(coldTransactions&&records.has(path)&&update(null)===undefined)return{committed:false,snapshot:snapshot(null)};const next=update(clone(records.get(path)));if(next===undefined)return{committed:false,snapshot:snapshot(records.get(path))};records.set(path,clone(next));return{committed:true,snapshot:snapshot(next)};},
 })};return{db,records};
}

import {validateImages} from './vision.mjs';
import {fail} from './cloud-services.mjs';
export function createGalleryStore(db){const base=k=>'nebulaGallery/v1/'+k;return {
 async galleryList(k){const index=(await db.ref(base(k)+'/index').get()).val()||{};return Object.values(index).sort((a,b)=>b.createdAt-a.createdAt);},
 async galleryPhoto(k,id){return (await db.ref(base(k)+'/photos/'+id).get()).val();},
 async gallerySave(k,id,name,data,time){validateImages([{data}]);const bytes=Buffer.byteLength(data);const record={id,name:String(name||'Photo').slice(0,120),createdAt:time,bytes};const index=db.ref(base(k)+'/index');const r=await index.transaction(old=>{const items=old||{};if(items[id])return;items[id]=record;if(Object.keys(items).length>200||Object.values(items).reduce((n,p)=>n+p.bytes,0)>100000000)return;return items;},undefined,false);if(!r.committed){const existing=await this.galleryPhoto(k,id);if(existing?.data===data)return existing;fail('GALLERY_LIMIT',409);}try{await db.ref(base(k)+'/photos/'+id).set({...record,data});}catch(e){await db.ref(base(k)+'/index/'+id).remove();throw e;}return record;},
 async galleryDelete(k,id){await db.ref(base(k)).update({['index/'+id]:null,['photos/'+id]:null});}
};}

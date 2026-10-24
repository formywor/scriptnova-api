import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
const root=process.cwd(),index=path.join(root,'index.js');
if(!existsSync(path.join(root,'lib','movie.mjs'))||!existsSync(index))throw Error('Run from the API repository root after copying lib/movie.mjs and lib/movie-state.mjs.');
const source=readFileSync(index,'utf8');
if(source.includes("from './lib/movie.mjs'")){console.log('Movie route import already exists. No changes made.');process.exit(0);}
const marker='export default createNodeHandler(request=>';
if(source.split(marker).length!==2||!source.includes('getAdminDatabase'))throw Error('API entry point differs from the supplied version. No files changed. Follow the manual routing instructions.');
const updated="import {createMovieHandler} from './lib/movie.mjs';\n"+source.replace(marker,"const movieApp=createMovieHandler({getAdminDatabase});\nexport default createNodeHandler(request=>new URL(request.url).pathname.startsWith('/movie-api/')?movieApp(request):");
if(existsSync(index+'.before-movie'))throw Error('A route backup already exists; no files changed.');
writeFileSync(index+'.before-movie',source);writeFileSync(index,updated);console.log('Added /movie-api/ dispatch. Existing route handlers are unchanged. Backup: index.js.before-movie');

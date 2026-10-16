import {createServer} from 'node:http';
import handler from '../index.js';

createServer(handler).listen(Number(process.env.PORT || 8787),'127.0.0.1',()=>console.log('Nebula API: http://127.0.0.1:8787'));

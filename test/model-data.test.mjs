import {test} from 'node:test';
import assert from 'node:assert/strict';
import {selectContributions} from '../scripts/model-data.mjs';
test('training export includes only consented current account generations, not guests or revoked data',()=>{
 const sample={consentVersion:1,messages:[{role:'user',content:'Hello'}],source:{kind:'user',accountKey:'alice',generation:1}};
 const training={good:{samples:{chat:{turn:sample}}},old:{samples:{chat:{turn:{...sample,source:{...sample.source,generation:0}}}}},guest:{samples:{chat:{turn:{consentVersion:1,messages:sample.messages}}}},revoked:{revoked:true,samples:{chat:{turn:sample}}}};
 const accounts={alice:{improve:true,trainingGeneration:1}};
 const rows=selectContributions(training,accounts);assert.equal(rows.length,1);assert.equal(rows[0].source.owner,'good');assert.equal(rows[0].reviewStatus,'pending');accounts.alice.improve=false;assert.equal(selectContributions(training,accounts).length,0);
});

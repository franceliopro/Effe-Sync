import test from 'node:test';import assert from 'node:assert/strict';import {matchPausedSession,accountInbox} from '../matching.js';
test('matches phone to one paused session',()=>{const p={sender:{phone_number:'+55 66 99999-9999'}};assert.deepEqual(matchPausedSession(p,{sessions:[{remoteJid:'5566999999999@s.whatsapp.net',status:'paused'}]}),{remoteJid:'5566999999999@s.whatsapp.net',reason:'phone'})});
test('does not guess LID from telephone',()=>{assert.equal(matchPausedSession({sender:{phone_number:'+55 66 99999-9999'}},{sessions:[{remoteJid:'123456789@lid',status:'paused'}]}).reason,'no_unique_paused_session')});
test('exact LID match',()=>{assert.equal(matchPausedSession({sender:{identifier:'123456789@lid'}},{sessions:[{remoteJid:'123456789@lid',status:'paused'}]}).remoteJid,'123456789@lid')});
test('requires paused',()=>{assert.equal(matchPausedSession({sender:{identifier:'5566999999999@s.whatsapp.net'}},{sessions:[{remoteJid:'5566999999999@s.whatsapp.net',status:'opened'}]}).reason,'no_unique_paused_session')});
test('account inbox are explicit',()=>{assert.deepEqual(accountInbox({account:{id:3},inbox:{id:7}}),{account:3,inbox:7})});

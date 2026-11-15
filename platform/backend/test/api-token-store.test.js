

'use strict';



const test = require('node:test');



const assert = require('node:assert/strict');



const {

  createApiTokenStore

} = require('../src/api-token-store');



test('accepts only current registered Vault tokens', () => {

  const store = createApiTokenStore();



  const token1h = 'a'.repeat(64);



  const token6h = 'b'.repeat(64);



  store.set('1h', token1h, new Date(Date.now() + 60000));



  store.set('6h', token6h, new Date(Date.now() + 6 * 60 * 60 * 1000));



  assert.equal(store.activeCount(), 2);



  assert.equal(store.matches(token1h), true);



  assert.equal(store.matches(token6h), true);



  assert.equal(store.matches('c'.repeat(64)), false);



  assert.equal(store.matches('not-a-token'), false);



  store.clear();



  assert.equal(store.activeCount(), 0);



  assert.equal(store.matches(token1h), false);

});



test('replaces a profile token immediately on rotation', () => {

  const store = createApiTokenStore();



  const oldToken = '1'.repeat(64);



  const newToken = '2'.repeat(64);



  const expiry = new Date(Date.now() + 60000);



  store.set('1h', oldToken, expiry);



  assert.equal(store.matches(oldToken), true);



  store.set('1h', newToken, expiry);



  assert.equal(store.matches(oldToken), false);



  assert.equal(store.matches(newToken), true);

});



test('rejects expired tokens and tokens without expiry', () => {

  const store = createApiTokenStore();



  const token = 'f'.repeat(64);



  assert.throws(() => {

    store.set('1h', token, new Date(Date.now() - 1000));

  });



  assert.throws(() => {

    store.set('1h', token, null);

  });



  assert.equal(store.activeCount(), 0);

});



test('does not accept unknown profile names', () => {

  const store = createApiTokenStore();



  assert.throws(() => {

    store.set(

      '../unexpected',

      'a'.repeat(64),

      new Date(Date.now() + 60000)

    );

  });

});



test('expires tokens after their expiration time', async () => {

  const store = createApiTokenStore();



  const token = 'e'.repeat(64);



  store.set('1h', token, new Date(Date.now() + 25));



  assert.equal(store.matches(token), true);



  await new Promise(resolve => setTimeout(resolve, 40));



  assert.equal(store.matches(token), false);



  assert.equal(store.activeCount(), 0);

});



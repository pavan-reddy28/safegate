

'use strict';



const crypto = require('node:crypto');



const TOKEN_PATTERN = /^[a-fA-F0-9]{64}$/;



function toExpiryMilliseconds(value) {

  const timestamp = value instanceof Date

    ? value.getTime()

    : new Date(value).getTime();



  return Number.isFinite(timestamp) ? timestamp : null;

}



function createApiTokenStore() {

  const entries = new Map();



  function removeExpired(now = Date.now()) {

    for (const [profile, entry] of entries) {

      if (entry.expiresAt <= now) {

        entry.digest.fill(0);

        entries.delete(profile);

      }

    }

  }



  function set(profile, token, expiresAt) {

    if (

      typeof profile !== 'string' ||

      !/^[A-Za-z0-9_-]{1,32}$/.test(profile) ||

      typeof token !== 'string' ||

      !TOKEN_PATTERN.test(token)

    ) {

      throw new Error('Invalid API token update');

    }



    const expiry = toExpiryMilliseconds(expiresAt);



    if (expiry === null || expiry <= Date.now()) {

      throw new Error('API token expiry is invalid');

    }



    const digest = crypto.createHash('sha256')

      .update(token, 'utf8')

      .digest();



    const previous = entries.get(profile);



    if (previous) {

      previous.digest.fill(0);

    }



    entries.set(profile, {

      digest,

      expiresAt: expiry

    });

  }



  function matches(token) {

    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {

      return false;

    }



    removeExpired();



    const candidate = crypto.createHash('sha256')

      .update(token, 'utf8')

      .digest();



    let matched = false;



    try {

      for (const entry of entries.values()) {

        const currentMatch = crypto.timingSafeEqual(

          candidate,

          entry.digest

        );



        matched = currentMatch || matched;

      }

    } finally {

      candidate.fill(0);

    }



    return matched;

  }



  function activeCount() {

    removeExpired();

    return entries.size;

  }



  function clear() {

    for (const entry of entries.values()) {

      entry.digest.fill(0);

    }



    entries.clear();

  }



  return Object.freeze({

    set,

    matches,

    activeCount,

    clear

  });

}



module.exports = { createApiTokenStore };


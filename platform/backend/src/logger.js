'use strict';




const SERVICE = 'safegateway.platform';




const LEVELS = Object.freeze({


  INFO: 'INFO',


  WARN: 'WARN',


  ERROR: 'ERROR',


  FATAL: 'FATAL',


  DEBUG: 'DEBUG',


  IDLE: 'IDLE'


});




// Sensitive information must never enter application logs.


const SENSITIVE_KEYS = /authorization|access.?token|api.?key|api.?token|verification.?token|proof|private.?key|hmac|password|passwd|secret|cookie|raw.?url|full.?url|^url$|domain|destination.?host|registrable.?domain|fingerprint|hash|request.?body|response.?body|payload|client.?id|device.?id|tenant.?id|credential|token.?value/i;




// Do not log calendar dates or clock timestamps.


const DATE_TIME_KEYS = new Set([


  'timestamp',


  'datetime',


  'date',


  'time',


  'eventtime',


  'createdat',


  'updatedat',


  'generatedat',


  'expiresat',


  'nextrunat',


  'createdon',


  'updatedon',


  'starttime',


  'endtime'


]);




function redactString(value) {




  return String(value)




    .replace(


      /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,


      'Bearer [REDACTED]'


    )




    .replace(


      /\bhttps?:\/\/[^\s"'<>]+/gi,


      '[REDACTED_URL]'


    )




    .replace(


      /\b[a-fA-F0-9]{64,}\b/g,


      '[REDACTED_SECRET]'


    )




    // Hide vendor and authentication terminology.


    .replace(


      /(?:azure|key[\s_-]?vault|service[\s_-]?principal)/gi,


      '[REDACTED_COMPONENT]'


    )




    .replace(


      /@azure\/[^\s"'<>]+/gi,


      '[REDACTED_COMPONENT]'


    )




    // Remove date and time strings from log messages.


    .replace(


      /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,


      '[REDACTED_DATETIME]'


    );


}




function normalizeKey(key) {


  return String(key)


    .replace(/[_-]/g, '')


    .toLowerCase();


}




function sanitize(value, key = '', seen = new WeakSet()) {




  if (key && SENSITIVE_KEYS.test(key)) {


    return '[REDACTED]';


  }




  if (key && DATE_TIME_KEYS.has(normalizeKey(key))) {


    return '[REDACTED]';


  }




  if (value === null || value === undefined) {


    return value;


  }




  if (typeof value === 'string') {


    return redactString(value);


  }




  if (


    typeof value === 'number' ||


    typeof value === 'boolean'


  ) {


    return value;


  }




  if (typeof value === 'bigint') {


    return value.toString();


  }




  if (value instanceof Error) {




    // Never log stacks or raw provider error messages.


    return {


      name: redactString(value.name || 'Error'),


      code: value.code || 'INTERNAL_ERROR'


    };


  }




  if (typeof value !== 'object') {


    return String(value);


  }




  if (seen.has(value)) {


    return '[Circular reference]';


  }




  seen.add(value);




  let result;




  if (Array.isArray(value)) {




    result = value.map(item =>


      sanitize(item, '', seen)


    );




  } else {




    result = {};




    for (const [property, propertyValue] of Object.entries(value)) {




      const safeProperty = redactString(property);




      const outputKey = safeProperty.includes('[REDACTED')


        ? 'redactedField'


        : property;




      result[outputKey] = sanitize(


        propertyValue,


        property,


        seen


      );


    }


  }




  seen.delete(value);




  return result;


}




function resolveLevel(level, metadata) {




  const requestedLevel =


    String(level || 'INFO').toUpperCase();




  if (


    requestedLevel !== 'INFO' ||


    !metadata


  ) {


    return LEVELS[requestedLevel]


      ? requestedLevel


      : 'INFO';


  }




  const status = Number(


    metadata.status ?? metadata.statusCode


  );




  if (Number.isInteger(status)) {




    if (status >= 500) return 'ERROR';




    if (status >= 400) return 'WARN';


  }




  return 'INFO';


}




function write(level, message, metadata = {}) {




  const safeMetadata = sanitize(metadata);




  const finalLevel = resolveLevel(


    level,


    metadata


  );




  let finalMessage = redactString(


    message || 'Log event'


  );




  if (


    message === 'API request completed' &&


    metadata


  ) {




    const status = Number(


      metadata.status ?? metadata.statusCode


    );




    if (status >= 500) {


      finalMessage = 'API request failed';


    } else if (status >= 400) {


      finalMessage = 'API request rejected';


    }


  }




  if (


    finalLevel === 'IDLE' &&


    safeMetadata &&


    typeof safeMetadata === 'object'


  ) {


    safeMetadata.severity = 'IDLE';


  }




  let extra = '';




  if (


    safeMetadata &&


    typeof safeMetadata === 'object' &&


    Object.keys(safeMetadata).length > 0


  ) {




    try {


      extra = ' ' + JSON.stringify(safeMetadata);


    } catch {


      extra = ' {"metadata":"[UNAVAILABLE]"}';


    }


  }




  // No date, clock time or timestamp.


  const line =


    `[${finalLevel}] ` +


    `[${SERVICE}] ${finalMessage}${extra}\n`;




  process.stdout.write(line);


}




module.exports = {




  info: (message, metadata) =>


    write('INFO', message, metadata),




  warn: (message, metadata) =>


    write('WARN', message, metadata),




  error: (message, metadata) =>


    write('ERROR', message, metadata),




  fatal: (message, metadata) =>


    write('FATAL', message, metadata),




  idle: (message, metadata) =>


    write('IDLE', message, metadata),




  debug: (message, metadata) => {


    if (process.env.LOG_LEVEL === 'debug') {


      write('DEBUG', message, metadata);


    }


  }




};


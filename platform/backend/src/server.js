

'use strict';



const logger = require('./logger');



const { loadConfig } = require('./config');



const { initializeDatabase } = require('./database');



const { createApp } = require('./app');



const { createApiTokenStore } = require('./api-token-store');



const {

  createTokenRotator

} = require('./token-rotator');



let server = null;



let database = null;



let heartbeat = null;



let tokenRotator = null;



let apiTokenStore = null;



let shuttingDown = false;



// SAFE ERROR DETAILS

function getErrorDetails(error) {

  return {

    errorName: error?.name || 'Error',

    errorCode: error?.code || 'INTERNAL_ERROR'

  };

}



// FINAL SHUTDOWN

async function closeDatabase(exitCode) {

  let finalExitCode = exitCode;



  try {

    if (tokenRotator) {

      await tokenRotator.stop();



      logger.info('Rotation service stopped');

    }



  } catch (error) {

    logger.error(

      'Rotation service shutdown failed',

      getErrorDetails(error)

    );



    finalExitCode = 1;

  }



  try {

    if (apiTokenStore) {

      apiTokenStore.clear();

      apiTokenStore = null;

    }



    if (

      database &&

      typeof database.close === 'function'

    ) {

      database.close();



      logger.info('SQLite connection closed');

    }



    logger.info('Platform shutdown completed');



  } catch (error) {

    logger.error(

      'Database shutdown failed',

      getErrorDetails(error)

    );



    finalExitCode = 1;

  }



  process.exit(finalExitCode);

}



// SHUTDOWN HANDLER

function shutdown(signal, exitCode = 0) {

  if (shuttingDown) return;



  shuttingDown = true;



  logger.warn('Shutdown initiated', {

    signal,

    state: 'SHUTTING_DOWN'

  });



  if (heartbeat) {

    clearInterval(heartbeat);

    heartbeat = null;

  }



  if (tokenRotator) {

    tokenRotator.stop().catch(error => {

      logger.error(

        'Rotation stop failed',

        getErrorDetails(error)

      );

    });

  }



  if (server && server.listening) {

    server.close(error => {

      if (error) {

        logger.error(

          'HTTP service shutdown failed',

          getErrorDetails(error)

        );



        void closeDatabase(1);

        return;

      }



      void closeDatabase(exitCode);

    });



    return;

  }



  void closeDatabase(exitCode);

}



// APPLICATION BOOTSTRAP

async function bootstrap() {

  logger.info('================================================');



  logger.info('SafeGate Platform | Starting application');



  logger.info('================================================');



  logger.info('Platform bootstrap initiated', {

    state: 'INITIALIZING'

  });



  // 1. Load configuration.

  const config = loadConfig(logger);



  // 2. Initialize SQLite.

  database = initializeDatabase(

    config,

    logger

  );



  // 3. Initialize the in-memory token store and rotation service.

  apiTokenStore = createApiTokenStore();



  tokenRotator = createTokenRotator(

    config.vault,

    logger,

    {

      onToken: ({ profile, token, expiresAt }) => {

        apiTokenStore.set(profile, token, expiresAt);

      }

    }

  );



  await tokenRotator.start();



  // Fail closed: do not listen unless at least one current token is loaded.

  if (apiTokenStore.activeCount() < 1) {

    throw new Error('No active API credentials are available');

  }



  logger.info('Active API credentials loaded', {

    profiles: apiTokenStore.activeCount()

  });



  // 4. Initialize the application.

  const metrics = {

    requestsSinceHeartbeat: 0

  };



  const app = createApp({

    config,

    db: database,

    logger,

    metrics,

    apiTokenStore

  });



  // 5. Start HTTP server.

  server = app.listen(

    config.port,

    '0.0.0.0',

    () => {

      logger.info('HTTP service initialized', {

        environment: config.nodeEnv,

        status: 'READY'

      });



      logger.info('Application initialization completed');



      logger.info('Platform status: READY', {

        health: 'READY',

        database: 'CONNECTED',

        vaultRotation: 'INITIALIZED'

      });

    }

  );



  server.on('error', error => {

    logger.fatal(

      'HTTP service encountered a fatal error',

      getErrorDetails(error)

    );



    shutdown('HTTP_SERVER_ERROR', 1);

  });



  // HEARTBEAT

  heartbeat = setInterval(() => {

    const requests =

      metrics.requestsSinceHeartbeat || 0;



    metrics.requestsSinceHeartbeat = 0;



    if (requests === 0) {

      logger.idle(

        'Runtime idle | Service healthy; no API activity detected',

        {

          state: 'IDLE',

          health: 'READY',

          database: 'CONNECTED',

          requests: 0

        }

      );



      return;

    }



    logger.info(

      'Runtime heartbeat | API activity observed',

      {

        state: 'ACTIVE',

        requests

      }

    );



  }, config.idleIntervalMs);



  heartbeat.unref();



  logger.info('Runtime monitoring initialized', {

    state: 'ACTIVE',

    heartbeat: 'ENABLED',

    vaultRotation: 'ENABLED'

  });



  process.once('SIGTERM', () => {

    shutdown('SIGTERM', 0);

  });



  process.once('SIGINT', () => {

    shutdown('SIGINT', 0);

  });

}



// PROCESS ERROR HANDLING

process.on('uncaughtException', error => {

  logger.fatal(

    'Uncaught application exception',

    getErrorDetails(error)

  );



  shutdown('UNCAUGHT_EXCEPTION', 1);

});



process.on('unhandledRejection', reason => {

  logger.fatal(

    'Unhandled promise rejection',

    getErrorDetails(reason)

  );



  shutdown('UNHANDLED_REJECTION', 1);

});



// START APPLICATION

bootstrap().catch(error => {

  logger.fatal(

    'Platform bootstrap failed',

    getErrorDetails(error)

  );



  shutdown('BOOTSTRAP_FAILURE', 1);

});


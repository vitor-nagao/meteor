// URL parsing and validation
// RPC to server (endpoint, arguments)
// see if RPC requires password
// prompt for password
// send RPC with or without password as required

import {
  pathJoin,
  createTarGzStream,
  getSettings,
  mkdtemp,
} from '../fs/files.js';
import { request } from '../utils/http-helpers.js';
import buildmessage from '../utils/buildmessage.js';
import {
  pollForRegistrationCompletion,
  doInteractivePasswordLogin,
  loggedInUsername,
  isLoggedIn,
  maybePrintRegistrationLink,
} from './auth.js';
import { recordPackages } from './stats.js';
import { Console } from '../console/console.js';
import { setTimeout } from 'timers';
var fiberHelpers = require('../utils/fiber-helpers.js');

const hasOwn = Object.prototype.hasOwnProperty;

const CAPABILITIES = ['showDeployMessages', 'canTransferAuthorization'];

// Make a synchronous RPC to the "classic" MDG deploy API. The deploy
// API has the following contract:
//
// - Parameters are always sent in the query string.
// - A tarball can be sent in the body (when deploying an app).
// - On success, all calls return HTTP 200. Those that return a value
//   either return a JSON payload or a plaintext payload and the
//   Content-Type header is set appropriately.
// - On failure, calls return some non-200 HTTP status code and
//   provide a human-readable error message in the body.
// - URLs are of the form "/[operation]/[site]".
// - Body encodings are always utf8.
// - Meteor Accounts auth is possible using first-party MDG cookies
//   (rather than OAuth).
//
// Options include:
// - method: GET, POST, or DELETE. default GET
// - operation: "info", "logs", "mongo", "deploy", "authorized-apps", "version-status"
// - site: site name, version ID
// - expectPayload: an array of key names. if present, then we expect
//   the server to return JSON content on success and to return an
//   object with all of these key names.
// - expectMessage: if true, then we expect the server to return text
//   content on success.
// - bodyStream: if provided, a stream to use as the request body
// - any other parameters accepted by the node 'request' module, for example
//   'qs' to set query string parameters
// - printDeployURL: provided if we should show the deploy URL; set this
//   for the first RPC of any user command
//
// Waits until server responds, then returns an object with the
// following keys:
//
// - statusCode: HTTP status code, or null if the server couldn't be
//   contacted
// - payload: if successful, and the server returned a JSON body, the
//   parsed JSON body
// - message: if successful, and the server returned a text body, the
//   body as a string
// - errorMessage: if unsuccessful, a human-readable error message,
//   derived from either a transport-level exception, the response
//   body, or a generic 'try again later' message, as appropriate

function deployRpc(options) {
  options = Object.assign({}, options);
  options.headers = Object.assign({}, options.headers || {});
  if (options.headers.cookie) {
    throw new Error("sorry, can't combine cookie headers yet");
  }
  options.qs = Object.assign({}, options.qs, {capabilities: CAPABILITIES});

  const deployURLBase = getDeployURL(options.site).await();

  if (options.printDeployURL) {
    Console.info("Talking to Galaxy servers at " + deployURLBase);
  }

  // XXX: Reintroduce progress for upload
  try {
    var result = request(Object.assign(options, {
      url: deployURLBase + '/' + options.operation +
        (options.site ? ('/' + options.site) : ''),
      method: options.method || 'GET',
      bodyStream: options.bodyStream,
      useAuthHeader: true,
      encoding: 'utf8' // Hack, but good enough for the deploy server..
    }));
  } catch (e) {
    return {
      statusCode: null,
      errorMessage: "Connection error (" + e.message + ")"
    };
  }

  var response = result.response;
  var body = result.body;
  var ret = { statusCode: response.statusCode };

  if (response.statusCode !== 200) {
    if (body.length > 0) {
      ret.errorMessage = body;
    } else {
      ret.errorMessage = "Server error " + response.statusCode +
        " (please try again later)";
    }
    return ret;
  }

  var contentType = response.headers["content-type"] || '';
  if (contentType === "application/json; charset=utf-8") {
    try {
      ret.payload = JSON.parse(body);
    } catch (e) {
      ret.errorMessage =
        "Server error (please try again later)\n"
        + "Invalid JSON: " + body;
      return ret;
    }
  } else if (contentType === "text/plain; charset=utf-8") {
    ret.message = body;
  }

  const hasAllExpectedKeys =
    (options.expectPayload || [])
      .map(key => ret.payload && hasOwn.call(ret.payload, key))
      .every(x => x);

  if ((options.expectPayload && ! hasOwn.call(ret, 'payload')) ||
      (options.expectMessage && ! hasOwn.call(ret, 'message')) ||
      ! hasAllExpectedKeys) {
    delete ret.payload;
    delete ret.message;

    ret.errorMessage = "Server error (please try again later)\n" +
      "Response missing expected keys.";
  }

  return ret;
};

// Just like deployRpc, but also presents authentication. It will
// prompt the user for a password, or use a Meteor Accounts
// credential, as necessary.
//
// Additional options (beyond deployRpc):
//
// - preflight: if true, do everything but the actual RPC. The only
//   other necessary option is 'site'. On failure, returns an object
//   with errorMessage (just like deployRpc). On success, returns an
//   object without an errorMessage key and with possible keys
//   'protection' (value either 'password' or 'account') and
//   'authorized' (true if the current user is an authorized user on
//   this app).
// - promptIfAuthFails: if true, then we think we are logged in with the
//   accounts server but our authentication actually fails, then prompt
//   the user to log in with a username and password and then resend the
//   RPC.
function authedRpc(options) {
  var rpcOptions = Object.assign({}, options);
  var preflight = rpcOptions.preflight;
  delete rpcOptions.preflight;

  // Fetch auth info
  var infoResult = deployRpc({
    operation: 'info',
    site: rpcOptions.site,
    expectPayload: [],
    qs: options.qs,
    printDeployURL: options.printDeployURL
  });
  delete rpcOptions.printDeployURL;

  if (infoResult.statusCode === 401 && rpcOptions.promptIfAuthFails) {
    Console.error("Authentication failed or login token expired.");

    if (!Console.isInteractive()) {
      return {
        statusCode: 401,
        errorMessage: "login failed."
      };
    }

    // Our authentication didn't validate, so prompt the user to log in
    // again, and resend the RPC if the login succeeds.
    var username = Console.readLine({
      prompt: "Username: ",
      stream: process.stderr
    });
    var loginOptions = {
      username: username,
      suppressErrorMessage: true
    };
    if (doInteractivePasswordLogin(loginOptions)) {
      return authedRpc(options);
    } else {
      return {
        statusCode: 403,
        errorMessage: "login failed."
      };
    }
  }

  if (infoResult.statusCode === 404) {
    // Doesn't exist, therefore not protected.
    return preflight ? { } : deployRpc(rpcOptions);
  }

  if (infoResult.errorMessage) {
    return infoResult;
  }
  var info = infoResult.payload;

  if (! hasOwn.call(info, 'protection')) {
    // Not protected.
    //
    // XXX should prompt the user to claim the app (only if deploying?)
    return preflight ? { } : deployRpc(rpcOptions);
  }

  if (info.protection === "account") {
    if (! hasOwn.call(info, 'authorized')) {
      // Absence of this implies that we are not an authorized user on
      // this app
      if (preflight) {
        return { protection: info.protection };
      } else {
        return {
          statusCode: null,
          errorMessage: isLoggedIn() ?
            // XXX better error message (probably need to break out of
            // the 'errorMessage printed with brief prefix' pattern)
            "Not an authorized user on this site" :
            "Not logged in"
        };
      }
    }

    // Sweet, we're an authorized user.
    if (preflight) {
      return {
        protection: info.protection,
        authorized: info.authorized
      };
    } else {
      return deployRpc(rpcOptions);
    }
  }

  return {
    statusCode: null,
    errorMessage: "You need a newer version of Meteor to work with this site"
  };
};

// When the user is trying to do something with an app that they are not
// authorized for, instruct them to get added via 'meteor authorized
// --add' or switch accounts.
function printUnauthorizedMessage() {
  var username = loggedInUsername();
  Console.error("Sorry, that site belongs to a different user.");
  if (username) {
    Console.error("You are currently logged in as " + username + ".");
  }
  Console.error();
  Console.error(
    "Either have the site owner use " +
    Console.command("'meteor authorized --add'") + " to add you as an " +
    "authorized developer for the site, or switch to an authorized account " +
    "with " + Console.command("'meteor login'") + ".");
};

// Take a proposed sitename for deploying to. If it looks
// syntactically good, canonicalize it (this essentially means
// stripping 'http://' or a trailing '/' if present) and return it. If
// not, print an error message to stderr and return null.
function canonicalizeSite(site) {
  // There are actually two different bugs here. One is that the meteor deploy
  // server does not support apps whose total site length is greater than 63
  // (because of how it generates Mongo database names); that can be fixed on
  // the server. After that, this check will be too strong, but we still will
  // want to check that each *component* of the hostname is at most 63
  // characters (url.parse will do something very strange if a component is
  // larger than 63, which is the maximum legal length).
  if (site.length > 63) {
    Console.error(
      "The maximum hostname length currently supported is 63 characters: " +
      site + " is too long. " +
      "Please try again with a shorter URL for your site.");
    return false;
  }

  var url = site;
  if (!url.match(':\/\/')) {
    url = 'http://' + url;
  }

  var parsed = require('url').parse(url);

  if (! parsed.hostname) {
    Console.info(
      "Please specify a domain to connect to, such as www.example.com or " +
      "http://www.example.com/");
    return false;
  }

  if (parsed.pathname != '/' || parsed.hash || parsed.query) {
    Console.info(
      "Sorry, Meteor does not yet support specific path URLs, such as " +
      Console.url("http://www.example.com/blog") + " .  Please specify the root of a domain.");
    return false;
  }

  return parsed.hostname;
};

// Creates a polling configuration with defaults if fields left unset
// Default initialWaitTime is 10 seconds – this is the time to wait before checking at all
// Default startInterval is 700 milliseconds – this is the first wait interval between polls
// Default backoffFactor is 1.3
// Default timeout is 15 minutes
function PollingConfiguration(
  timeoutMillis,
  initialWaitTimeMillis,
  startIntervalMillis,
  backoffFactor) {
    const fifteenMinutesMillis = 15*60*1000;
    this.initialWaitTimeMillis = initialWaitTimeMillis || 10*1000;
    this.startIntervalMillis = startIntervalMillis || 700;
    this.backoffFactor = backoffFactor || 1.3;
    this.timeoutMillis = timeoutMillis || fifteenMinutesMillis;
  }

// Build statuses that indicate we should stop polling for build
const terminalBuildStatuses = ['failed-permanently', 'success']
// Deploy statuses that indicate we should stop polling for deploy
const terminalDeployStatuses = ['success', 'failed', 'aborted']

// Declare tracking variables for the duration of the poll
// `start` tracks the time when we started polling so we can know when to time out
// `pollingRounds` tracks the number of rounds we have polled, resetting when build/deploy succeed
// `currentStatus` tracks what the current status is of the build and the deploy for this version
let start, pollingRounds, currentStatus;

// Poll the "version-status" endpoint for the build and deploy status
// of a specified version ID with a polling configuration.
// This will only end successfully when the version being polled is marked as the
// active version by Galaxy. If the build / deploy fails, then the poll
// will exit. At the end of the poll, this function will return a JSON object
// which contains a `buildStatus` string, `deployStatus` string, and `isActive` boolean
function pollForDeploy(pollingConfiguration, versionId, firstRun = true) {
  let {timeoutMillis,
    initialWaitTimeMillis,
    startIntervalMillis,
    backoffFactor}
    = pollingConfiguration
  // If this is the first poll, we will wait for initialWaitTimeMillis before beginning
  // We also want to initialize all of our tracking variables
  if(firstRun) {
    // Set up tracking variables to persist and be updated throughout polling
    start = new Date().getTime();
    pollingRounds = 1;
    currentStatus = {buildStatus: null, isActive: false};
    
    // Timeouts must be done within Promises, so we set a dummy Promise to
    // wait before initiating polling
    return new Promise(function (resolve) {
      let timer = setTimeout(() => resolve(null), initialWaitTimeMillis);
    }).then(fiberHelpers.bindEnvironment(function() {
      return pollForDeploy(pollingConfiguration, versionId, false);
    })).await();
  } else {
    // Do a call to the version-status endpoint for the specified versionId
    let versionStatusResult = deployRpc({
      method: 'GET',
      operation: 'version-status',
      site: versionId,
      expectPayload: [],
      printDeployURL: false,
    })
    // We've done one call, so update the number of polling rounds
    pollingRounds++;
    let terminal = false;

    //Check the details of the Version Status response and compare to last call
    if(versionStatusResult &&
      versionStatusResult.payload &&
      versionStatusResult.payload.buildStatus) {
      // Collect all of the statuses from the returned rpc call
      const {buildStatus, deployStatus, isActive} = versionStatusResult.payload;

      // If the build status has changed, we should report on that change to the user
      // Allowable values for buildStatus are :
      // ['missing', 'failed-temporarily', 'failed-permanently', 'success', 'building']
      //    We will ignore the 'missing' buildStatus, and treat 'failed-temporarily'
      //    the same as we do 'building', trusting the server to change the status.
      if(currentStatus.buildStatus !== buildStatus) {
        // Update our tracking variable for buildStatus
        currentStatus.buildStatus = buildStatus;
        // If we have reached a terminal buildStatus, handle it
        if (terminalBuildStatuses.indexOf(buildStatus) >= 0) {
          if(buildStatus == 'success') {
            Console.info('Successfully built app image, initiating deploy');
            // Reset the polling rounds to poll faster for a change in deployStatus
            // Basically, we don't necessarily expect deploying to take a long time simply
            // because building did.
            pollingRounds = 1;
          } else {
            // Any other terminal status is failure, so report on it
            Console.info(`Your app failed to build, with buildStatus: ${buildStatus}`);
            // We also want to stop polling, since deploy cannot succeed with a failed build
            terminal = true;
          }
        } else if (buildStatus !== 'building') {
          // This will report if the buildStatus changes to a non-terminal, unexpected state
          //    e.g. failed-temporarily
          Console.info(`Build state changed to nonterminal state: ${buildStatus}`)
        }
      } else if(currentStatus.deployStatus !== deployStatus) {
        // Deploy status is treated similarly to buildStatus above
        currentStatus.deployStatus = deployStatus;
        if (terminalDeployStatuses.indexOf(deployStatus) >= 0) {
          if(deployStatus == 'success') {
            Console.info('Your app has been deployed successfully.' +
              ' Waiting for new version to be active...');
            // Reset the polling rounds to poll faster for a change in isActive
            pollingRounds = 1;
          } else {
            Console.info(`Your app has failed to deploy, with deployStatus: ${deployStatus}`);
            terminal = true;
          }
        } else if(deployStatus !== 'deploying') {
          Console.info(`Deploy status changed to nonterminal state: ${deployStatus}`)
        }
      } else if(currentStatus.isActive !== isActive) {
        currentStatus.isActive = isActive;
        // isActive was initialized to false, so it can only be true
        Console.info('Your deployed version is now active.');
        terminal = true;
      }
    } else {
      // If we did not get a valid Version Status response, just fail silently
      // keep polling as per usual – this may have just been a whiff from Galaxy
    }

    let elapsed = new Date().getTime() - start;
    // Poll again if version status isn't in a terminal state and we haven't exceeded the timeout
    if(elapsed < timeoutMillis && !terminal) {
      let newWaitTime = startIntervalMillis*Math.pow(backoffFactor, pollingRounds);

      // Wait for exponentially increasingly more time, and then poll again
      return new Promise(function (resolve) {
        let timer = setTimeout(() => resolve(null), newWaitTime);
      }).then(fiberHelpers.bindEnvironment(function() {
        return pollForDeploy(pollingConfiguration, versionId, false);
      })).await();

    } else if (terminal) {
      return versionStatusResult.payload;
    } else {
      Console.info('Polling timed out without reaching terminal status.');
      return versionStatusResult.payload;
    }
  }
}


// Run the bundler and deploy the result. Print progress
// messages. Return a command exit code.
//
// Options:
// - projectContext: the ProjectContext for the app
// - site: site to deploy as
// - settingsFile: file from which to read deploy settings (undefined
//   to leave unchanged from previous deploy of the app, if any)
// - recordPackageUsage: (defaults to true) if set to false, don't
//   send information about packages used by this app to the package
//   stats server.
// - buildOptions: the 'buildOptions' argument to the bundler
// - rawOptions: any unknown options that were passed to the command line tool
export function bundleAndDeploy(options) {
  if (options.recordPackageUsage === undefined) {
    options.recordPackageUsage = true;
  }

  var site = canonicalizeSite(options.site);
  if (! site) {
    return 1;
  }

  // We should give a username/password prompt if the user was logged in
  // but the credentials are expired, unless the user is logged in but
  // doesn't have a username (in which case they should hit the email
  // prompt -- a user without a username shouldn't be given a username
  // prompt). There's an edge case where things happen in the following
  // order: user creates account, user sets username, credential expires
  // or is revoked, user comes back to deploy again. In that case,
  // they'll get an email prompt instead of a username prompt because
  // the command-line tool didn't have time to learn about their
  // username before the credential was expired.
  pollForRegistrationCompletion({
    noLogout: true
  });
  var promptIfAuthFails = (loggedInUsername() !== null);

  // Check auth up front, rather than after the (potentially lengthy)
  // bundling process.
  var preflight = authedRpc({
    site: site,
    preflight: true,
    promptIfAuthFails: promptIfAuthFails,
    qs: options.rawOptions,
    printDeployURL: true
  });

  if (preflight.errorMessage) {
    Console.error("Error deploying application: " + preflight.errorMessage);
    return 1;
  }

  if (preflight.protection === "account" &&
             ! preflight.authorized) {
    printUnauthorizedMessage();
    return 1;
  }

  var buildDir = mkdtemp('build_tar');
  var bundlePath = pathJoin(buildDir, 'bundle');

  Console.info('Deploying your app...');

  var settings = null;
  var messages = buildmessage.capture({
    title: "preparing to deploy",
    rootPath: process.cwd()
  }, function () {
    if (options.settingsFile) {
      settings = getSettings(options.settingsFile);
    }
  });

  if (! messages.hasMessages()) {
    var bundler = require('../isobuild/bundler.js');

    var bundleResult = bundler.bundle({
      projectContext: options.projectContext,
      outputPath: bundlePath,
      buildOptions: options.buildOptions,
    });

    if (bundleResult.errors) {
      messages = bundleResult.errors;
    }
  }

  if (messages.hasMessages()) {
    Console.info("\nErrors prevented deploying:");
    Console.info(messages.formatMessages());
    return 1;
  }

  if (options.recordPackageUsage) {
    recordPackages({
      what: "sdk.deploy",
      projectContext: options.projectContext,
      site: site
    });
  }

  var result = buildmessage.enterJob({ title: "uploading" }, function () {
    return authedRpc({
      method: 'POST',
      operation: 'deploy',
      site: site,
      qs: Object.assign({}, options.rawOptions, settings !== null ? {settings: settings} : {}),
      bodyStream: createTarGzStream(pathJoin(buildDir, 'bundle')),
      expectPayload: ['url'],
      preflightPassword: preflight.preflightPassword,
      // Disable the HTTP timeout for this POST request.
      timeout: null,
    });
  });

  if (result.errorMessage) {
    Console.error("\nError deploying application: " + result.errorMessage);
    return 1;
  }

  // After an upload succeeds, we want to poll Galaxy to see if the build / deploy succeeds
  // We used to indicate that the upload was finished via a message to check Galaxy
  if (result.payload.message) {
    // If there is a newVersionId, then poll for status of the app
    if(result.payload.newVersionId) {
      // Create a default polling configuration for polling for deploy / build
      // In the future, we may change this to be user-configurable or smart
      let pollingConfiguration = new PollingConfiguration();

      var deploymentPollResult = buildmessage.enterJob({
        title: "Waiting for Deploy to succeed..."}, 
        function() {
          return pollForDeploy(pollingConfiguration,
            result.payload.newVersionId,
            true);
        });

      if(deploymentPollResult && deploymentPollResult.isActive) {
        // The deploy succeeded and the deployed version is now active
        const {newVersionNum, hostname, username, region, galaxyUrl} = result.payload;
        var successfulDeploymentMessage = `
        ******************************************************************************
        You have successfully upgraded your app to version ${newVersionNum}.
        Hostname: ${hostname}, Region: ${region}, Username: ${username}
        To see the status of your app, visit your app's page on Galaxy
        \t\t${galaxyUrl}.
        ******************************************************************************
        `
        Console.info(successfulDeploymentMessage);
      } else {
        // The deploy did not succeed or the polling timed out
        if(deploymentPollResult.buildStatus === 'failed-permanently' ||
          deploymentPollResult.deployStatus === 'failed') {
            const {newVersionNum, hostname, username, region, galaxyUrl} = result.payload;
            var failedDeploymentMessage = `
            ******************************************************************************
            Failed to deploy your app to version ${newVersionNum}. No changes were made.
            Hostname: ${hostname}, Region: ${region}, Username: ${username}
            To see the logs for your app, visit ${galaxyUrl}/logs.
            ******************************************************************************
            `
            Console.info(successfulDeploymentMessage);
          } else {
            // The status was non-terminal, so we most likely timed out
            Console.info('most likely timed out!')
            Console.info(result.payload.message);
            return 1;
          }
      }
    } else {
      // The previous path
      Console.info(result.payload.message);
      return 1;
    }
  } else {
    var deployedAt = require('url').parse(result.payload.url);
    var hostname = deployedAt.hostname;

    Console.info('Now serving at http://' + hostname);

    if (! hostname.match(/meteor\.com$/)) {
      var dns = require('dns');
      dns.resolve(hostname, 'CNAME', function (err, cnames) {
        if (err || cnames[0] !== 'origin.meteor.com') {
          dns.resolve(hostname, 'A', function (err, addresses) {
            if (err || addresses[0] !== '107.22.210.133') {
              Console.info('-------------');
              Console.info(
                "You've deployed to a custom domain.",
                "Please be sure to CNAME your hostname",
                "to origin.meteor.com, or set an A record to 107.22.210.133.");
              Console.info('-------------');
            }
          });
        }
      });
    }
  }
  
  return 0;
};

export function deleteApp(site) {
  site = canonicalizeSite(site);
  if (! site) {
    return 1;
  }

  var result = authedRpc({
    method: 'DELETE',
    operation: 'deploy',
    site: site,
    promptIfAuthFails: true,
    printDeployURL: true
  });

  if (result.errorMessage) {
    Console.error("Couldn't delete application: " + result.errorMessage);
    return 1;
  }

  Console.info("Deleted.");
  return 0;
};

// Helper that does a preflight request to check auth, and prints the
// appropriate error message if auth fails or if this is a legacy
// password-protected app. If auth succeeds, then it runs the actual
// RPC. 'site' and 'operation' are the site and operation for the
// RPC. 'what' is a string describing the operation, for use in error
// messages.  Returns the result of the RPC if successful, or null
// otherwise (including if auth failed or if the user is not authorized
// for this site).
function checkAuthThenSendRpc(site, operation, what) {
  var preflight = authedRpc({
    operation: operation,
    site: site,
    preflight: true,
    promptIfAuthFails: true,
    printDeployURL: true
  });

  if (preflight.errorMessage) {
    Console.error("Couldn't " + what + ": " + preflight.errorMessage);
    return null;
  }

  if (preflight.protection === "account" &&
             ! preflight.authorized) {
    if (! isLoggedIn()) {
      // Maybe the user is authorized for this app but not logged in
      // yet, so give them a login prompt.
      var loginResult = doUsernamePasswordLogin({ retry: true });
      if (loginResult) {
        // Once we've logged in, retry the whole operation. We need to
        // do the preflight request again instead of immediately moving
        // on to the real RPC because we don't yet know if the newly
        // logged-in user is authorized for this app, and if they
        // aren't, then we want to print the nice unauthorized error
        // message.
        return checkAuthThenSendRpc(site, operation, what);
      } else {
        // Shouldn't ever get here because we set the retry flag on the
        // login, but just in case.
        Console.error(
          "\nYou must be logged in to " + what + " for this app. Use " +
           Console.command("'meteor login'") + "to log in.");
        Console.error();
        Console.error(
          "If you don't have a Meteor developer account yet, you can quickly " +
          "create one at www.meteor.com.");
        return null;
      }
    } else { // User is logged in but not authorized for this app
      Console.error();
      printUnauthorizedMessage();
      return null;
    }
  }

  // User is authorized for the app; go ahead and do the actual RPC.

  var result = authedRpc({
    operation: operation,
    site: site,
    expectMessage: true,
    promptIfAuthFails: true
  });

  if (result.errorMessage) {
    Console.error("Couldn't " + what + ": " + result.errorMessage);
    return null;
  }

  return result;
};

// On failure, prints a message to stderr and returns null. Otherwise,
// returns a temporary authenticated Mongo URL allowing access to this
// site's database.
export function temporaryMongoUrl(site) {
  site = canonicalizeSite(site);
  if (! site) {
    // canonicalizeSite printed an error
    return null;
  }

  var result = checkAuthThenSendRpc(site, 'mongo', 'open a mongo connection');

  if (result !== null) {
    return result.message;
  } else {
    return null;
  }
};

export function logs(site) {
  site = canonicalizeSite(site);
  if (! site) {
    return 1;
  }

  var result = checkAuthThenSendRpc(site, 'logs', 'view logs');

  if (result === null) {
    return 1;
  } else {
    Console.info(result.message);
    maybePrintRegistrationLink({ leadingNewline: true });
    return 0;
  }
};

export function listAuthorized(site) {
  site = canonicalizeSite(site);
  if (! site) {
    return 1;
  }

  var result = deployRpc({
    operation: 'info',
    site: site,
    expectPayload: [],
    printDeployURL: true
  });
  if (result.errorMessage) {
    Console.error("Couldn't get authorized users list: " + result.errorMessage);
    return 1;
  }
  var info = result.payload;

  if (! hasOwn.call(info, 'protection')) {
    Console.info("<anyone>");
    return 0;
  }

  if (info.protection === "account") {
    if (! hasOwn.call(info, 'authorized')) {
      Console.error("Couldn't get authorized users list: " +
                    "You are not authorized");
      return 1;
    }

    Console.info((loggedInUsername() || "<you>"));
    info.authorized.forEach(username => {
      if (username) {
        // Current username rules don't let you register anything that we might
        // want to split over multiple lines (ex: containing a space), but we
        // don't want confusion if we ever change some implementation detail.
        Console.rawInfo(username + "\n");
      }
    });
    return 0;
  }
};

// action is "add", "transfer" or "remove"
export function changeAuthorized(site, action, username) {
  site = canonicalizeSite(site);
  if (! site) {
    // canonicalizeSite will have already printed an error
    return 1;
  }

  var result = authedRpc({
    method: 'POST',
    operation: 'authorized',
    site: site,
    qs: {[action]: username},
    promptIfAuthFails: true,
    printDeployURL: true
  });

  if (result.errorMessage) {
    Console.error("Couldn't change authorized users: " + result.errorMessage);
    return 1;
  }

  const verbs = {
    add: "added",
    remove: "removed",
    transfer: "transferred"
  };
  Console.info(`${site}: ${verbs[action]} ${username}`);
  return 0;
};

export function listSites() {
  var result = deployRpc({
    method: "GET",
    operation: "authorized-apps",
    promptIfAuthFails: true,
    expectPayload: ["sites"]
  });

  if (result.errorMessage) {
    Console.error("Couldn't list sites: " + result.errorMessage);
    return 1;
  }

  if (! result.payload ||
      ! result.payload.sites ||
      ! result.payload.sites.length) {
    Console.info("You don't have any sites yet.");
  } else {
    result.payload.sites
      .sort()
      .forEach(site => Console.info(site));
  }
  return 0;
};

// Given a hostname, add "http://" or "https://" as
// appropriate. (localhost gets http; anything else is always https.)
function addScheme(hostOrURL) {
  if (hostOrURL.match(/^http/)) {
    return hostOrURL;
  } else if (hostOrURL.match(/^localhost(:\d+)?$/)) {
    return "http://" + hostOrURL;
  } else {
    return "https://" + hostOrURL;
  }
};

// Maps from "site" to Promise<deploy URL>, so we don't have to re-ping on each
// RPC (even if the calls to getDeployURL overlap).
const galaxyDiscoveryCache = new Map;

// getDeployURL returns the a Promise for the base deploy URL for the given app.
// "app" may be falsey for certain RPCs (eg meteor list-sites).
function getDeployURL(site) {
  // Always trust explicitly configuration via env.
  if (process.env.DEPLOY_HOSTNAME) {
    return Promise.resolve(addScheme(process.env.DEPLOY_HOSTNAME.trim()));
  }

  const defaultURL = "https://us-east-1.galaxy-deploy.meteor.com";

  // No site? Just use the default.
  if (!site) {
    return Promise.resolve(defaultURL);
  }

  // If we have a site, we can try to do Galaxy discovery.

  // Do we already have an answer?
  if (galaxyDiscoveryCache.has(site)) {
    return galaxyDiscoveryCache.get(site);
  }

  // Otherwise, try https first, then http, then just use the default.
  const p = discoverGalaxy(site, "https")
          .catch(() => discoverGalaxy(site, "http"))
          .catch(() => defaultURL);
  galaxyDiscoveryCache.set(site, p);
  return p;
}

// discoverGalaxy returns the URL to use for Galaxy discovery, or an error if it
// couldn't be fetched.
async function discoverGalaxy(site, scheme) {
  const discoveryURL =
          scheme + "://" + site + "/.well-known/meteor/deploy-url";
  // If httpHelpers.request throws, the returned Promise will reject, which is
  // fine.
  const { response, body } = request({
    url: discoveryURL,
    json: true,
    strictSSL: true,
    // We don't want to be confused by, eg, a non-Galaxy-hosted site which
    // redirects to a Galaxy-hosted site.
    followRedirect: false
  });
  if (response.statusCode !== 200) {
    throw new Error("bad status code: " + response.statusCode);
  }
  if (!body) {
    throw new Error("response had no body");
  }
  if (body.galaxyDiscoveryVersion !== "galaxy-1") {
    throw new Error(
      "unexpected galaxyDiscoveryVersion: " + body.galaxyDiscoveryVersion);
  }
  if (! hasOwn.call(body, "deployURL")) {
    throw new Error("no deployURL");
  }
  return body.deployURL;
}

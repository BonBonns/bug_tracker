const bcrypt = require('bcrypt');
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
async function getHashedKey(key) {
    let hash;
    try {
        if (key) {
            let i = key.indexOf(":");
            if (i > 0) {
                let salt = key.slice(0, i);
                let text = key.slice(i + 1);
                hash = await bcrypt.hash(text, salt);
            }
        }
    } catch (err) {
        console.log("Error:", err);
    }
    return hash;
}

function getRequestIP(req) {
    const cf = req.headers['cf-connecting-ip'];
    const xr = req.headers['x-real-ip'];
    const xf = req.headers['x-forwarded-for'];
    const ra = req.socket.remoteAddress;
    const ip_txt = 'cf: ' + cf + ' xr: ' + xr + ' xf: ' + xf + ' ra: ' + ra
    return ip_txt;
}

async function getUserFromKey(dbClient, key, origin) {
    const userDoc = { "name": "unknown", "authorized": false, "api_env": process.env.api_env };
    try {
        const hashedKey = await getHashedKey(key);
        if (hashedKey) {
            const result = await dbClient.db(process.env.DB_NAME).collection('keys').findOne({ key: hashedKey });
            if (result) {
                userDoc.name = result.user;
                const envs = result.environments;
                if (envs) {
                    if (envs.includes('*') || envs.includes(userDoc.api_env)) {
                        //sxa 7/26/2024 keys are not associated with origins at this time. uncomment the following block if that changes.
                        // const orgs = result.origins;
                        // if (orgs) {
                        //     if (orgs.includes('*') || (origin && orgs.includes(origin))) {
                        //         userDoc.authorized = true;
                        //     } else { userDoc.issue = "origin didn't match."; }
                        // } else { userDoc.issue = "origin not specified."; }
                        userDoc.authorized = true;
                    } else { userDoc.issue = "environment didn't match."; }
                } else { userDoc.issue = "environment not specified."; }
            } else {
                userDoc.issue = "key didn't match";
            }
        } else {
            if (userDoc.api_env == 'dev' || userDoc.api_env == 'test' || userDoc.api_env == 'prod') {
                if (origin && allowedOrigins.includes(origin)) {
                    userDoc.authorized = true;
                    userDoc.keylessEntry = true;
                }
                else {
                    userDoc.issue = "no key provided. origin not recognized: " + origin;
                }
            } else {
                userDoc.issue = "environment does not support keyless access.";
            }
        }
    } catch (err) {
        console.log("Error:", err);
        userDoc.issue = err;
    }
    return userDoc;
}

async function createLogEntryObj(req, dbClient, route) {
    const inputKey = req.body.key;
    const user = await getUserFromKey(dbClient, inputKey, req.headers.origin);
    return {
        route: route,
        user: user,
        ip: getRequestIP(req),
        request: { "body": req.body, "headers": req.headers },
        req_time: new Date()
    }
}

async function writeLogObj(logEntry, dbClient, dbName, colName) {
    try {
        if (logEntry) {
            if (logEntry.user.authorized) {
                logEntry.request.body.key = 'API key removed for logging purposes. The key was not stored in the database.';
            } else {
                // console.log('let the key be visible if we don't know the user');
            }
            const result = await dbClient.db(dbName).collection(colName).insertOne(logEntry);
            console.log(`New req logged with the following id: ${result.insertedId}`);
        }
    } catch (err) {
        console.log("Error:");
        console.log(err);
    }
}

module.exports = {
    createLogEntryObj,
    writeLogObj
};
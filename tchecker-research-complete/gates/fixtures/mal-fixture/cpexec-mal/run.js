// STRUCTURAL REPRODUCTION: spawns a shell at INSTALL time; command is inert.
const { exec } = require("child_process");
exec("echo installed");                       // child_process in install hook

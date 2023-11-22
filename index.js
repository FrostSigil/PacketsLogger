/* eslint-disable no-param-reassign */
const hexy = require("hexy");

module.exports = function PacketsLogger(mod) {
	const logConsole = true;

	let logC = false; //
	let logS = false;
	let logRaw = false;
	let logRawUnkOnly = false;
	let logJson = true;
	let logUnk = true;
	let logUnkOnly = false;
	let logPaste = false;
	let hook = null;
	let hookEnabled = false;
	let searchExpr = null;
	let showBlacklist = false;

	let blacklist = require("./blacklist");
	const hardBlacklist = require("./hardblacklist");

	if (logS || logC) {
		enableHook();
	}

	mod.command.add("logC", () => {
		logC = !logC;

		mod.command.message(`Client packet logging is now log C ${logC ? "enabled" : "disabled"}.`);

		if (!logC && !logS && hookEnabled) disableHook();
		if ((logC || logS) && !hookEnabled) enableHook();
	});

	mod.command.add("logS", () => {
		logS = !logS;

		mod.command.message(`Server packet logging is now log S ${logS ? "enabled" : "disabled"}.`);

		if (!logC && !logS && hookEnabled) disableHook();
		if ((logC || logS) && !hookEnabled) enableHook();
	});

	mod.command.add("logRaw", arg => {
		arg = arg.toLowerCase();

		if (["true", "yes", "y", "1"].includes(arg)) {
			logRaw = true;
			logRawUnkOnly = false;
		} else if (["false", "no", "n", "0"].includes(arg)) {
			logRaw = false;
			logRawUnkOnly = false;
		} else if (["unk", "u", "2"].includes(arg)) {
			logRaw = true;
			logRawUnkOnly = true;
		} else {
			logRaw = !logRaw;
			logRawUnkOnly = false;
		}

		mod.command.message(`Raw packet logging is now ${logRaw ? "enabled" : "disabled"}${logRawUnkOnly ? " (only unknown packets)" : ""}.`);
	});

	mod.command.add("logJson", () => {
		logJson = !logJson;
		mod.command.message(`Json packet logging is now ${logJson ? "enabled" : "disabled"}.`);
	});

	mod.command.add("logPaste", () => {
		logPaste = !logPaste;
		mod.command.message(`Raw packet pasting format is now ${logPaste ? "enabled" : "disabled"}.`);
	});

	mod.command.add("logUnk", (arg) => {
		arg = `${arg}`;
		arg = arg.toLowerCase();

		if (["true", "yes", "y", "1"].includes(arg)) {
			logUnk = true;
			logUnkOnly = false;
		} else if (["false", "no", "n", "0"].includes(arg)) {
			logUnk = false;
			logUnkOnly = false;
		} else if (["only", "o", "2"].includes(arg)) {
			logUnk = true;
			logUnkOnly = true;
		} else {
			logUnk = !logUnk;
			logUnkOnly = false;
		}

		mod.command.message(`Unknown packet logging is now ${logUnk ? "enabled" : "disabled"}${logUnkOnly ? " (only)" : ""}.`);
	});

	mod.command.add("logSearch", (s) => {
		if (s === "" || s === undefined) s = null;
		searchExpr = s;

		if (searchExpr !== null) {
			searchExpr = `${searchExpr}`;
			mod.command.message(`Logger search expression set to: ${searchExpr}`);
		} else {
			mod.command.message("Logger search disabled.");
		}
	});

	mod.command.add("logBlack", (name) => {
		if (name === null || name === undefined) {
			mod.command.message("Invalid");
			return;
		}

		const index = blacklist.indexOf(name);

		if (index > -1) {
			blacklist.splice(index, 1);
			mod.command.message(`Now showing ${name}.`);
		} else {
			blacklist.push(`${name}`);
			mod.command.message(`Now hiding ${name}.`);
		}
	});

	mod.command.add("logBlackShow", (name) => {
		for (const item of blacklist) {
			mod.command.message(item);
		}
	});

	mod.command.add("logBlackClear", (name) => {
		blacklist = [];
		mod.command.message("Logger blacklist cleared.");
	});

	mod.command.add("loghideblack", () => {
		showBlacklist = !showBlacklist;
		mod.command.message(`Show blacklist packets is now ${showBlacklist ? "enabled" : "disabled"}.`);
	});

	function hexDump(data) {
		if (logPaste) {
			return data.toString("hex");
		} else {
			return hexy.hexy(data, { "format": "eights", "offset": 4, "caps": "upper", "width": 32 });
		}
	}

	function timestamp() {
		const today = new Date();
		return `[${today.getHours()}:${today.getMinutes()}:${today.getSeconds()}:${today.getMilliseconds()}]`;
	}

	function packetArrow(incoming) {
		return incoming ? "<-" : "->";
	}

	function internalType(data) {
		return (data.$fake ? "[CRAFTED]    " : "") + (data.$silenced ? "[BLOCKED]    " : "") + (data.$modified ? "[EDITED]    " : "") + ((!data.$fake && !data.$silenced && !data.$modified) ? "            " : "");
	}

	function printUnknown(code, data, incoming, name) {
		writeLog(`${timestamp()} ${packetArrow(incoming)} ${internalType(data)}    (id ${code}) ${name}`);

		if (logRaw) {
			writeLog(hexDump(data));
			writeLog(data.toString("hex"));
		}
	}

	function loopBigIntToString(obj) {
		Object.keys(obj).forEach(key => {
			if (obj[key] && typeof obj[key] === "object") loopBigIntToString(obj[key]);
			else if (typeof obj[key] === "bigint") obj[key] = obj[key].toString();
		});
	}

	function printKnown(name, packet, incoming, code, data, defPerhapsWrong) {
		loopBigIntToString(packet);
		const json = JSON.stringify(packet, null, 4);

		writeLog(`${timestamp()} ${packetArrow(incoming)} ${internalType(data)} ${name}    (id ${code}${defPerhapsWrong ? ", DEF WRONG!!!)" : ")"}`);

		if (logJson) {
			writeLog(json);
		}

		if (logRaw && (defPerhapsWrong || !logRawUnkOnly)) {
			writeLog(hexDump(data));
			writeLog(data.toString("hex"));
		}
	}

	function isDefPerhapsWrong(name, packet, incoming, data) {
		if (incoming && name.slice(0, 2) === "C_") {
			return true;
		}

		if (!incoming && name.slice(0, 2) === "S_") {
			return true;
		}

		const data2 = mod.dispatch.toRaw(name, "*", packet);

		if ((data.length != data2.length)) {
			return true;
		} else {
			return false;
		}
	}

	function shouldPrintKnownPacket(name, code, incoming, data) {
		if (logUnk && logUnkOnly) return false;

		if (incoming) {
			if (!logS) return false;
		} else if (!logC) return false;

		if (hardBlacklist.includes(name)) {
			return false;
		}

		for (const item of blacklist) {
			if (item === name || item === `${code}`) {
				if (!showBlacklist) return false;
				writeLog(`[BLACKLIST] ${internalType(data)}${name} (${code})`);
				return false;
			}
		}

		if (searchExpr !== null && !packetMatchesSearch(name, code)) {
			return false;
		}

		return true;
	}

	function shouldPrintUnknownPacket(name, code, incoming, data) {
		if (!logUnk) return false;

		if (incoming) {
			if (!logS) return false;
		} else if (!logC) return false;

		if (hardBlacklist.includes(name)) {
			return false;
		}

		for (const item of blacklist) {
			if (item === name || item === `${code}`) {
				if (!showBlacklist) return false;
				writeLog(`[BLACKLIST]   ${internalType(data)}${name} (${code})`);
				return false;
			}
		}

		if (searchExpr !== null && !packetMatchesSearch("", code)) {
			return false;
		}

		return true;
	}


	function packetMatchesSearch(name, code) {
		if (searchExpr === (`${code}`)) {
			return true;
		} else if (name !== "" && new RegExp(searchExpr).test(name)) {
			return true;
		}

		return false;
	}

	function disableHook() {
		hookEnabled = false;
		mod.unhook(hook);
		writeLog("<---- Hook DISABLED ---->");
	}

	function enableHook() {
		hookEnabled = true;

		writeLog("<---- Hook ENABLED ---->");

		hook = mod.hook("*", "raw", {
			"order": 999999,
			"filter": {
				"fake": null,
				"silenced": null,
				"modified": null
			}
		}, (code, data, incoming, fake) => {
			if (!logC && !logS) return;

			let name = null;
			let packet = null;

			name = mod.dispatch.protocolMap.code.get(code);
			if (name === undefined) name = null;

			if (name) {
				try {
					packet = mod.dispatch.fromRaw(code, "*", data);
				} catch (e) {
					packet = null;
				}

				if (packet) {
					const defPerhapsWrong = isDefPerhapsWrong(name, packet, incoming, data);

					if (shouldPrintKnownPacket(name, code, incoming, data)) {
						printKnown(name, packet, incoming, code, data, defPerhapsWrong);
					}
				}
			}

			if (!name || !packet) {
				if (shouldPrintUnknownPacket(name, code, incoming, data)) {
					printUnknown(code, data, incoming, name);
				}
			}
		});
	}

	function writeLog(str) {
		if (logConsole) {
			console.log(str);
		}
	}

	this.destructor = function() {
		disableHook();
	};
};

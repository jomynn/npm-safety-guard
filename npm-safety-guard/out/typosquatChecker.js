"use strict";
/**
 * NPM Safety Guard — Typosquat & Homoglyph Detector
 *
 * Two attack classes covered, both at the package-name level (not source):
 *
 * 1. Typosquatting — `axioss`, `loadash`, `cha1k` — names within edit
 *    distance 1-2 of a popular package. Damerau-Levenshtein with quick
 *    length pre-filter.
 *
 * 2. Homoglyph substitution — Cyrillic/Greek lookalikes (`reаct` with a
 *    Cyrillic 'а') that visually match a popular package. After mapping
 *    suspicious code points back to ASCII, if the normalised name hits
 *    a top package, it's an unambiguous attack signal (npm itself
 *    actually rejects most of these now, but old or punycode-encoded
 *    packages can still slip through).
 *
 * Bundled top-package list (~250 entries) is hand-curated from the
 * highest-traffic npm packages. Pure offline, zero HTTP, instant.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkPackageName = checkPackageName;
exports.checkAllPackageNames = checkAllPackageNames;
// ─── Damerau-Levenshtein ─────────────────────────────────────────────────────
function damerauLevenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0)
        return n;
    if (n === 0)
        return m;
    const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++)
        d[i][0] = i;
    for (let j = 0; j <= n; j++)
        d[0][j] = j;
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
            d[i][j] = Math.min(d[i - 1][j] + 1, // deletion
            d[i][j - 1] + 1, // insertion
            d[i - 1][j - 1] + cost // substitution
            );
            if (i > 1 && j > 1 &&
                a.charCodeAt(i - 1) === b.charCodeAt(j - 2) &&
                a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
                d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
            }
        }
    }
    return d[m][n];
}
// ─── Homoglyph table ─────────────────────────────────────────────────────────
const HOMOGLYPH_MAP = {
    // Cyrillic → Latin lookalikes
    "\u0430": "a", "\u0410": "A", // а / А
    "\u0441": "c", "\u0421": "C", // с / С
    "\u0435": "e", "\u0415": "E", // е / Е
    "\u043E": "o", "\u041E": "O", // о / О
    "\u0440": "p", "\u0420": "P", // р / Р
    "\u0443": "y", "\u0423": "Y", // у / У
    "\u0445": "x", "\u0425": "X", // х / Х
    "\u0456": "i", "\u0406": "I", // і / І
    "\u0458": "j", "\u0408": "J", // ј / Ј
    "\u04AB": "s", "\u04AA": "S", // ҫ family — close enough
    "\u0455": "s", "\u0405": "S", // ѕ / Ѕ
    // Greek
    "\u03B1": "a", "\u0391": "A", // α / Α
    "\u03B5": "e", "\u0395": "E", // ε / Ε
    "\u03BF": "o", "\u039F": "O", // ο / Ο
    "\u03C1": "p", "\u03A1": "P", // ρ / Ρ
    "\u03BD": "v", // ν
    "\u03BA": "k", // κ
    "\u03B9": "i", // ι
};
function normaliseHomoglyphs(s) {
    return [...s].map((c) => HOMOGLYPH_MAP[c] ?? c).join("");
}
function hasNonAscii(s) {
    return /[^\x00-\x7F]/.test(s);
}
// ─── Top package list (curated from top npm downloads) ───────────────────────
const TOP_PACKAGES_RAW = [
    // React ecosystem
    "react", "react-dom", "react-native", "react-router", "react-router-dom",
    "react-redux", "react-query", "@tanstack/react-query", "react-hook-form",
    "react-scripts", "react-icons", "react-select", "next", "gatsby",
    // Vue / Angular
    "vue", "vue-router", "vuex", "@vue/cli", "nuxt",
    "@angular/core", "@angular/cli", "@angular/common",
    // State / forms
    "redux", "@reduxjs/toolkit", "zustand", "jotai", "recoil", "mobx", "immer",
    "formik", "yup", "zod", "joi", "ajv", "validator",
    // HTTP / network
    "axios", "node-fetch", "request", "got", "undici", "ws", "socket.io", "socket.io-client",
    // Server frameworks
    "express", "fastify", "koa", "hapi", "@nestjs/core", "@nestjs/common",
    "body-parser", "cors", "helmet", "morgan", "multer", "passport", "express-session",
    "compression", "cookie-parser", "express-validator",
    // Utilities
    "lodash", "lodash-es", "ramda", "underscore", "chalk", "kleur", "picocolors",
    "debug", "ms", "dotenv", "uuid", "nanoid", "shortid", "ulid",
    "fs-extra", "graceful-fs", "glob", "fast-glob", "micromatch", "minimatch", "chokidar",
    "rimraf", "mkdirp", "ncp", "shelljs", "shx",
    "json5", "yaml", "ini", "toml", "xml2js", "fast-xml-parser",
    "dayjs", "date-fns", "moment", "luxon",
    "classnames", "clsx",
    // CLI & dev
    "commander", "yargs", "minimist", "inquirer", "chalk",
    "ora", "boxen", "figlet", "cli-progress", "listr",
    "nodemon", "ts-node", "tsx", "ts-node-dev", "concurrently", "npm-run-all",
    "husky", "lint-staged", "commitlint", "semantic-release", "conventional-changelog",
    // Build tools
    "webpack", "vite", "rollup", "esbuild", "terser", "uglify-js",
    "@swc/core", "@swc/cli", "@babel/core", "babel", "babel-loader",
    "postcss", "autoprefixer", "tailwindcss", "sass", "less", "stylus",
    // Testing
    "mocha", "jest", "vitest", "jasmine", "sinon", "chai", "supertest",
    "cypress", "playwright", "puppeteer", "puppeteer-core", "selenium-webdriver",
    "@testing-library/react", "@testing-library/jest-dom", "@testing-library/user-event",
    "nyc", "c8", "istanbul",
    // Linters / types
    "eslint", "prettier", "typescript", "@types/node", "@types/react", "@types/express",
    // Database / ORM
    "mongoose", "mongodb", "mysql", "mysql2", "pg", "sqlite3", "better-sqlite3",
    "redis", "ioredis", "sequelize", "knex", "prisma", "@prisma/client", "typeorm",
    // Auth / crypto
    "jsonwebtoken", "jose", "bcrypt", "bcryptjs", "argon2", "crypto-js",
    // Cloud / SDKs
    "aws-sdk", "@aws-sdk/client-s3", "@aws-sdk/client-dynamodb",
    "googleapis", "@google-cloud/storage", "@google-cloud/firestore",
    "firebase", "firebase-admin", "stripe", "twilio", "@sendgrid/mail",
    // Image / media
    "sharp", "jimp", "canvas", "gifsicle", "mozjpeg", "optipng",
    // CSS / UI
    "styled-components", "@emotion/react", "@emotion/styled",
    "framer-motion", "react-spring", "gsap", "three",
    "d3", "chart.js", "recharts", "victory",
    // Misc heavy hitters
    "core-js", "regenerator-runtime", "tslib", "rxjs", "zone.js",
    "graphql", "apollo-server", "apollo-client", "@apollo/client",
    "express-graphql", "graphql-tag", "type-graphql",
    "electron", "electron-builder", "electron-updater",
    "cordova", "ionic",
    // utility chunks
    "axios-retry", "axios-mock-adapter",
    "deepmerge", "object-assign", "extend",
    "winston", "pino", "bunyan", "log4js",
    "node-cron", "cron", "agenda", "bull", "bullmq",
    "kafka-node", "amqplib", "rabbitmq",
    // sometimes-mistyped tiny libs
    "left-pad", "is-thirteen", "noop", "is-promise", "is-callable",
    "p-limit", "p-map", "p-queue", "p-retry",
];
const TOP_PACKAGES = new Set(TOP_PACKAGES_RAW);
// ─── Public API ──────────────────────────────────────────────────────────────
function checkPackageName(name, version) {
    // 1. Homoglyph / non-ASCII check (highest signal)
    if (hasNonAscii(name)) {
        const normalised = normaliseHomoglyphs(name);
        if (normalised !== name && TOP_PACKAGES.has(normalised)) {
            return {
                package: name, version,
                reason: "homoglyph",
                closestMatch: normalised,
                distance: 0,
                note: `Package name contains Cyrillic/Greek lookalike chars; normalises to "${normalised}" — a popular package.`,
            };
        }
        return {
            package: name, version,
            reason: "non_ascii",
            note: `Package name contains non-ASCII characters: ${[...name].filter((c) => /[^\x00-\x7F]/.test(c)).map((c) => `U+${c.codePointAt(0).toString(16).padStart(4, "0").toUpperCase()}`).join(" ")}`,
        };
    }
    // 2. Exact match in top list — known-popular, not a typosquat
    if (TOP_PACKAGES.has(name))
        return null;
    // 3. Damerau-Levenshtein against top list (with length pre-filter)
    let closest = "";
    let minDist = Infinity;
    for (const top of TOP_PACKAGES) {
        if (Math.abs(top.length - name.length) > 2)
            continue;
        const d = damerauLevenshtein(name, top);
        if (d < minDist) {
            minDist = d;
            closest = top;
            if (d === 1)
                break; // can't beat 1 from a non-equal candidate
        }
    }
    if (minDist <= 2 && minDist > 0 && closest) {
        // Skip scoped pairs that legitimately match unscoped popular packages,
        // e.g. "@types/lodash" vs "lodash" (hits via length/distance noise).
        if (name.startsWith("@") && !closest.startsWith("@"))
            return null;
        return {
            package: name, version,
            reason: "typosquat",
            closestMatch: closest,
            distance: minDist,
            note: `Name is ${minDist} edit(s) away from the popular package "${closest}". Verify you didn't fat-finger the install command.`,
        };
    }
    return null;
}
function checkAllPackageNames(deps) {
    const hits = [];
    for (const [name, version] of Object.entries(deps)) {
        const hit = checkPackageName(name, version);
        if (hit)
            hits.push(hit);
    }
    return hits;
}
//# sourceMappingURL=typosquatChecker.js.map